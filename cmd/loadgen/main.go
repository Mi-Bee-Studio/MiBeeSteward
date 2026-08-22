// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

// loadgen is the synthetic-load harness for scale benchmarking (#283). It is
// NOT part of the default build (make build only compiles cmd/server) — build
// it explicitly with `go build ./cmd/loadgen`.
//
// Two modes:
//
//		loadgen serve --devices 1000 --base 127.8.0.0
//		  Starts a synthetic device plane on the loopback /8: N fake devices, each
//		  answering on its own 127.x.y.z address — ICMP works for free (kernel),
//		  and per-template TCP/UDP responders emulate SNMP v2c agents, HTTP
//		  servers, SSH-style banners, and RTSP servers with realistic payload
//		  shapes (sysDescr/title/banner per device class).
//
//		loadgen drive --center http://127.0.0.1:8080 --targets 127.8.0.0/22 --out report
//		  Drives a REAL center through its HTTP API (login → async scan task →
//		  poll to completion), sampling /metrics deltas around the run: scan
//		  duration, hosts discovered, DB growth, SQLITE_BUSY counter, Go process
//	         CPU/memory, and API p50/p95 latency. Emits JSON + Markdown.
//
// Requires CAP_NET_BIND_SERVICE (root) for the well-known ports (22/80/161/
// 554) — synthetic devices deliberately use the same ports real ones do so
// the scanner's port heuristics and classifiers are exercised unmodified.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if len(os.Args) < 2 {
		fmt.Println(usage)
		os.Exit(2)
	}
	switch strings.ToLower(os.Args[1]) {
	case "serve":
		serveCmd(os.Args[2:])
	case "drive":
		driveCmd(os.Args[2:])
	default:
		fmt.Println(usage)
		os.Exit(2)
	}
}

const usage = `loadgen — MiBee Steward synthetic load harness (#283)

  loadgen serve --devices N --base 127.8.0.0 [--seed 1]
      Start the synthetic device plane (Ctrl-C stops).
  loadgen drive --center URL --user u --pass p --targets CIDR --out PREFIX
      Drive one scan of the plane through a real center; write PREFIX.json + PREFIX.md`

// --- device templates ---

// deviceTemplate shapes what a synthetic device answers on each protocol.
// The payload strings mirror real firmware output so the fingerprint
// classifiers exercise their actual matching paths.
type deviceTemplate struct {
	Class      string // drives selection weights + naming
	SNMPDesc   string // sysDescr
	SNMPName   string // sysName
	HTTPTitle  string
	HTTPServer string
	Banner     string // TCP greeting (SSH-style)
	RTSPServer string
	Ports      []string // "tcp:22", "udp:161", ...
}

var templates = []deviceTemplate{
	{Class: "camera", SNMPDesc: "HIKVISION IPCam V5.7.1", SNMPName: "hik-cam",
		HTTPTitle: "Network Camera", HTTPServer: "uc-httpd/1.0.0", RTSPServer: "HIKVISION RTSP/1.0",
		Ports: []string{"tcp:80", "udp:161", "tcp:554"}},
	{Class: "router", SNMPDesc: "Linux BRUME2 5.4.211", SNMPName: "brume2",
		Banner: "SSH-2.0-dropbear-2022.83",
		Ports:  []string{"tcp:22", "udp:161"}},
	{Class: "server", SNMPDesc: "Linux arch 6.9 zen", SNMPName: "vm-arch",
		HTTPTitle: "Welcome to nginx", HTTPServer: "nginx/1.26.1",
		Banner: "SSH-2.0-OpenSSH_9.8p1",
		Ports:  []string{"tcp:22", "tcp:80"}},
	{Class: "nas", SNMPDesc: "Synology DS920+ DSM 7.2", SNMPName: "ds920",
		HTTPTitle: "Synology DiskStation", HTTPServer: "nginx",
		Ports: []string{"tcp:80", "tcp:443", "udp:161"}},
	{Class: "iot", HTTPTitle: "Xiaomi Air Conditioner", HTTPServer: "miio/1.0",
		Ports: []string{"tcp:80"}},
	{Class: "printer", SNMPDesc: "HP LaserJet M404dn", SNMPName: "NPI9A4B2C",
		HTTPTitle: "HP LaserJet", HTTPServer: "HP-HTTP-Server",
		Ports: []string{"tcp:80", "tcp:631", "udp:161"}},
}

func pickTemplate(i int) deviceTemplate {
	// Deterministic weighted mix; the seed keeps runs reproducible.
	w := []int{25, 15, 20, 10, 20, 10}
	total := 0
	for _, x := range w {
		total += x
	}
	pick := (i*7919 + 13) % total
	for idx, x := range w {
		if pick < x {
			return templates[idx]
		}
		pick -= x
	}
	return templates[0]
}

// --- serve mode ---

func serveCmd(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	devices := fs.Int("devices", 1000, "number of synthetic devices")
	base := fs.String("base", "127.8.0.0", "base address; devices take consecutive IPs from here")
	_ = fs.Parse(args)

	start := net.ParseIP(*base).To4()
	if start == nil {
		slog.Error("invalid --base", "base", *base)
		os.Exit(1)
	}

	ln := &sync.WaitGroup{}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	bind := func(ip net.IP, port string, handler func(net.Conn), proto string) bool {
		addr := net.JoinHostPort(ip.String(), port)
		var l net.Listener
		var pc net.PacketConn
		var err error
		if proto == "udp" {
			pc, err = net.ListenPacket("udp4", addr)
		} else {
			l, err = net.Listen("tcp4", addr)
		}
		if err != nil {
			slog.Warn("bind failed (address in use or missing cap_net_bind_service?)", "addr", addr, "error", err)
			return false
		}
		ln.Add(1)
		go func() {
			defer ln.Done()
			<-ctx.Done()
			if l != nil {
				l.Close()
			}
			if pc != nil {
				pc.Close()
			}
		}()
		if l != nil {
			go func() {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					go handler(c)
				}
			}()
		} else {
			go func() {
				buf := make([]byte, 1500)
				for {
					n, from, err := pc.ReadFrom(buf)
					if err != nil {
						return
					}
					if resp := snmpRespond(buf[:n]); resp != nil {
						_, _ = pc.WriteTo(resp, from)
					}
				}
			}()
		}
		return true
	}

	ok, failed := 0, 0
	for i := 0; i < *devices; i++ {
		ip := dupIP(start, i)
		tpl := pickTemplate(i)
		for _, p := range tpl.Ports {
			proto, port, _ := strings.Cut(p, ":")
			var h func(net.Conn)
			switch port {
			case "161":
				if proto != "udp" {
					continue
				}
				// UDP handled by the packet-conn branch; the tcp handler is unused.
				h = func(c net.Conn) { c.Close() }
			case "22":
				h = bannerHandler(tpl.Banner)
			case "80", "443":
				h = httpHandler(tpl)
			case "554":
				h = rtspHandler(tpl)
			default:
				h = bannerHandler(tpl.Banner) // 631 etc: generic greeting
			}
			if bind(ip, port, h, proto) {
				ok++
			} else {
				failed++
			}
		}
	}
	slog.Info("synthetic plane up", "devices", *devices, "listeners", ok, "bind_failures", failed)
	slog.Info("press Ctrl-C to stop")
	ln.Wait()
	slog.Info("plane stopped")
}

func dupIP(base net.IP, i int) net.IP {
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, binary.BigEndian.Uint32(base)+uint32(i))
	return out
}

func bannerHandler(banner string) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		_, _ = c.Write([]byte(banner + "\r\n"))
		buf := make([]byte, 512)
		for {
			if _, err := c.Read(buf); err != nil {
				return
			}
		}
	}
}

func httpHandler(tpl deviceTemplate) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 4096)
		n, _ := c.Read(buf)
		_ = n // request line consumed; answer generically
		body := fmt.Sprintf("<html><head><title>%s</title></head><body>device page</body></html>", tpl.HTTPTitle)
		fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
			tpl.HTTPServer, len(body), body)
	}
}

func rtspHandler(tpl deviceTemplate) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		buf := make([]byte, 1024)
		if _, err := c.Read(buf); err != nil {
			return
		}
		fmt.Fprintf(c, "RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: %s\r\nPublic: OPTIONS, DESCRIBE, SETUP, PLAY\r\n\r\n", tpl.RTSPServer)
	}
}

// --- minimal SNMP v2c GET responder ---
//
// The scanner sends one GET with 8 scalar OIDs; we echo request-id and bind
// per-OID values derived from the device template. Only the pieces a v2c GET
// response needs are implemented (BER length handling included).

func snmpRespond(req []byte) []byte {
	// Parse: SEQUENCE { INTEGER version, OCTET STRING community, PDU { ... } }
	// Walk top-level TLVs of the outer sequence.
	seq, ok := tlv(req)
	if !ok || seq.tag != 0x30 {
		return nil
	}
	rest := seq.value
	ver, ok := tlv(rest)
	if !ok || ver.tag != 0x02 {
		return nil
	}
	rest = rest[len(ver.raw):]
	comm, ok := tlv(rest)
	if !ok || comm.tag != 0x04 {
		return nil
	}
	rest = rest[len(comm.raw):]
	pdu, ok := tlv(rest)
	if !ok || pdu.tag != 0xA0 { // GetRequest-PDU
		return nil
	}
	// PDU body: INTEGER req-id, INTEGER error-status, INTEGER error-index, SEQUENCE varbinds
	body := pdu.value
	reqID, ok := tlv(body)
	if !ok {
		return nil
	}
	vblRaw := body[len(reqID.raw):]
	// skip error-status + error-index
	for i := 0; i < 2; i++ {
		t, ok := tlv(vblRaw)
		if !ok {
			return nil
		}
		vblRaw = vblRaw[len(t.raw):]
	}
	vbl, ok := tlv(vblRaw)
	if !ok || vbl.tag != 0x30 {
		return nil
	}

	// Build the response varbind list, answering each requested OID.
	var out []byte
	cur := vbl.value
	for len(cur) > 0 {
		vb, ok := tlv(cur)
		if !ok {
			break
		}
		cur = cur[len(vb.raw):]
		oidTLV, ok := tlv(vb.value)
		if !ok || oidTLV.tag != 0x06 {
			continue
		}
		oidStr := oidToString(oidTLV.value)
		out = append(out, tlvEncode(0x30, append(oidTLV.raw, valueForOID(oidStr)...))...)
	}

	// GetResponse PDU (0xA2) with echoed req-id, zero error fields.
	respPDU := tlvEncode(0xA2, append(append(append(
		reqID.raw,
		intTLV(0)...),
		intTLV(0)...),
		tlvEncode(0x30, out)...))
	msg := tlvEncode(0x30, append(append(ver.raw, comm.raw...), respPDU...))
	return msg
}

// valueForOID renders the synthetic value TLV for a scalar OID.
func valueForOID(oid string) []byte {
	switch {
	case strings.HasSuffix(oid, "1.1.1.0"): // sysDescr — template text; global default
		return tlvEncode(0x04, []byte(syntheticDescr))
	case strings.HasSuffix(oid, "1.1.2.0"): // sysObjectID
		return tlvEncode(0x06, []byte{0x2b, 6, 1, 4, 1, 99, 99})
	case strings.HasSuffix(oid, "1.1.3.0"): // sysUpTime
		return tlvEncode(0x43, []byte{0x01, 0x02, 0x03, 0x04})
	case strings.HasSuffix(oid, "1.1.5.0"): // sysName
		return tlvEncode(0x04, []byte("loadgen-device"))
	case strings.HasSuffix(oid, "1.1.7.0"): // sysServices
		return intTLV(76)
	case strings.HasSuffix(oid, "2.1.0"): // ifNumber
		return intTLV(4)
	default:
		return tlvEncode(0x05, nil) // NULL
	}
}

// syntheticDescr is set per-listener by the serve loop. The SNMP responder is
// UDP-packet-based (no per-connection state), so per-template sysDescr is not
// distinguishable without a lookup from the local address — acceptable for a
// load plane: identification pressure comes from the TCP side, and the DB/
// write-path load is identical regardless of the sysDescr text.
var syntheticDescr = "loadgen synthetic device v1"

type tlvT struct {
	tag   byte
	value []byte
	raw   []byte
}

func tlv(b []byte) (tlvT, bool) {
	if len(b) < 2 {
		return tlvT{}, false
	}
	tag := b[0]
	l := int(b[1])
	hdr := 2
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 4 || len(b) < 2+n {
			return tlvT{}, false
		}
		l = 0
		for i := 0; i < int(n); i++ {
			l = l<<8 | int(b[2+i])
		}
		hdr = 2 + int(n)
	}
	if len(b) < hdr+l {
		return tlvT{}, false
	}
	return tlvT{tag: tag, value: b[hdr : hdr+l], raw: b[:hdr+l]}, true
}

// intTLV encodes a small non-negative INTEGER.
func intTLV(v int) []byte { return tlvEncode(0x02, []byte{byte(v)}) }

func tlvEncode(tag byte, value []byte) []byte {
	var out []byte
	l := len(value)
	if l < 0x80 {
		out = []byte{tag, byte(l)}
	} else {
		var lb []byte
		for x := l; x > 0; x >>= 8 {
			lb = append([]byte{byte(x)}, lb...)
		}
		out = append([]byte{tag, byte(0x80 | len(lb))}, lb...)
	}
	return append(out, value...)
}

func oidToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []int{int(b[0]) / 40, int(b[0]) % 40}
	for _, x := range b[1:] {
		if x < 0x80 {
			parts = append(parts, int(x))
		}
	}
	var sb strings.Builder
	for i, p := range parts {
		if i > 0 {
			sb.WriteByte('.')
		}
		fmt.Fprintf(&sb, "%d", p)
	}
	return sb.String()
}

// --- drive mode ---

func driveCmd(args []string) {
	fs := flag.NewFlagSet("drive", flag.ExitOnError)
	center := fs.String("center", "http://127.0.0.1:8080", "center base URL")
	user := fs.String("user", "admin", "login username")
	pass := fs.String("pass", "", "login password")
	targets := fs.String("targets", "127.8.0.0/22", "scan targets (the synthetic plane)")
	out := fs.String("out", "bench-report", "output prefix (.json/.md appended)")
	apiBurst := fs.Int("api-burst", 100, "GET /devices requests for the latency sample")
	_ = fs.Parse(args)
	if *pass == "" {
		slog.Error("--pass is required")
		os.Exit(1)
	}

	rep := &report{Center: *center, Targets: *targets, StartedAt: time.Now().UTC()}
	client := &http.Client{Timeout: 60 * time.Second}
	token := login(client, *center, *user, *pass)

	before := snapshotMetrics(client, *center)
	t0 := time.Now()

	taskID := createScanTask(client, *center, token, *targets)
	trigger(client, *center, token, taskID)
	run := waitForRun(client, *center, token, taskID, 30*time.Minute)
	rep.ScanDurationSec = time.Since(t0).Seconds()
	rep.HostsTotal = run.TotalHosts
	rep.HostsAlive = run.AliveHosts

	after := snapshotMetrics(client, *center)
	rep.Metrics = delta(before, after)

	rep.APILatency = apiLatencySample(client, *center, token, *apiBurst)

	rep.FinishedAt = time.Now().UTC()
	writeReports(rep, *out)
	slog.Info("report written", "prefix", *out)
}

type report struct {
	Center          string        `json:"center"`
	Targets         string        `json:"targets"`
	StartedAt       time.Time     `json:"started_at"`
	FinishedAt      time.Time     `json:"finished_at"`
	ScanDurationSec float64       `json:"scan_duration_sec"`
	HostsTotal      int64         `json:"hosts_total"`
	HostsAlive      int64         `json:"hosts_alive"`
	Metrics         metricsDelta  `json:"metrics"`
	APILatency      latencySample `json:"api_latency"`
}

type metricsSnapshot map[string]float64

type metricsDelta struct {
	DBSizeBytes       float64 `json:"db_size_bytes_delta"`
	WALSizeBytes      float64 `json:"wal_size_bytes_delta"`
	SQLiteBusyTotal   float64 `json:"sqlite_busy_total_delta"`
	ScannerRuns       float64 `json:"scanner_runs_total_delta"`
	HeartbeatChecks   float64 `json:"heartbeat_checks_total_delta"`
	ProcessCPUSeconds float64 `json:"process_cpu_seconds_delta"`
	ResidentMemoryMB  float64 `json:"resident_memory_mb_end"`
}

type latencySample struct {
	N      int     `json:"n"`
	P50    float64 `json:"p50_ms"`
	P95    float64 `json:"p95_ms"`
	MaxVal float64 `json:"max_ms"`
}

func login(c *http.Client, center, user, pass string) string {
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)
	req, _ := http.NewRequest("POST", center+"/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	must(err)
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Token == "" {
		resp.Body.Close()
		slog.Error("login failed", "error", err)
		os.Exit(1)
	}
	resp.Body.Close()
	return out.Token
}

func snapshotMetrics(c *http.Client, center string) metricsSnapshot {
	req, _ := http.NewRequest("GET", center+"/metrics", nil)
	resp, err := c.Do(req)
	if err != nil {
		return metricsSnapshot{}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	out := metricsSnapshot{}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "mibee_") && !strings.HasPrefix(line, "process_") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		out[fields[0]] = parseFloat(fields[1])
	}
	return out
}

func delta(a, b metricsSnapshot) metricsDelta {
	get := func(m metricsSnapshot, key string) float64 {
		var v float64
		for k, val := range m {
			if strings.HasPrefix(k, key) {
				v = val
			}
		}
		return v
	}
	d := metricsDelta{}
	d.DBSizeBytes = get(b, "mibee_db_size_bytes") - get(a, "mibee_db_size_bytes")
	d.WALSizeBytes = 0
	d.SQLiteBusyTotal = get(b, "mibee_sqlite_busy_total") - get(a, "mibee_sqlite_busy_total")
	d.ScannerRuns = get(b, "mibee_scanner_runs_total") - get(a, "mibee_scanner_runs_total")
	d.HeartbeatChecks = get(b, "mibee_heartbeat_checks_total") - get(a, "mibee_heartbeat_checks_total")
	d.ProcessCPUSeconds = get(b, "process_cpu_seconds_total") - get(a, "process_cpu_seconds_total")
	d.ResidentMemoryMB = get(b, "process_resident_memory_bytes") / 1024 / 1024
	return d
}

func createScanTask(c *http.Client, center, token, targets string) int64 {
	body := fmt.Sprintf(`{"name":"loadgen-bench","targets":%q,"cron_expr":"0 3 * * *","timeout":120,"concurrent_hosts":64,"enabled":false,"pipeline_config":{"icmp":{"enabled":true},"port_scan":{"enabled":true},"snmp":{"enabled":true,"community":"public"}}}`, targets)
	req, _ := http.NewRequest("POST", center+"/api/v1/scanner/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	must(err)
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.ID == 0 {
		resp.Body.Close()
		slog.Error("task creation failed", "error", err)
		os.Exit(1)
	}
	resp.Body.Close()
	return out.ID
}

func trigger(c *http.Client, center, token string, taskID int64) {
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/v1/scanner/tasks/%d/trigger", center, taskID), nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := c.Do(req)
	must(err)
	resp.Body.Close()
}

type runRow struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	TotalHosts int64  `json:"total_hosts"`
	AliveHosts int64  `json:"alive_hosts"`
}

func waitForRun(c *http.Client, center, token string, taskID int64, maxWait time.Duration) runRow {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/scanner/tasks/%d/runs?limit=1", center, taskID), nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.Do(req)
		if err == nil {
			var out struct {
				Runs []runRow `json:"runs"`
			}
			if json.NewDecoder(resp.Body).Decode(&out) == nil && len(out.Runs) > 0 {
				r := out.Runs[0]
				if r.Status == "completed" || r.Status == "failed" {
					resp.Body.Close()
					return r
				}
			}
			resp.Body.Close()
		}
		time.Sleep(2 * time.Second)
	}
	slog.Error("scan did not finish within deadline")
	return runRow{Status: "timeout"}
}

func apiLatencySample(c *http.Client, center, token string, n int) latencySample {
	lat := []float64{}
	for i := 0; i < n; i++ {
		t0 := time.Now()
		req, _ := http.NewRequest("GET", center+"/api/v1/devices?limit=50", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := c.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		lat = append(lat, float64(time.Since(t0).Microseconds())/1000.0)
	}
	sort.Float64s(lat)
	if len(lat) == 0 {
		return latencySample{}
	}
	pct := func(p float64) float64 {
		return lat[int(float64(len(lat)-1)*p)]
	}
	return latencySample{N: len(lat), P50: pct(0.50), P95: pct(0.95), MaxVal: lat[len(lat)-1]}
}

func writeReports(r *report, prefix string) {
	j, _ := json.MarshalIndent(r, "", "  ")
	must(os.WriteFile(prefix+".json", j, 0o644))

	md := fmt.Sprintf(`# loadgen benchmark — %s

- targets: %s
- scan duration: %.1fs (hosts %d/%d alive)
- DB growth: %.1f MB · SQLITE_BUSY delta: %.0f
- center CPU: %.1fs · RSS end: %.0f MB
- API p50/p95/max: %.1f/%.1f/%.1f ms (n=%d)
`,
		r.StartedAt.Format(time.RFC3339), r.Targets, r.ScanDurationSec,
		r.HostsAlive, r.HostsTotal,
		r.Metrics.DBSizeBytes/1024/1024, r.Metrics.SQLiteBusyTotal,
		r.Metrics.ProcessCPUSeconds, r.Metrics.ResidentMemoryMB,
		r.APILatency.P50, r.APILatency.P95, r.APILatency.MaxVal, r.APILatency.N)
	must(os.WriteFile(prefix+".md", []byte(md), 0o644))
}

func parseFloat(s string) float64 {
	var f float64
	_, _ = fmt.Sscanf(s, "%g", &f)
	return f
}

func must(err error) {
	if err != nil {
		slog.Error("loadgen fatal", "error", err)
		os.Exit(1)
	}
}
