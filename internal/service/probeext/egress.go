// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

package probeext

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"mibee-steward/internal/config"
	"mibee-steward/internal/service/probe"
)

// vantageCenter is the center's own track name (probe_results convention).
const vantageCenter = "center"

var ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// egressCollector runs one egress round across the configured echo sources
// and enriches the distinct IPs with their origin ASN (#718).
type egressCollector struct {
	cfg    config.ProbeEgressConfig
	logger *slog.Logger
	client *http.Client
	// asnCache: ip -> (asn, asName, fetchedAt). The origin ASN of a public
	// IP is stable for weeks; 24h entries keep the TXT load negligible.
	asnCache sync.Map
}

func newEgressCollector(cfg config.ProbeEgressConfig, logger *slog.Logger) *egressCollector {
	if logger == nil {
		logger = slog.Default()
	}
	return &egressCollector{
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

// sourceOutcome is one source's result before persistence.
type sourceOutcome struct {
	name, kind string
	ok         bool
	ip, err    string
	ms         float64
}

// round queries every source concurrently plus the local egress (default
// route), then persists one EgressRow per result. The local row reuses the
// row shape: source="local", ip=gateway, err=iface (documented in the store).
func (c *egressCollector) round(ctx context.Context, store *Store) error {
	roundAt := time.Now().UTC().Format(time.RFC3339)
	outcomes := make([]sourceOutcome, len(c.cfg.Sources))
	var wg sync.WaitGroup
	for i, src := range c.cfg.Sources {
		wg.Add(1)
		go func(i int, src config.ProbeEgressSource) {
			defer wg.Done()
			start := time.Now()
			var ip, errMsg string
			switch src.Kind {
			case "http":
				ip, errMsg = c.httpEcho(ctx, src.Target)
			case "stun":
				ip, errMsg = stunEcho(src.Target, 4*time.Second)
			case "dns":
				ip, errMsg = c.dnsEcho(ctx, src.Target)
			default:
				errMsg = "unknown kind " + src.Kind
			}
			outcomes[i] = sourceOutcome{
				name: src.Name, kind: src.Kind, ok: ip != "",
				ip: ip, err: errMsg, ms: float64(time.Since(start).Milliseconds()),
			}
		}(i, src)
	}
	wg.Wait()

	rows := make([]EgressRow, 0, len(outcomes)+1)
	gwIP, gwIface := readLocalEgress()
	rows = append(rows, EgressRow{
		Vantage: vantageCenter, RoundAt: roundAt,
		Source: "local", Kind: "local", OK: gwIP != "",
		IP: gwIP, Err: gwIface,
	})
	distinct := map[string]bool{}
	for _, o := range outcomes {
		r := EgressRow{
			Vantage: vantageCenter, RoundAt: roundAt,
			Source: o.name, Kind: o.kind, OK: o.ok, IP: o.ip, MS: o.ms, Err: o.err,
		}
		if o.ok && isPublicIP(o.ip) && !distinct[o.ip] {
			distinct[o.ip] = true
			r.ASN, r.ASName = c.lookupASN(ctx, o.ip)
		}
		rows = append(rows, r)
	}
	if err := store.InsertEgressRound(ctx, rows); err != nil {
		return fmt.Errorf("insert egress round: %w", err)
	}
	okN := 0
	for _, o := range outcomes {
		if o.ok {
			okN++
		}
	}
	c.logger.Info("egress round done",
		"sources_ok", fmt.Sprintf("%d/%d", okN, len(outcomes)),
		"distinct_public_ips", len(distinct), "gateway", gwIP)
	return nil
}

// httpEcho fetches a URL and extracts the first IPv4 in the body. The
// cdn-cgi/trace variant is parsed from its ip= line when present.
func (c *egressCollector) httpEcho(ctx context.Context, url string) (string, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err.Error()
	}
	req.Header.Set("User-Agent", probe.UserAgent())
	resp, err := c.client.Do(req)
	if err != nil {
		return "", trimErr(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", trimErr(err)
	}
	if resp.StatusCode >= 400 {
		return "", "http status " + strconv.Itoa(resp.StatusCode)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k == "ip" {
			if ip := strings.TrimSpace(v); isPublicIP(ip) {
				return ip, ""
			}
		}
	}
	if ip := ipv4Re.FindString(string(body)); ip != "" && isPublicIP(ip) {
		return ip, ""
	}
	return "", "no public IPv4 in body"
}

// stunEcho sends a RFC 5389 binding request and parses XOR-MAPPED-ADDRESS
// (or MAPPED-ADDRESS). Two attempts against the well-known packet loss.
func stunEcho(server string, timeout time.Duration) (string, string) {
	addr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return "", trimErr(err)
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return "", trimErr(err)
	}
	defer conn.Close()
	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:2], 0x0001)
	binary.BigEndian.PutUint32(req[4:8], 0x2112A442)
	_, _ = rand.Read(req[8:20])
	for attempt := 0; attempt < 2; attempt++ {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := conn.Write(req); err != nil {
			return "", trimErr(err)
		}
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			continue
		}
		if ip := parseSTUNMappedAddress(buf[:n]); ip != "" {
			return ip, ""
		}
	}
	return "", "no mapped address in stun response"
}

// parseSTUNMappedAddress extracts XOR-MAPPED-ADDRESS (0x0020, RFC 5389) or
// the legacy MAPPED-ADDRESS (0x0001).
func parseSTUNMappedAddress(msg []byte) string {
	if len(msg) < 20 {
		return ""
	}
	ml := int(binary.BigEndian.Uint16(msg[2:4]))
	attrs := msg[20:]
	if ml < len(attrs) {
		attrs = attrs[:ml]
	}
	plain := ""
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:2])
		l := int(binary.BigEndian.Uint16(attrs[2:4]))
		if len(attrs) < 4+l {
			break
		}
		v := attrs[4 : 4+l]
		if (typ == 0x0020 || typ == 0x8020) && l >= 8 && v[1] == 0x01 {
			xored := binary.BigEndian.Uint32(v[4:8]) ^ 0x2112A442
			return net.IPv4(byte(xored>>24), byte(xored>>16), byte(xored>>8), byte(xored)).String()
		}
		if typ == 0x0001 && l >= 8 && v[1] == 0x01 {
			plain = net.IPv4(v[4], v[5], v[6], v[7]).String()
		}
		adv := 4 + l
		if l%4 != 0 {
			adv += 4 - l%4
		}
		attrs = attrs[adv:]
	}
	return plain
}

// dnsEcho asks "server|qname" for the qname's TXT records and extracts the
// first public IPv4 (the authoritative-resolver echo trick).
func (c *egressCollector) dnsEcho(ctx context.Context, target string) (string, string) {
	server, qname, ok := strings.Cut(target, "|")
	if !ok {
		return "", "dns source target must be server|qname"
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp4", resolverAddr(server))
		},
	}
	qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	vals, err := resolver.LookupTXT(qctx, qname)
	if err != nil {
		return "", trimErr(err)
	}
	for _, v := range vals {
		if ip := ipv4Re.FindString(v); ip != "" && isPublicIP(ip) {
			return ip, ""
		}
	}
	return "", "no public IPv4 in TXT"
}

// lookupASN resolves the origin ASN via Team Cymru's DNS interface
// (reverse.octets.origin.asn.cymru.com TXT) through the first configured
// resolver that answers, with a 24h cache. Best-effort: failures leave the
// fields empty.
func (c *egressCollector) lookupASN(ctx context.Context, ip string) (string, string) {
	if v, ok := c.asnCache.Load(ip); ok {
		e := v.(asnEntry)
		if time.Since(e.at) < 24*time.Hour {
			return e.asn, e.name
		}
	}
	qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	v4 := net.ParseIP(ip).To4()
	if v4 == nil {
		return "", ""
	}
	qname := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	var asn, asName string
	for _, server := range c.cfg.ASNResolvers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 3 * time.Second}
				return d.DialContext(ctx, "udp4", resolverAddr(server))
			},
		}
		vals, err := resolver.LookupTXT(qctx, qname)
		if err != nil || len(vals) == 0 {
			continue
		}
		f := strings.Split(vals[0], "|")
		if len(f) >= 2 {
			if fields := strings.Fields(strings.TrimSpace(f[0])); len(fields) > 0 {
				asn = fields[0]
			}
		}
		if asn != "" {
			// Best-effort AS name lookup (second TXT query, same resolver).
			// Live responses vary: with an empty bgp-prefix the name lands
			// on field 4, the documented 6-field layout puts it on 5. Take
			// the last populated of the two.
			if nv, nerr := resolver.LookupTXT(qctx, "AS"+asn+".asn.cymru.com"); nerr == nil && len(nv) > 0 {
				nf := strings.Split(nv[0], "|")
				if len(nf) >= 6 && strings.TrimSpace(nf[5]) != "" {
					asName = strings.TrimSpace(nf[5])
				} else if len(nf) >= 5 {
					asName = strings.TrimSpace(nf[4])
				}
			}
			break
		}
	}
	c.asnCache.Store(ip, asnEntry{asn: asn, name: asName, at: time.Now()})
	return asn, asName
}

type asnEntry struct {
	asn, name string
	at        time.Time
}

// readLocalEgress returns the default-route gateway IP and interface from
// /proc/net/route (little-endian hex columns). Empty on non-Linux.
func readLocalEgress() (gwIP, iface string) {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", ""
	}
	return parseProcNetRoute(string(data))
}

// parseProcNetRoute extracts the first default route's gateway + interface.
// Exposed for tests; the gateway column is little-endian hex.
func parseProcNetRoute(content string) (gwIP, iface string) {
	lines := strings.Split(content, "\n")
	if len(lines) < 2 {
		return "", ""
	}
	for _, line := range lines[1:] {
		cols := strings.Fields(line)
		if len(cols) < 8 || cols[1] != "00000000" {
			continue
		}
		hex := cols[2]
		if len(hex) != 8 {
			continue
		}
		var b [4]byte
		for i := 0; i < 4; i++ {
			v, err := strconv.ParseUint(hex[8-2*i-2:8-2*i], 16, 8)
			if err != nil {
				return "", ""
			}
			b[i] = byte(v)
		}
		return net.IPv4(b[0], b[1], b[2], b[3]).String(), cols[0]
	}
	return "", ""
}

// resolverAddr normalizes a configured resolver to a UDP dial address:
// host, host:port, or [v6]:port pass through, bare hosts get :53.
func resolverAddr(server string) string {
	if strings.Contains(server, ":") {
		return server
	}
	return net.JoinHostPort(server, "53")
}

// isPublicIP reports whether s parses as a global-scope IPv4. CGNAT space
// (100.64/10) deliberately counts: it IS the egress identity the ISP
// presents even when a further NAT sits behind it. Documentation and
// benchmark ranges do not.
func isPublicIP(s string) bool {
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return false
	}
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	switch {
	case ip[0] == 192 && ip[1] == 0: // 192.0.0.0/24 + TEST-NET-1 192.0.2.0/24
		return false
	case ip[0] == 198 && (ip[1] == 18 || ip[1] == 19): // benchmarking
		return false
	case ip[0] == 198 && ip[1] == 51 && ip[2] == 100: // TEST-NET-2
		return false
	case ip[0] == 203 && ip[1] == 0 && ip[2] == 113: // TEST-NET-3
		return false
	}
	return true
}

// trimErr keeps error strings bounded for storage.
func trimErr(err error) string {
	s := err.Error()
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
