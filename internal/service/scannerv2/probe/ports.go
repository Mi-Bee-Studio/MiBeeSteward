// Package probe implements the ① Probe layer of scannerv2.
//
// Each ProbeSource gathers Evidence for one IP. Probes are domain-agnostic:
// they emit raw observations (port_open, banner bytes, SNMP varbinds, SOAP
// responses) and never decide what service is running — that's the
// Classifier's job.
//
// Active probes (this package) connect to the target. A passive eBPF observer
// lives in package ebpf (build-tag-gated).
package probe

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// DefaultFingerprintPorts are scanned first (priority ordering) so that
// high-signal services are identified even when a fast-scan aborts mid-way.
// Derived from the legacy fingerprint set plus camera ports.
var DefaultFingerprintPorts = []int{
	22, 80, 443, 8080, 8443, 8000, // common web/admin
	554, 8554, // RTSP (cameras)
	9090, 9100, 9104, 9113, 9121, 9187, // prometheus family
	161,        // SNMP
	3306, 5432, // databases
}

const (
	maxConcurrentDials = 100
	bannerReadSize     = 1024
	bannerReadTimeout  = 2 * time.Second
)

// PortSpecProbe scans a TCP port spec ("22,80,100-200") with priority ports
// scanned first. For each open port it emits a port_open Evidence plus, when a
// banner can be passively read or actively elicited, a banner Evidence. It
// does NOT do protocol-specific probing (no HTTP GET, no RTSP OPTIONS) — that
// is the job of the dedicated protocol probes, which run after port discovery.
//
// Name: "active:tcp".
type PortSpecProbe struct {
	ports            string // port spec, e.g. "22,80,443,8080,554"
	fingerprintPorts []int  // scanned first; nil → use DefaultFingerprintPorts
}

// NewPortSpecProbe constructs a port probe. ports is the spec scanned; if empty
// the fingerprint ports are scanned.
func NewPortSpecProbe(ports string, fingerprintPorts []int) *PortSpecProbe {
	if fingerprintPorts == nil {
		fingerprintPorts = DefaultFingerprintPorts
	}
	return &PortSpecProbe{ports: ports, fingerprintPorts: fingerprintPorts}
}

func (p *PortSpecProbe) Name() string { return "active:tcp" }

// Probe dials every port in the spec concurrently, emits port_open + banner
// evidence for open ports. hint.Ports is advisory and ignored (we scan the
// configured spec); hint.Timeout bounds each dial.
func (p *PortSpecProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	spec := p.ports
	if spec == "" {
		spec = joinInts(p.fingerprintPorts)
	}
	ports, err := priorityPortList(spec, p.fingerprintPorts)
	if err != nil {
		return nil, fmt.Errorf("active:tcp: invalid port spec: %w", err)
	}
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var (
		mu  sync.Mutex
		evs []scannerv2.Evidence
		wg  sync.WaitGroup
		sem = make(chan struct{}, maxConcurrentDials)
	)

	now := time.Now()
	for _, port := range ports {
		select {
		case <-ctx.Done():
			return evs, ctx.Err()
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			open, banner := dialAndGrab(ctx, ip, port, timeout)
			if !open {
				return
			}
			mu.Lock()
			evs = append(evs, scannerv2.Evidence{
				Source:     "active:tcp",
				Kind:       "port_open",
				IP:         ip,
				Port:       port,
				Protocol:   "tcp",
				Confidence: 1.0,
				ObservedAt: now,
			})
			if banner != "" {
				evs = append(evs, scannerv2.Evidence{
					Source:     "active:tcp",
					Kind:       "banner",
					IP:         ip,
					Port:       port,
					Protocol:   "tcp",
					RawData:    map[string]string{"banner": banner},
					Confidence: 0.9,
					ObservedAt: now,
				})
			}
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	return evs, nil
}

// dialAndGrab connects (TCP), and on success attempts a passive banner read.
// Many servers (SSH, RTSP, FTP, SMTP, redis) send a greeting immediately;
// others (HTTP) stay silent until a request and return "" banner. Returns
// (open, banner).
func dialAndGrab(ctx context.Context, ip string, port int, timeout time.Duration) (bool, string) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	// Passive banner read: don't send anything; wait briefly for a server
	// greeting. This avoids confusing request-then-response protocols and
	// keeps the probe pure ("what does the server volunteer?").
	_ = conn.SetReadDeadline(time.Now().Add(bannerReadTimeout))
	buf := make([]byte, bannerReadSize)
	n, _ := conn.Read(buf)
	return true, strings.TrimRight(string(buf[:n]), "\r\n\x00")
}

// priorityPortList orders ports with fingerprint ports first (in fingerprint
// order), then the remaining spec ports ascending, deduplicated. Mirrors the
// legacy behavior so fast-scan hits high-signal ports first.
func priorityPortList(spec string, fingerprintPorts []int) ([]int, error) {
	all, err := parsePortSpec(spec)
	if err != nil {
		return nil, err
	}
	if len(fingerprintPorts) == 0 {
		return all, nil
	}
	specSet := make(map[int]struct{}, len(all))
	for _, p := range all {
		specSet[p] = struct{}{}
	}
	fpSet := make(map[int]struct{}, len(fingerprintPorts))
	for _, p := range fingerprintPorts {
		if p >= 1 && p <= 65535 {
			fpSet[p] = struct{}{}
		}
	}
	result := make([]int, 0, len(all))
	seen := make(map[int]struct{})
	for _, fp := range fingerprintPorts {
		if _, inSpec := specSet[fp]; inSpec {
			if _, ok := seen[fp]; !ok {
				result = append(result, fp)
				seen[fp] = struct{}{}
			}
		}
	}
	for _, p := range all {
		if _, isFP := fpSet[p]; !isFP {
			result = append(result, p)
		}
	}
	return result, nil
}

// parsePortSpec parses "22,80,100-200" into a sorted, deduped []int.
func parsePortSpec(spec string) ([]int, error) {
	var out []int
	seen := make(map[int]struct{})
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if i := strings.Index(part, "-"); i > 0 {
			lo, err1 := strconv.Atoi(part[:i])
			hi, err2 := strconv.Atoi(part[i+1:])
			if err1 != nil || err2 != nil || lo < 1 || hi < lo || hi > 65535 {
				return nil, fmt.Errorf("invalid range %q", part)
			}
			if hi-lo > 10000 {
				return nil, fmt.Errorf("range %q too large (>10000)", part)
			}
			for p := lo; p <= hi; p++ {
				if _, ok := seen[p]; !ok {
					out = append(out, p)
					seen[p] = struct{}{}
				}
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil || p < 1 || p > 65535 {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			if _, ok := seen[p]; !ok {
				out = append(out, p)
				seen[p] = struct{}{}
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

func joinInts(in []int) string {
	parts := make([]string, len(in))
	for i, p := range in {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}

// readLine was removed (unused); protocol probes read banners inline.
