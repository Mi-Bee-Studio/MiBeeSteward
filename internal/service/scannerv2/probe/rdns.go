package probe

import (
	"context"
	"net"
	"strings"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// RDNSProbe resolves the target IP's hostname via reverse DNS (PTR lookup).
// This is the cheapest source of a human-readable hostname: many networks
// (especially with mDNS reflectors or DNS servers that synthesize PTR records
// from DHCP leases) will answer for nearly every live host.
//
// The lookup uses the standard Go resolver, which honors /etc/resolv.conf.
// Honors hint.Timeout; falls back to 2s.
//
// Name: "active:rdns".
type RDNSProbe struct{ resolver *net.Resolver }

// NewRDNSProbe returns a reverse-DNS probe using the default system resolver.
func NewRDNSProbe() *RDNSProbe { return &RDNSProbe{resolver: net.DefaultResolver} }

func (p *RDNSProbe) Name() string { return "active:rdns" }

// Probe issues a PTR lookup for ip. Returns one "hostname" Evidence on success,
// nil evidence on miss/timeout (a host with no PTR record is normal).
func (p *RDNSProbe) Probe(ctx context.Context, ip string, hint scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	timeout := hint.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	names, err := p.resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return nil, nil
	}
	// net.LookupAddr returns FQDNs with a trailing dot ("host.example."); strip
	// the trailing dot for cleaner display and downstream matching.
	host := strings.TrimSuffix(names[0], ".")
	if host == "" {
		return nil, nil
	}
	return []scannerv2.Evidence{{
		Source:     "active:rdns",
		Kind:       "hostname",
		IP:         ip,
		RawData:    map[string]string{"hostname": host},
		Confidence: 0.8, // rDNS is best-effort; DHCP/mDNS names can be stale
		ObservedAt: time.Now(),
	}}, nil
}
