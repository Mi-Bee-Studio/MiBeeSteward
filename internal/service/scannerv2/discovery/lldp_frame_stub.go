//go:build !WITH_LLDP

// Stub build (default): no raw-frame LLDP listener. The real implementation
// (lldp_frame_real.go, build tag WITH_LLDP) requires AF_PACKET raw sockets
// (CAP_NET_RAW) to capture ethertype 0x88cc frames, which would break the
// project's unprivileged deployment model. Build with -tags WITH_LLDP to
// enable it. This mirror's the eBPF observer's build-tag pattern.

package discovery

import (
	"context"
	"log/slog"
)

// LLDPFrameSource is nil in the default build — NewLLDPFrameSource returns nil,
// and the caller skips registration. See lldp_frame_real.go (WITH_LLDP) for the
// real listener.
type lldpFrameSource struct{}

// NewLLDPFrameSource returns nil in the default (no-WITH_LLDP) build, signaling
// to the caller that raw-frame LLDP listening is unavailable. interfaces is the
// list of NIC names to listen on (empty = all). svc is the discovery
// coordinator (for host events); neighborSink receives neighbor edges.
func NewLLDPFrameSource(interfaces []string, svc *Service, neighborSink func(localMAC string, neighbors []lldpEdge), logger *slog.Logger) *lldpFrameSource {
	if logger != nil {
		logger.Info("lldp_frame source disabled (build without WITH_LLDP)")
	}
	return nil
}

// Start is unreachable (NewLLDPFrameSource returns nil in this build). Present
// for the type signature so the real/stub files share the same call surface.
func (s *lldpFrameSource) Start(_ context.Context) {}

// Name satisfies the naming convention used in activeSources logging.
func (s *lldpFrameSource) Name() string { return "lldp_frame" }
