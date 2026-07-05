package probe

import (
	"context"
	"log/slog"
	"net"
	"time"
)

// TCPProber checks TCP port connectivity to a target address.
type TCPProber struct{}

// Probe attempts to establish a TCP connection to the target within the given timeout.
func (p *TCPProber) Probe(ctx context.Context, target string, timeout time.Duration) (*ProbeResult, error) {
	start := time.Now()
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	elapsed := time.Since(start)

	if err != nil {
		slog.Error("probe failed", "method", "tcp", "target", target, "error", err)
		return &ProbeResult{
			Success:      false,
			Latency:      elapsed,
			ErrorMessage: err.Error(),
		}, nil
	}
	conn.Close()

	slog.Debug("probe executed", "method", "tcp", "target", target, "success", true, "latency", elapsed)
	return &ProbeResult{
		Success: true,
		Latency: elapsed,
	}, nil
}
