package probe

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// ICMPProber sends ICMP ping requests to a target.
type ICMPProber struct{}

// Probe sends a single ICMP ping to the target and returns the result.
func (p *ICMPProber) Probe(ctx context.Context, target string, timeout time.Duration) (*Result, error) {
	pinger, err := probing.NewPinger(target)
	if err != nil {
		slog.Error("probe failed", "method", "icmp", "target", target, "error", err)
		return &Result{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to create pinger: %v", err),
		}, nil
	}

	pinger.Timeout = timeout
	pinger.Count = 1
	pinger.SetPrivileged(false)

	start := time.Now()
	err = pinger.RunWithContext(ctx)
	elapsed := time.Since(start)

	if err != nil {
		slog.Error("probe failed", "method", "icmp", "target", target, "error", err)
		return &Result{
			Success:      false,
			Latency:      elapsed,
			ErrorMessage: err.Error(),
		}, nil
	}

	stats := pinger.Statistics()
	if stats.PacketsRecv > 0 {
		slog.Debug("probe executed", "method", "icmp", "target", target, "success", true, "latency", stats.AvgRtt)
		return &Result{
			Success: true,
			Latency: stats.AvgRtt,
		}, nil
	}

	slog.Debug("probe executed", "method", "icmp", "target", target, "success", false, "latency", elapsed)
	return &Result{
		Success:      false,
		Latency:      elapsed,
		ErrorMessage: "no response received",
	}, nil
}
