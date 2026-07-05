package probe

import (
	"context"
	"time"
)

// ProbeResult holds the outcome of a single probe execution.
type ProbeResult struct {
	Success      bool
	Latency      time.Duration
	ErrorMessage string
}

// Prober is the interface that all probe types must implement.
type Prober interface {
	Probe(ctx context.Context, target string, timeout time.Duration) (*ProbeResult, error)
}
