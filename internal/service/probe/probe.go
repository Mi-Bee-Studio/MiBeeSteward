package probe

import (
	"context"
	"time"
)

// Result holds the outcome of a single probe execution.
type Result struct {
	Success      bool
	Latency      time.Duration
	ErrorMessage string
}

// Prober is the interface that all probe types must implement.
type Prober interface {
	Probe(ctx context.Context, target string, timeout time.Duration) (*Result, error)
}
