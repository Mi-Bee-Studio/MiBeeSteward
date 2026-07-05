package probe

import (
	"context"
	"log/slog"
	"time"
)

// RetryProber wraps a Prober with retry logic using exponential backoff.
type RetryProber struct {
	inner     Prober
	maxTries  int
	baseDelay time.Duration
}

// NewRetryProber creates a retry wrapper around a Prober.
// maxTries is the total number of attempts (e.g., 3 means 1 initial + 2 retries).
// baseDelay is the initial delay; subsequent delays double (1s → 2s → 4s).
func NewRetryProber(inner Prober, maxTries int, baseDelay time.Duration) *RetryProber {
	return &RetryProber{inner: inner, maxTries: maxTries, baseDelay: baseDelay}
}

// Probe executes the inner prober with retries on error.
// Successful probes return immediately. Probes that run but report failure
// (e.g., port closed, HTTP 500) are not retried — only network-level errors trigger retries.
func (rp *RetryProber) Probe(ctx context.Context, target string, timeout time.Duration) (*ProbeResult, error) {
	var lastResult *ProbeResult
	var lastErr error

	for attempt := 0; attempt < rp.maxTries; attempt++ {
		if attempt > 0 {
			delay := rp.baseDelay * time.Duration(1<<(attempt-1)) // 1s, 2s, 4s
			slog.Debug("probe retry", "attempt", attempt+1, "delay", delay, "target", target)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		result, err := rp.inner.Probe(ctx, target, timeout)
		if err != nil {
			lastErr = err
			slog.Debug("probe error, will retry", "attempt", attempt+1, "error", err, "target", target)
			continue
		}

		// Probe ran successfully — return result regardless of Success flag.
		// Only network-level errors (timeout, DNS failure, connection refused) trigger retries.
		return result, nil
	}

	if lastResult != nil {
		return lastResult, nil
	}
	return nil, lastErr
}
