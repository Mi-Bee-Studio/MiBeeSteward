package probe

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// HTTPProber sends HTTP/HTTPS GET requests to a target URL.
type HTTPProber struct{}

// Probe performs an HTTP GET to the target URL and checks the status code.
func (p *HTTPProber) Probe(ctx context.Context, target string, timeout time.Duration) (*ProbeResult, error) {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		slog.Error("probe failed", "method", "http", "target", target, "error", err)
		return &ProbeResult{
			Success:      false,
			ErrorMessage: err.Error(),
		}, nil
	}

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start)

	if err != nil {
		slog.Error("probe failed", "method", "http", "target", target, "error", err)
		return &ProbeResult{
			Success:      false,
			Latency:      elapsed,
			ErrorMessage: err.Error(),
		}, nil
	}
	defer resp.Body.Close()

	latency := elapsed
	if success := resp.StatusCode < 400; success {
		slog.Debug("probe executed", "method", "http", "target", target, "success", true, "latency", latency)
		return &ProbeResult{
			Success: true,
			Latency: latency,
		}, nil
	}

	slog.Debug("probe executed", "method", "http", "target", target, "success", false, "latency", latency)
	return &ProbeResult{
		Success:      false,
		Latency:      latency,
		ErrorMessage: http.StatusText(resp.StatusCode),
	}, nil
}
