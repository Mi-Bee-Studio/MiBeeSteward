package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// APIRequestsTotal counts API requests by method, path, and status.
var APIRequestsTotal = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "mibee_api_requests_total",
		Help: "Total API requests",
	},
	[]string{"method", "path", "status"},
)

// APIRequestDuration records API request duration in seconds.
var APIRequestDuration = prometheus.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "mibee_api_request_duration_seconds",
		Help:    "API request duration in seconds",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"method", "path"},
)

func init() {
	prometheus.MustRegister(APIRequestsTotal)
	prometheus.MustRegister(APIRequestDuration)
}

// metricsResponseWriter wraps http.ResponseWriter to capture status code for metrics.
type metricsResponseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *metricsResponseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Metrics returns middleware that records Prometheus metrics for each API request.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &metricsResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(wrapped, r)
		duration := time.Since(start).Seconds()

		statusStr := strconv.Itoa(wrapped.status)
		APIRequestsTotal.WithLabelValues(r.Method, r.URL.Path, statusStr).Inc()
		APIRequestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration)
	})
}
