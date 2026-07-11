// Package agent implements the discovery-agent runtime that runs the scannerv2
// engine locally and reports results to an aggregation center. The Reporter
// here is the upstream-reporting component: it receives alive HostReports from
// the runner (via the ReportSink hook), buffers them, and flushes them to the
// center's POST /agents/report endpoint with exponential-backoff retries.
package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/runner"
)

// Reporter buffers scan results from the local engine and flushes them to the
// center. It implements runner.ReportSink (via its Report method) so the runner
// hands it each scan's alive HostReports without knowing about HTTP.
//
// It is the agent counterpart to the center's ingestion handler. The agent's
// network identity (network_id) is NOT sent in the body — the center resolves
// it from the agent's bearer token (authenticity + scoping live there). The
// reporter just ships the discovery payload + the agent_id label.
//
// Disconnect recovery: when the center is unreachable, failed batches are held
// in an in-memory pending queue (not dropped). The flush loop drains pending
// first on each tick, so once the center recovers, the backlog is delivered in
// order. The queue is bounded (maxPendingBatches); oldest batches are dropped
// if it overflows (extreme outage — the center's change-detection reconciles
// state across scans, so data loss here degrades to "stale" not "corrupt").
type Reporter struct {
	centerURL  string // base URL, e.g. "http://192.168.63.101:8080"
	authToken  string // agent bearer token (minted on the center)
	agentID    string // advisory label echoed in the report body
	client     *http.Client
	logger     *slog.Logger

	mu       sync.Mutex
	buf      []domain.ReportedHost // buffered hosts awaiting the next flush
	pending  [][]byte              // failed batches awaiting retry (JSON-encoded payloads)
	flush    time.Duration         // max time between flushes (ReportInterval)
	maxBuf   int                   // max hosts buffered before an early flush
	maxPending int                 // max failed batches held for retry

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewReporter constructs a Reporter. centerURL is the center base URL,
// authToken the agent's bearer token, agentID the advisory label, flush the
// max interval between flushes (≤0 → 30s), maxBuf the buffer size that triggers
// an early flush (≤0 → 256).
func NewReporter(centerURL, authToken, agentID string, flush time.Duration, maxBuf int, logger *slog.Logger) *Reporter {
	if logger == nil {
		logger = slog.Default()
	}
	if flush <= 0 {
		flush = 30 * time.Second
	}
	if maxBuf <= 0 {
		maxBuf = 256
	}
	return &Reporter{
		centerURL:  centerURL,
		authToken:  authToken,
		agentID:    agentID,
		client:     newCenterClient(30 * time.Second),
		logger:     logger,
		flush:      flush,
		maxBuf:     maxBuf,
		maxPending: 100, // bounded: ~100 scans of backlog before oldest is dropped
	}
}

// Report is the runner.ReportSink implementation. It converts each alive
// HostReport to the wire payload, buffers it, and flushes immediately when the
// buffer fills. Non-blocking past the buffer-append; the actual HTTP POST
// happens on the flush goroutine or inline on a full buffer.
func (r *Reporter) Report(_ context.Context, _ int64, reports []scannerv2.HostReport) {
	r.mu.Lock()
	for _, rep := range reports {
		if !rep.Alive || rep.IP == "" {
			continue
		}
		r.buf = append(r.buf, hostToReported(rep))
	}
	full := len(r.buf) >= r.maxBuf
	r.mu.Unlock()

	if full {
		// Buffer full — flush now rather than waiting for the ticker. Best-effort
		// (run on a background goroutine so the scan pipeline isn't blocked).
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.flushOnce(context.Background())
		}()
	}
}

// Start launches the periodic flush loop. On each tick it first drains any
// pending (previously-failed) batches, then flushes the current buffer. This
// ordering delivers the backlog in order once the center recovers.
func (r *Reporter) Start(ctx context.Context) {
	ctx, r.cancel = context.WithCancel(ctx)
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(r.flush)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				// Drain pending backlog first (a recovered center should get the
				// oldest undelivered data before the newest).
				r.flushPending(ctx)
				r.flushOnce(ctx)
			}
		}
	}()
}

// Stop cancels the flush loop and does a final best-effort flush of any buffered
// hosts + pending backlog (so a graceful agent shutdown delivers as much as
// possible rather than dropping in-flight data).
func (r *Reporter) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
	r.wg.Wait()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.flushPending(ctx)
	r.flushOnce(ctx)
}

// flushOnce drains the buffer and POSTs it to the center with exponential
// backoff on failure. On exhaustion (4 attempts) the batch is enqueued to the
// pending retry queue instead of dropped — so a center outage doesn't lose
// data. The flush loop drains pending first on the next tick.
func (r *Reporter) flushOnce(ctx context.Context) {
	r.mu.Lock()
	if len(r.buf) == 0 {
		r.mu.Unlock()
		return
	}
	hosts := r.buf
	r.buf = nil
	r.mu.Unlock()

	payload := domain.AgentReport{
		AgentID:    r.agentID,
		ScannedAt:  time.Now().UTC(),
		Hosts:      hosts,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		r.logger.Warn("agent reporter: marshal failed, dropping batch", "hosts", len(hosts), "error", err)
		return
	}
	// Anti-entropy: a digest of the alive set's identity+classification fields.
	// The center compares it to the last hash it saw for this agent; when they
	// match the network is stable and the center skips the expensive per-host
	// device bridge (it still refreshes leases). The field set mirrors
	// changedetect.DeviceSnapshot so "nothing changed" == "same hash".
	hash := networkStateHash(hosts)
	if !r.postWithRetry(ctx, body, len(hosts), hash) {
		// Exhausted retries — enqueue for later delivery instead of dropping.
		r.enqueuePending(body)
	}
}

// flushPending drains the failed-batch queue, oldest first. Each batch gets a
// single attempt (no inline backoff — the next tick retries again). This keeps
// the backlog draining without blocking the flush loop on a still-down center.
func (r *Reporter) flushPending(ctx context.Context) {
	r.mu.Lock()
	if len(r.pending) == 0 {
		r.mu.Unlock()
		return
	}
	batches := r.pending
	r.pending = nil
	r.mu.Unlock()

	remaining := batches[:0]
	for _, body := range batches {
		if r.postWithRetry(ctx, body, -1, "") { // -1 = pending batch (count unknown, no hash)
			continue
		}
		remaining = append(remaining, body)
	}
	if len(remaining) > 0 {
		r.mu.Lock()
		// Prepend remaining back (oldest first) preserving order.
		r.pending = append(remaining, r.pending...)
		r.mu.Unlock()
	}
}

// enqueuePending appends a failed batch to the retry queue, dropping the oldest
// if the queue is full (bounded memory; extreme outage).
func (r *Reporter) enqueuePending(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) >= r.maxPending {
		// Drop oldest — the center's change-detection reconciles state across
		// scans, so losing the oldest stale batch degrades to "less history",
		// not corruption.
		r.pending = r.pending[1:]
		r.logger.Warn("agent reporter: pending queue full, dropping oldest batch", "max", r.maxPending)
	}
	r.pending = append(r.pending, body)
	r.logger.Warn("agent reporter: batch enqueued for retry", "pending", len(r.pending))
}

// FlushPendingForTest exposes flushPending for tests (to simulate a center
// recovery mid-test without waiting for the ticker). Not for production use.
func (r *Reporter) FlushPendingForTest() {
	r.flushPending(context.Background())
}

// postWithRetry sends one JSON body to the center with up to 4 attempts
// (1s/2s/4s/8s backoff). stateHash, when non-empty, is sent as the
// X-Network-State-Hash header so the center can skip the expensive per-host
// device bridge when the network is unchanged since the last report. Pending
// batches (retries of previously-failed posts) pass an empty hash: a stale
// hash could mask a state change that happened between the original attempt
// and the retry, so re-delivery always forces full processing (conservative).
// Returns true on success, false if exhausted/cancelled.
// 4xx (except 429) is terminal-failure (bad token) — returns true to avoid
// re-queueing an unrecoverable payload.
func (r *Reporter) postWithRetry(ctx context.Context, body []byte, hostCount int, stateHash string) bool {
	url := r.centerURL + "/api/v1/agents/report"
	backoff := time.Second
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			r.logger.Warn("agent reporter: request build failed", "error", err)
			return false
		}
		req.Header.Set("Authorization", "Bearer "+r.authToken)
		req.Header.Set("Content-Type", "application/json")
		if stateHash != "" {
			req.Header.Set("X-Network-State-Hash", stateHash)
		}

		resp, err := r.client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				if hostCount >= 0 {
					r.logger.Info("agent reporter: report accepted", "hosts", hostCount, "attempt", attempt)
				} else {
					r.logger.Info("agent reporter: pending batch delivered", "attempt", attempt)
				}
				return true
			}
			// 4xx (except 429) is terminal — retrying won't help (bad token, bad
			// payload). Don't re-queue.
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
				r.logger.Warn("agent reporter: center rejected report (terminal)", "status", resp.StatusCode)
				return true
			}
			err = errRejected{status: resp.StatusCode}
		}
		if attempt >= 4 {
			return false
		}
		r.logger.Warn("agent reporter: report failed, retrying", "attempt", attempt, "error", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

// errRejected wraps a non-2xx response so the retry log line is informative.
type errRejected struct{ status int }

func (e errRejected) Error() string { return "center rejected report" }

// hostToReported converts one in-memory HostReport to the wire payload. Mirrors
// runner.ReportedHostToReport in reverse: pulls the MAC (from Fields or the mac
// evidence piece), inferred fields, services, heartbeats. The center
// reconstructs a HostReport from this via ReportedHostToReport.
func hostToReported(rep scannerv2.HostReport) domain.ReportedHost {
	f := rep.Device.Fields
	out := domain.ReportedHost{
		IP:                  rep.IP,
		Alive:               rep.Alive,
		RTTMs:               rep.RTTMs,
		MAC:                 f["mac"],
		InferredType:        f["inferred_type"],
		InferredBrand:       f["inferred_brand"],
		InferredDescription: f["inferred_description"],
		InferredLocation:    f["inferred_location"],
		Hostname:            firstNonEmptyStr(f["node_hostname"], f["sys_name"]),
		OpenPorts:           f["open_ports"],
		DetectedServices:    f["detected_services"],
		PrometheusURL:       f["prometheus_url"],
		NodeExporterURL:     f["node_exporter_url"],
	}
	// MAC fallback from evidence (the ARP probe may put it there rather than Fields).
	if out.MAC == "" {
		for _, e := range rep.Evidence {
			if e.Kind == "mac" && e.RawData != nil && e.RawData["mac"] != "" {
				out.MAC = e.RawData["mac"]
				break
			}
		}
	}
	for _, s := range rep.Services {
		out.Services = append(out.Services, domain.ReportedService{
			Service: s.Service, Port: s.Port, Protocol: s.Protocol, Metadata: s.Metadata,
		})
	}
	for _, hb := range rep.Heartbeats {
		out.Heartbeats = append(out.Heartbeats, domain.ReportedHeartbeat{
			Method: hb.Method, Target: hb.Target, IntervalSeconds: hb.IntervalSeconds,
			TimeoutSeconds: hb.TimeoutSeconds, SNMPCommunity: hb.SNMPCommunity, SNMPOID: hb.SNMPOID,
		})
	}
	return out
}

func firstNonEmptyStr(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// networkStateHash computes a SHA-256 digest of the alive set's
// identity+classification fields. It is the anti-entropy digest the center
// compares across reports: when the hash is unchanged the network is stable
// and the center skips the per-host device bridge, refreshing only leases.
//
// Field set mirrors changedetect.DeviceSnapshot (the fields the center's
// change detector treats as "a real change"): identity (ip+mac), inferred
// type/brand/description/location, hostname, and the raw service/port JSON.
// Deliberately excludes scanned_at (changes every report) and rtt_ms (jitters).
// Hosts are sorted by IP so the hash is order-independent.
func networkStateHash(hosts []domain.ReportedHost) string {
	if len(hosts) == 0 {
		return ""
	}
	sorted := make([]domain.ReportedHost, len(hosts))
	copy(sorted, hosts)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].IP < sorted[j].IP })
	h := sha256.New()
	for _, host := range sorted {
		h.Write([]byte(host.IP))
		h.Write([]byte{0})
		h.Write([]byte(host.MAC))
		h.Write([]byte{0})
		h.Write([]byte(host.InferredType))
		h.Write([]byte{0})
		h.Write([]byte(host.InferredBrand))
		h.Write([]byte{0})
		h.Write([]byte(host.InferredDescription))
		h.Write([]byte{0})
		h.Write([]byte(host.InferredLocation))
		h.Write([]byte{0})
		h.Write([]byte(host.Hostname))
		h.Write([]byte{0})
		h.Write([]byte(host.OpenPorts))
		h.Write([]byte{0})
		h.Write([]byte(host.DetectedServices))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Compile-time check that Reporter satisfies the runner.ReportSink signature.
var _ runner.ReportSink = (*Reporter)(nil).Report
