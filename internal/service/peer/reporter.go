// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// Package peer implements the federated-peer reporter (#379): the component
// a center embeds to mirror ITS OWN network's devices to a peer center. It
// reuses the agent-report channel verbatim (POST /agents/report with a peer
// bearer token) - the peer's ingestion handler, lease sweeper, and
// change-detection run the exact same pipeline they run for Rust agents, so
// "not sharing" anything beyond the device portrait is free: the wire format
// carries nothing else.
//
// Deliberately NOT included (the read-only federation boundary): the command
// poller and prober (a peer must never dispatch scans/probes/reboots into
// the other segment), fingerprint sync, and credential exchange.
//
// Ported from the retired internal/agent Reporter (PR #483 retired the Go
// agent; this is the center-side resurrection of its reporting half).
package peer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	"mibee-steward/internal/domain"
	"mibee-steward/internal/service/scannerv2"
	"mibee-steward/internal/service/scannerv2/runner"
	"mibee-steward/internal/service/scannerv2/store"
)

// Reporter buffers this center's scan results and passive discoveries, and
// flushes them to the peer center's POST /agents/report endpoint. It
// implements runner.ReportSink (Report) for scan batches; ReportPassive is
// the discovery funnel's per-host trickle. Exponential-backoff retries with a
// bounded pending queue ride out peer outages; the peer's leases expire
// during long outages and re-converge on recovery.
type Reporter struct {
	peerURL     string // base URL, e.g. "http://192.168.2.1:8080"
	authToken   string // peer bearer token (minted ON THE PEER)
	agentID     string // advisory label echoed in the report body
	networkCIDR string // this center's own cidr; the peer backfills networks.cidr from it
	client      *http.Client
	logger      *slog.Logger

	mu         sync.Mutex
	buf        []domain.ReportedHost
	bufScan    int
	pending    [][]byte
	flush      time.Duration
	maxBuf     int
	maxPending int

	version    string
	startTime  time.Time
	scansTotal int64
	lastPostAt time.Time

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewReporter constructs a peer Reporter. peerURL is the peer center's base
// URL, authToken the peer token minted on it, agentID the advisory label,
// networkCIDR this center's own cidr. flush ≤0 → 30s; maxBuf ≤0 → 256.
func NewReporter(peerURL, authToken, agentID, networkCIDR string, flush time.Duration, maxBuf int, logger *slog.Logger) *Reporter {
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
		peerURL:     peerURL,
		startTime:   time.Now(),
		authToken:   authToken,
		agentID:     agentID,
		networkCIDR: networkCIDR,
		client:      newPeerClient(30 * time.Second),
		logger:      logger,
		flush:       flush,
		maxBuf:      maxBuf,
		maxPending:  100,
	}
}

// SetVersion stamps the build version shipped in the report meta block.
func (r *Reporter) SetVersion(v string) { r.version = v }

// Meta builds the fleet-observability block for the current report.
func (r *Reporter) Meta() domain.AgentMeta {
	r.mu.Lock()
	scans := r.scansTotal
	r.mu.Unlock()
	host, _ := os.Hostname()
	return domain.AgentMeta{
		Version:    r.version,
		GoVersion:  runtime.Version(),
		Hostname:   host,
		UptimeSec:  int64(time.Since(r.startTime).Seconds()),
		ScansTotal: scans,
	}
}

// Report is the runner.ReportSink implementation: convert alive HostReports
// to the wire payload, buffer, flush early when the buffer fills.
func (r *Reporter) Report(_ context.Context, _ int64, reports []scannerv2.HostReport) {
	r.mu.Lock()
	r.scansTotal++
	for _, rep := range reports {
		if !rep.Alive || rep.IP == "" {
			continue
		}
		r.buf = append(r.buf, HostToReported(rep))
		r.bufScan++
	}
	full := len(r.buf) >= r.maxBuf
	r.mu.Unlock()
	if full {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.flushOnce(context.Background())
		}()
	}
}

// ReportPassive buffers a single passively-discovered host (the discovery
// funnel's Forward hook); tagged origin="passive" on the wire.
func (r *Reporter) ReportPassive(_ context.Context, rep scannerv2.HostReport) {
	if !rep.Alive || rep.IP == "" {
		return
	}
	r.mu.Lock()
	r.buf = append(r.buf, HostToReported(rep))
	full := len(r.buf) >= r.maxBuf
	r.mu.Unlock()
	if full {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			r.flushOnce(context.Background())
		}()
	}
}

// Start launches the periodic flush loop (pending backlog first, then the
// current buffer). A detached context per tick body: Stop cancels the loop
// without cutting an in-flight POST mid-response.
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
				r.flushPending(context.Background())
				r.flushOnce(context.Background())
			}
		}
	}()
}

// Stop cancels the loop and does a final flush of buffered + pending batches.
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

func (r *Reporter) flushOnce(ctx context.Context) {
	r.mu.Lock()
	if len(r.buf) == 0 {
		// Status-only heartbeat: keep the peer's fleet liveness fresh between
		// scans without touching leases or the device bridge. Throttled to
		// ≥30s so idle heartbeats stay cheap.
		if !r.lastPostAt.IsZero() && time.Since(r.lastPostAt) < 30*time.Second {
			r.mu.Unlock()
			return
		}
		r.mu.Unlock()
		metaVal := r.Meta()
		body, err := json.Marshal(domain.AgentReport{
			AgentID:     r.agentID,
			NetworkCIDR: r.networkCIDR,
			ScannedAt:   time.Now().UTC(),
			Meta:        &metaVal,
		})
		if err != nil {
			return
		}
		if r.postWithRetry(ctx, body, 0, "") {
			r.markPosted()
		}
		return
	}
	hosts := r.buf
	fromScan := r.bufScan > 0
	r.buf = nil
	r.bufScan = 0
	r.mu.Unlock()

	batchMeta := r.Meta()
	payload := domain.AgentReport{
		AgentID:     r.agentID,
		NetworkCIDR: r.networkCIDR,
		ScannedAt:   time.Now().UTC(),
		Meta:        &batchMeta,
		Hosts:       hosts,
	}
	if !fromScan {
		payload.Origin = "passive"
	}
	body, err := json.Marshal(payload)
	if err != nil {
		r.logger.Warn("peer reporter: marshal failed, dropping batch", "hosts", len(hosts), "error", err)
		return
	}
	hash := ""
	if fromScan {
		hash = NetworkStateHash(hosts)
	}
	if r.postWithRetry(ctx, body, len(hosts), hash) {
		r.markPosted()
	} else {
		r.enqueuePending(body)
	}
}

func (r *Reporter) markPosted() {
	r.mu.Lock()
	r.lastPostAt = time.Now()
	r.mu.Unlock()
}

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
		if r.postWithRetry(ctx, body, -1, "") {
			continue
		}
		remaining = append(remaining, body)
	}
	if len(remaining) > 0 {
		r.mu.Lock()
		r.pending = append(remaining, r.pending...)
		r.mu.Unlock()
	}
}

func (r *Reporter) enqueuePending(body []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.pending) >= r.maxPending {
		r.pending = r.pending[1:]
		r.logger.Warn("peer reporter: pending queue full, dropping oldest batch", "max", r.maxPending)
	}
	r.pending = append(r.pending, body)
	r.logger.Warn("peer reporter: batch enqueued for retry", "pending", len(r.pending))
}

// FlushPendingForTest exposes flushPending for tests.
func (r *Reporter) FlushPendingForTest() { r.flushPending(context.Background()) }

// postWithRetry sends one JSON body with up to 4 attempts (1s/2s/4s/8s).
// stateHash rides X-Network-State-Hash for the peer's anti-entropy fast path.
// 4xx (except 429) is terminal (bad token) and returns true to avoid
// re-queueing an unrecoverable payload.
func (r *Reporter) postWithRetry(ctx context.Context, body []byte, hostCount int, stateHash string) bool {
	url := r.peerURL + "/api/v1/agents/report"
	backoff := time.Second
	for attempt := 1; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			r.logger.Warn("peer reporter: request build failed", "error", err)
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
					r.logger.Info("peer reporter: report accepted", "hosts", hostCount, "attempt", attempt)
				} else {
					r.logger.Info("peer reporter: pending batch delivered", "attempt", attempt)
				}
				return true
			}
			if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
				r.logger.Warn("peer reporter: peer rejected report (terminal)", "status", resp.StatusCode)
				return true
			}
			err = errRejected{status: resp.StatusCode}
		}
		if attempt >= 4 {
			return false
		}
		r.logger.Warn("peer reporter: report failed, retrying", "attempt", attempt, "error", err, "backoff", backoff)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

type errRejected struct{ status int }

func (e errRejected) Error() string { return "peer rejected report" }

// HostToReported converts one in-memory HostReport to the wire payload
// (runner.ReportedHostToReport in reverse). Exported for tests.
func HostToReported(rep scannerv2.HostReport) domain.ReportedHost {
	f := rep.Device.Fields
	out := domain.ReportedHost{
		IP:                  rep.IP,
		Alive:               rep.Alive,
		RTTMs:               rep.RTTMs,
		MAC:                 f["mac"],
		InferredType:        f["inferred_type"],
		InferredTypeSource:  f["inferred_type_source"],
		InferredBrand:       f["inferred_brand"],
		InferredModel:       f["inferred_model"],
		InferredDescription: f["inferred_description"],
		InferredLocation:    f["inferred_location"],
		Hostname:            firstNonEmptyStr(f["node_hostname"], f["sys_name"]),
		OpenPorts:           f["open_ports"],
		DetectedServices:    f["detected_services"],
		PrometheusURL:       f["prometheus_url"],
		NodeExporterURL:     f["node_exporter_url"],
	}
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
	// Interface census (#529) + route table (#528): the flat wire arrays are
	// the only channel these cross on; the peer rebuilds them as evidence on
	// ingest exactly like an agent report.
	for _, e := range rep.Evidence {
		rd := e.RawData
		if rd == nil {
			continue
		}
		switch e.Kind {
		case "interface":
			idx := 0
			if v, err := strconv.Atoi(rd["if_index"]); err == nil {
				idx = v
			}
			if idx <= 0 {
				continue
			}
			speed := int64(0)
			if v, err := strconv.ParseInt(rd["speed_mbps"], 10, 64); err == nil {
				speed = v
			}
			out.Interfaces = append(out.Interfaces, domain.ReportedInterface{
				IfIndex: idx, IfName: rd["if_name"], IfDescr: rd["if_descr"],
				MAC: rd["mac"], IP: rd["ip"], SpeedMbps: speed,
			})
		case "route":
			if rd["dest"] == "" || rd["next_hop"] == "" {
				continue
			}
			ifx := 0
			if v, err := strconv.Atoi(rd["if_index"]); err == nil {
				ifx = v
			}
			out.Routes = append(out.Routes, domain.ReportedRoute{
				DestCIDR: rd["dest"], NextHop: rd["next_hop"], IfIndex: ifx, Proto: rd["proto"],
			})
		}
	}
	// L2 adjacency: "neighbor"-kind evidence rides the neighbors array; the
	// evidence slice itself never crosses the wire.
	seen := map[string]bool{}
	for _, e := range rep.Evidence {
		if e.Kind != "neighbor" || e.RawData == nil {
			continue
		}
		mac := store.NormalizeMAC(e.RawData["neighbor_mac"])
		protocol := e.RawData["protocol"]
		if mac == "" || protocol == "" {
			continue
		}
		key := mac + "|" + protocol
		if seen[key] {
			continue
		}
		seen[key] = true
		out.Neighbors = append(out.Neighbors, domain.ReportedNeighbor{
			NeighborMAC: mac,
			Protocol:    protocol,
			LocalPort:   e.RawData["local_port"],
			RemotePort:  e.RawData["remote_port"],
			VLANTag:     e.RawData["vlan_tag"],
			SysName:     e.RawData["sys_name"],
			SysDesc:     e.RawData["sys_desc"],
			Source:      e.Source,
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

// NetworkStateHash computes the anti-entropy digest of the alive set's
// identity+classification fields (mirrors changedetect.DeviceSnapshot's
// field set, sorted by IP for order independence).
func NetworkStateHash(hosts []domain.ReportedHost) string {
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

// newPeerClient builds an *http.Client tuned for the peer link: aggressively
// reaped idle connections (a peer restart leaves half-open sockets that can
// park a read for minutes) and a bounded dial timeout.
func newPeerClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          10,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// Compile-time check that Reporter satisfies the runner.ReportSink signature.
var _ runner.ReportSink = (*Reporter)(nil).Report
