// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// defaultBurstInterval is the gap between echoes of one burst round when the
// target carries no explicit burst_interval_ms option (#744).
const defaultBurstInterval = 20 * time.Millisecond

// burstOutcome is the raw outcome of one ICMP round, prober-agnostic so the
// metric math (and the tests) never touch a real network.
type burstOutcome struct {
	RTTs []time.Duration // received echo RTTs, arrival order
	Sent int             // echoes sent
	Recv int             // echoes received
	IP   string          // resolved target IP ('' = unresolved)
	TTL  int             // reply TTL of the first echo (0 = none)
}

// icmpRunner executes one round of `count` echoes against target, waiting at
// most `timeout` for the round to complete. Production wires the pro-bing
// runner; tests inject fakes.
type icmpRunner func(target string, count int, interval, timeout time.Duration) (*burstOutcome, error)

// ICMPProber sends ICMP ping requests to a target.
type ICMPProber struct {
	// BurstCount is the echoes per round (#744): 0/1 = a single ping whose
	// result keeps the legacy shape (no loss/jitter metrics).
	BurstCount int
	// BurstIntervalMS is the gap between echoes; 0 = defaultBurstInterval.
	BurstIntervalMS int

	// runner is the injection seam for tests; nil = production pro-bing.
	runner icmpRunner
}

// LossPct computes a round's packet loss percentage. Nothing sent is reported
// as 0 (not measured), never NaN — burst metrics ride rows that already carry
// a status, so an empty round is "no data", not "all lost".
func LossPct(sent, recv int) float64 {
	if sent <= 0 {
		return 0
	}
	return float64(sent-recv) / float64(sent) * 100
}

// JitterMs computes the mean absolute difference of consecutive echo RTTs
// over the received-only series — the iperf-style jitter proxy. Fewer than
// two received echoes leave it undefined, reported as 0 (not measured).
func JitterMs(rtts []time.Duration) float64 {
	if len(rtts) < 2 {
		return 0
	}
	var sum time.Duration
	for i := 1; i < len(rtts); i++ {
		d := rtts[i] - rtts[i-1]
		if d < 0 {
			d = -d
		}
		sum += d
	}
	return float64(sum.Microseconds()) / 1000.0 / float64(len(rtts)-1)
}

// Probe sends one round to the target and returns the result. With burst
// options set the round is N echoes and the result carries loss_pct +
// jitter_ms; without them it is the legacy single ping.
func (p *ICMPProber) Probe(_ context.Context, target string, timeout time.Duration) (*Result, error) {
	count := p.BurstCount
	if count <= 0 {
		count = 1
	}
	interval := defaultBurstInterval
	if p.BurstIntervalMS > 0 {
		interval = time.Duration(p.BurstIntervalMS) * time.Millisecond
	}

	run := p.runner
	if run == nil {
		run = proBingRunner
	}

	out, err := run(target, count, interval, timeout)
	if err != nil {
		// unresolvable/invalid target — same per-target repeat cycle as any
		// other execution failure, route through the streak logger (a stale
		// DNS name on a heartbeat config fires this every cycle).
		logProbeFailure("icmp", target, err)
		return &Result{
			Success:      false,
			ErrorMessage: fmt.Sprintf("failed to create pinger: %v", err),
		}, nil
	}

	res := &Result{}
	if out.Recv > 0 {
		avg := meanRTT(out.RTTs)
		slog.Debug("probe executed", "method", "icmp", "target", target, "success", true, "latency", avg)
		noteProbeSuccess("icmp", target, avg)
		res.Success = true
		res.Latency = avg
		res.Phases = &Phases{ReplyTTL: out.TTL, ResolvedIP: out.IP}
	} else {
		slog.Debug("probe executed", "method", "icmp", "target", target, "success", false)
		res.Success = false
		res.ErrorMessage = "no response received"
	}

	// Burst metrics only when the round actually carried a burst: a
	// single-ping round keeps the pre-#744 row shape (loss folded into
	// status, jitter undefined).
	if count > 1 && out.Sent > 0 {
		res.LossPct = LossPct(out.Sent, out.Recv)
		res.JitterMs = JitterMs(out.RTTs)
	}
	return res, nil
}

// meanRTT is the mean of the received echo RTTs (pro-bing's AvgRtt equivalent
// over the fake-friendly RTT slice). An empty slice returns 0 — callers only
// reach it with Recv > 0.
func meanRTT(rtts []time.Duration) time.Duration {
	if len(rtts) == 0 {
		return 0
	}
	var sum time.Duration
	for _, r := range rtts {
		sum += r
	}
	return sum / time.Duration(len(rtts))
}

// proBingRunner is the production icmpRunner: pro-bing unprivileged UDP echo
// (Linux datagram; other platforms need privileges and are not a runtime
// target). One socket sends `count` echoes `interval` apart; the round ends
// at the timeout deadline regardless of how many echoes landed.
func proBingRunner(target string, count int, interval, timeout time.Duration) (*burstOutcome, error) {
	pinger, err := probing.NewPinger(target)
	if err != nil {
		return nil, err
	}
	pinger.Count = count
	pinger.Interval = interval
	pinger.Timeout = timeout
	pinger.SetPrivileged(false)

	out := &burstOutcome{}
	// #717: capture the reply TTL off the first echo response — the remaining
	// hop budget from the target's perspective (0 = answer never arrived).
	pinger.OnRecv = func(pkt *probing.Packet) {
		if out.TTL == 0 {
			out.TTL = pkt.TTL
		}
		out.RTTs = append(out.RTTs, pkt.Rtt)
	}

	if err := pinger.RunWithContext(context.Background()); err != nil {
		return nil, err
	}

	stats := pinger.Statistics()
	out.Sent = stats.PacketsSent
	out.Recv = stats.PacketsRecv
	if pinger.IPAddr() != nil {
		out.IP = pinger.IPAddr().IP.String()
	}
	return out, nil
}
