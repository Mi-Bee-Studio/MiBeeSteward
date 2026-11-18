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
	"errors"
	"testing"
	"time"
)

// fakeBurstOutcome builds a burstOutcome with per-echo RTTs in one call.
func fakeBurstOutcome(rtts []time.Duration, sent, recv int) *burstOutcome {
	return &burstOutcome{RTTs: rtts, Sent: sent, Recv: recv}
}

// TestLossPct covers the burst loss percentage: the single-ping guard
// (sent<=0 → 0, never NaN), full loss, and the partial-loss fractions the
// quality verdicts consume (#744).
func TestLossPct(t *testing.T) {
	cases := []struct {
		name string
		sent int
		recv int
		want float64
	}{
		{"nothing sent", 0, 0, 0},
		{"all received", 10, 10, 0},
		{"all lost", 10, 0, 100},
		{"30% lost", 10, 7, 30},
		{"third received", 3, 1, 66.67},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := LossPct(tc.sent, tc.recv)
			if diff := got - tc.want; diff > 0.01 || diff < -0.01 {
				t.Errorf("LossPct(%d,%d) = %v, want %v", tc.sent, tc.recv, got, tc.want)
			}
		})
	}
}

// TestJitterMs pins the consecutive-difference definition: mean of |RTT[i] -
// RTT[i-1]| over the received series. Fewer than 2 echoes = undefined, 0.
func TestJitterMs(t *testing.T) {
	cases := []struct {
		name string
		rtts []time.Duration
		want float64
	}{
		{"no echoes", nil, 0},
		{"one echo", []time.Duration{5 * time.Millisecond}, 0},
		{"steady", []time.Duration{10 * time.Millisecond, 10 * time.Millisecond, 10 * time.Millisecond}, 0},
		{"two-step wave", []time.Duration{10 * time.Millisecond, 12 * time.Millisecond, 10 * time.Millisecond}, 2},
		{"ascending", []time.Duration{10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond}, 15},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := JitterMs(tc.rtts)
			if diff := got - tc.want; diff > 0.01 || diff < -0.01 {
				t.Errorf("JitterMs = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestICMPProber_BurstSuccess runs a fully-received burst through a fake
// runner: latency is the mean echo RTT, loss is 0, jitter is the pinned
// consecutive-difference value, and the phases carry TTL + resolved IP.
func TestICMPProber_BurstSuccess(t *testing.T) {
	calls := 0
	p := &ICMPProber{BurstCount: 5, BurstIntervalMS: 10, runner: func(target string, count int, interval, timeout time.Duration) (*burstOutcome, error) {
		calls++
		if target != "gw.invalid" {
			t.Errorf("target = %q", target)
		}
		if count != 5 {
			t.Errorf("count = %d, want 5", count)
		}
		if interval != 10*time.Millisecond {
			t.Errorf("interval = %v, want 10ms", interval)
		}
		return &burstOutcome{
			RTTs: []time.Duration{10 * time.Millisecond, 12 * time.Millisecond, 10 * time.Millisecond, 12 * time.Millisecond, 11 * time.Millisecond},
			Sent: 5, Recv: 5, IP: "192.0.2.10", TTL: 54,
		}, nil
	}}

	res, err := p.Probe(context.Background(), "gw.invalid", time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("runner called %d times, want 1", calls)
	}
	if !res.Success {
		t.Fatal("expected success")
	}
	if res.Latency != 11*time.Millisecond {
		t.Errorf("latency = %v, want mean 11ms", res.Latency)
	}
	if res.LossPct != 0 {
		t.Errorf("loss_pct = %v, want 0", res.LossPct)
	}
	// |10-12|=2, |12-10|=2, |10-12|=2, |12-11|=1 → 7/4 = 1.75ms
	if diff := res.JitterMs - 1.75; diff > 0.01 || diff < -0.01 {
		t.Errorf("jitter_ms = %v, want 1.75", res.JitterMs)
	}
	if res.Phases == nil || res.Phases.ReplyTTL != 54 || res.Phases.ResolvedIP != "192.0.2.10" {
		t.Errorf("phases = %+v, want TTL 54 + resolved IP", res.Phases)
	}
}

// TestICMPProber_BurstPartialLoss: 30% loss still reads success (some echoes
// arrived) but the metric is populated for the verdict layer.
func TestICMPProber_BurstPartialLoss(t *testing.T) {
	p := &ICMPProber{BurstCount: 10, runner: func(string, int, time.Duration, time.Duration) (*burstOutcome, error) {
		return &burstOutcome{RTTs: []time.Duration{9 * time.Millisecond, 11 * time.Millisecond}, Sent: 10, Recv: 2}, nil
	}}

	res, _ := p.Probe(context.Background(), "192.0.2.10", time.Second)
	if !res.Success {
		t.Fatal("partial loss still succeeds (some echoes arrived)")
	}
	if diff := res.LossPct - 80; diff > 0.01 || diff < -0.01 {
		t.Errorf("loss_pct = %v, want 80", res.LossPct)
	}
}

// TestICMPProber_BurstTotalLoss: zero replies = fail + 100% loss, the state
// the existing single-ping "no response received" path occupies.
func TestICMPProber_BurstTotalLoss(t *testing.T) {
	p := &ICMPProber{BurstCount: 5, runner: func(string, int, time.Duration, time.Duration) (*burstOutcome, error) {
		return &burstOutcome{Sent: 5, Recv: 0}, nil
	}}

	res, _ := p.Probe(context.Background(), "192.0.2.10", time.Second)
	if res.Success {
		t.Fatal("expected failure with zero replies")
	}
	if res.LossPct != 100 {
		t.Errorf("loss_pct = %v, want 100", res.LossPct)
	}
	if res.JitterMs != 0 {
		t.Errorf("jitter_ms = %v, want 0 (undefined)", res.JitterMs)
	}
}

// TestICMPProber_SinglePingLegacyShape: no burst options = the pre-#744 shape
// — metrics stay zero so old rows and new rows read identically.
func TestICMPProber_SinglePingLegacyShape(t *testing.T) {
	for _, burst := range []int{0, 1} {
		p := &ICMPProber{BurstCount: burst, runner: func(string, int, time.Duration, time.Duration) (*burstOutcome, error) {
			return &burstOutcome{RTTs: []time.Duration{8 * time.Millisecond}, Sent: 1, Recv: 1, IP: "192.0.2.9", TTL: 53}, nil
		}}
		res, err := p.Probe(context.Background(), "192.0.2.9", time.Second)
		if err != nil || !res.Success {
			t.Fatalf("burst=%d: unexpected outcome %v %v", burst, err, res)
		}
		if res.LossPct != 0 || res.JitterMs != 0 {
			t.Errorf("burst=%d: single ping must not populate burst metrics (loss=%v jitter=%v)",
				burst, res.LossPct, res.JitterMs)
		}
		if res.Latency != 8*time.Millisecond {
			t.Errorf("burst=%d: latency = %v, want 8ms", burst, res.Latency)
		}
	}
}

// TestICMPProber_CreateError: target resolution failure surfaces as a fail
// result without metrics — the same per-target repeat cycle as before.
func TestICMPProber_CreateError(t *testing.T) {
	p := &ICMPProber{BurstCount: 5, runner: func(string, int, time.Duration, time.Duration) (*burstOutcome, error) {
		return nil, errors.New("failed to create pinger: lookup bad: no such host")
	}}

	res, err := p.Probe(context.Background(), "bad", time.Second)
	if err != nil {
		t.Fatalf("prober errors route through the result, not the error return: %v", err)
	}
	if res.Success || res.LossPct != 0 || res.ErrorMessage == "" {
		t.Errorf("res = %+v, want fail without metrics and an error message", res)
	}
}

// TestICMPProber_DefaultInterval: unset interval falls back to the 20ms
// prober default; explicit BurstIntervalMS wins.
func TestICMPProber_DefaultInterval(t *testing.T) {
	var got time.Duration
	p := &ICMPProber{BurstCount: 3, runner: func(_ string, _ int, interval, _ time.Duration) (*burstOutcome, error) {
		got = interval
		return &burstOutcome{Sent: 3, Recv: 3}, nil
	}}
	if _, _ = p.Probe(context.Background(), "192.0.2.1", time.Second); got != 20*time.Millisecond {
		t.Errorf("default interval = %v, want 20ms", got)
	}
}
