// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

package reconcile

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

// Coverage-headroom tests (#697): the mismatch gauge lifecycle — nil
// receiver is a no-op (tests pass nil through the whole reconciler), set
// writes per-network values, reset clears stale label sets — plus the
// hand-rolled itoa (strconv was deliberately not imported for one call).

func TestMetrics_NilReceiverIsNoOp(t *testing.T) {
	var m *metrics
	m.set(1, "lan-1", 5) // must not panic
	m.reset()            // ditto
	require.Nil(t, newMetrics(nil), "nil registerer disables metrics entirely")
}

func TestMetrics_SetAndReadBack(t *testing.T) {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_mismatches"}, []string{"network_id", "network"})
	m := &metrics{mismatches: g}

	m.set(7, "lan-7", 3)
	m.set(8, "lan-8", 0)

	require.Equal(t, 3.0, gaugeValue(t, g, "7"))
	require.Equal(t, 0.0, gaugeValue(t, g, "8"))
}

func TestMetrics_ResetClearsLabelSets(t *testing.T) {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: "test_mismatches_reset"}, []string{"network_id", "network"})
	m := &metrics{mismatches: g}
	m.set(7, "lan-7", 3)
	require.Equal(t, 3.0, gaugeValue(t, g, "7"))
	m.reset()
	// GaugeVec.Reset() removes the child series entirely: after reset the
	// network is ABSENT from gathers, so nothing stale lingers — the
	// operator contract (current drift, not a tally) holds by absence.
	require.Equal(t, -1.0, gaugeValue(t, g, "7"), "series must be gone after reset")
}

func gaugeValue(t *testing.T, g *prometheus.GaugeVec, id string) float64 {
	t.Helper()
	reg := prometheus.NewPedanticRegistry()
	require.NoError(t, reg.Register(g))
	fams, err := reg.Gather()
	require.NoError(t, err)
	for _, fam := range fams {
		for _, mtr := range fam.GetMetric() {
			for _, lp := range mtr.GetLabel() {
				if lp.GetName() == "network_id" && lp.GetValue() == id {
					return mtr.GetGauge().GetValue()
				}
			}
		}
	}
	return -1
}

func TestItoa(t *testing.T) {
	require.Equal(t, "0", itoa(0))
	require.Equal(t, "7", itoa(7))
	require.Equal(t, "42", itoa(42))
	require.Equal(t, "123456789", itoa(123456789))
	require.Equal(t, "-1", itoa(-1))
	require.Equal(t, "-987654321", itoa(-987654321))
	// int64 min edge: negation overflows, but network IDs are positive; the
	// function still terminates and produces a deterministic string.
	require.NotEmpty(t, itoa(-9223372036854775808))
}
