// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// Package flows turns the passive observer's raw flow-map samples (#500)
// into device-level speaks-with aggregates.
//
// The privacy red line of #500 lives here: Fold is the ONLY transformation
// applied to raw samples, and its output is what may persist — per (device,
// peer) byte totals. Per-port, per-protocol raw flows never leave this
// package's input.

package flows

import (
	"net/netip"
	"sort"

	"mibee-steward/internal/service/scannerv2/ebpf"
)

// Agg is one device↔peer traffic aggregate: bytes_out counts device→peer
// traffic, bytes_in the peer→device direction. One row per (device, peer).
type Agg struct {
	DeviceIP string
	PeerIP   string
	BytesOut uint64
	BytesIn  uint64
}

type aggKey struct{ device, peer string }

// Fold reduces one drained flow batch into per-device aggregates.
//
//   - A sample with both endpoints inside the managed prefixes contributes
//     two half-records: bytes_out on the source device and bytes_in on the
//     destination device (both directions of a LAN↔LAN conversation are
//     observed as separate map keys and merge here).
//   - A sample with exactly one endpoint inside contributes one record on
//     that device; the other endpoint is the (possibly external) peer.
//   - Samples with neither endpoint inside the managed prefixes are dropped
//     (transit traffic the vantage happens to mirror; not our inventory).
//
// Unparsable IPs count as outside. Output is sorted by (device, peer) so
// callers and tests see a deterministic order.
func Fold(samples []ebpf.FlowSample, prefixes []netip.Prefix) []Agg {
	if len(samples) == 0 {
		return nil
	}
	out := make(map[aggKey]*Agg)
	add := func(device, peer string, outB, inB uint64) {
		k := aggKey{device, peer}
		a, ok := out[k]
		if !ok {
			a = &Agg{DeviceIP: device, PeerIP: peer}
			out[k] = a
		}
		a.BytesOut += outB
		a.BytesIn += inB
	}
	for _, s := range samples {
		src, errSrc := netip.ParseAddr(s.SrcIP)
		dst, errDst := netip.ParseAddr(s.DstIP)
		if errSrc != nil || errDst != nil {
			continue
		}
		srcIn := contains(prefixes, src)
		dstIn := contains(prefixes, dst)
		switch {
		case srcIn && dstIn:
			add(s.SrcIP, s.DstIP, s.Bytes, 0)
			add(s.DstIP, s.SrcIP, 0, s.Bytes)
		case srcIn:
			add(s.SrcIP, s.DstIP, s.Bytes, 0)
		case dstIn:
			add(s.DstIP, s.SrcIP, 0, s.Bytes)
		}
	}
	if len(out) == 0 {
		return nil
	}
	aggs := make([]Agg, 0, len(out))
	for _, a := range out {
		aggs = append(aggs, *a)
	}
	sort.Slice(aggs, func(i, j int) bool {
		if aggs[i].DeviceIP != aggs[j].DeviceIP {
			return aggs[i].DeviceIP < aggs[j].DeviceIP
		}
		return aggs[i].PeerIP < aggs[j].PeerIP
	})
	return aggs
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
