// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

// Package listenwatch diffs the local LISTEN table (/proc/net/tcp{,6}) and
// reports newly opened listening sockets as asset-anomaly events (#500).
// This is the eBPF-free half of the security-events scope: it needs no
// privileges and works on any Linux host running the process.

package listenwatch

import (
	"strconv"
	"strings"
)

// Entry is one LISTEN socket: (proto, bind address, port). The bind address
// is the canonical form the kernel prints (hex IPv4/IPv6, e.g. "00000000"
// for 0.0.0.0) — kept verbatim so diffs are exact and no parsing of address
// semantics is needed.
type Entry struct {
	Proto string // "tcp" | "tcp6"
	Addr  string // kernel hex form, verbatim
	Port  int
}

// Key is the dedup/diff identity of an entry.
func (e Entry) Key() string {
	return e.Proto + "/" + e.Addr + ":" + strconv.Itoa(e.Port)
}

// ParseProcNet parses /proc/net/tcp or /proc/net/tcp6 content into the set
// of LISTEN entries. Malformed lines are skipped (the files are kernel-
// generated; defensive parsing only). The proto label distinguishes v4/v6
// files for the caller.
func ParseProcNet(text, proto string) []Entry {
	var out []Entry
	for _, line := range strings.Split(text, "\n") {
		cols := strings.Fields(line)
		if len(cols) < 4 {
			continue
		}
		// Format: sl local_address rem_address st ...; LISTEN is st == 0A.
		local, st := cols[1], cols[3]
		if st != "0A" {
			continue
		}
		addr, portHex, ok := strings.Cut(local, ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		out = append(out, Entry{Proto: proto, Addr: addr, Port: int(port)})
	}
	return out
}

// Diff returns the entries present in cur but absent from prev — the newly
// opened listeners since the last snapshot. Order follows cur.
func Diff(prev, cur []Entry) []Entry {
	if len(cur) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(prev))
	for _, e := range prev {
		seen[e.Key()] = true
	}
	var out []Entry
	for _, e := range cur {
		if !seen[e.Key()] {
			out = append(out, e)
		}
	}
	return out
}
