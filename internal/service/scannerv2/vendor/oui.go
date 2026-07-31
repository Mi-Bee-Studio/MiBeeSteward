// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

// Package vendor provides MAC-address → manufacturer (OUI) lookup.
//
// The data source is the IEEE assignment list(s): MA-L (/24, 6 hex), MA-M
// (/28, 7 hex), and MA-S (/36, 9 hex, formerly IAB). One record per line in
// either:
//
//	<prefix>        Vendor
//	BCAD28          Hikvision Digital Technology       (MA-L, 6 hex)
//	8C1F64B14       Murata Manufacturing               (MA-S, 9 hex)
//
// or the raw IEEE download format (MA-L only — the .txt form does not carry
// MA-S/MA-M):
//
//	BC-AD-28   (hex)        Hikvision Digital Technology
//	BCAD28     (base 16)    Hikvision Digital Technology
//
// The loader tolerates both and indexes prefixes of any of the three lengths.
// Lookup does longest-prefix match: a MAC whose top 9 hex match an MA-S block
// resolves to that block's owner (e.g. 8C1F64B14 → Murata), NOT the parent
// /24 owner (8C1F64 → "IEEE Registration Authority"). This is mandatory because
// MA-S/MA-M sub-blocks are carved out of /24 OUIs owned by IEEE or another
// vendor. The file path is configurable via the MIBEE_SCANNER_OUI_PATH env
// override or the scanner.oui_path config key; when the path is empty, the
// engine seeds from the embedded curated table (see oui_curated.txt). When the
// file is missing or unreadable, Lookup returns "" (silent degradation — MAC
// is still recorded, just no vendor).
package vendor

import (
	"bufio"
	_ "embed"
	"os"
	"strings"
	"sync"
)

// embeddedCurated is the hand-maintained CC-BY-SA 4.0 vendor table shipped
// inside the binary for out-of-box coverage of common vendors. Authored by
// MiBee Studio from public knowledge of well-known OUIs (NOT a reproduction of
// the IEEE registry — see oui_curated.txt header). The full IEEE set is an
// optional runtime download via scripts/fetch-oui.sh.
//
//go:embed oui_curated.txt
var embeddedCurated string

// OUI maps an IEEE assignment prefix to a vendor name. Keys are stored as an
// uppercase hex string WITHOUT separators, at one of three lengths: 6 hex
// (MA-L /24), 7 hex (MA-M /28), or 9 hex (MA-S /36, formerly IAB). Lookup
// resolves a MAC by trying its prefixes longest-first (9 → 7 → 6) so MA-S/MA-M
// sub-blocks win over their parent /24 OUI (see package doc).
type OUI struct {
	mu       sync.RWMutex
	prefixes map[string]string
	loaded   bool
	path     string
}

// New returns an empty OUI table. Call Load to populate from a file. A nil/zero
// value OUI is safe to use (Lookup returns "").
func New() *OUI { return &OUI{prefixes: map[string]string{}} }

// Load reads an OUI file at path. Safe to call multiple times; later loads
// replace earlier data. Returns nil and sets loaded=false on missing file
// (silent degradation); returns an error only on a real read failure.
func (o *OUI) Load(path string) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.path = path
	o.loaded = false
	o.prefixes = map[string]string{}

	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Missing file is the documented degradation path — not an error.
			return nil
		}
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		prefix, vendor := parseOUILine(line)
		if prefix != "" && vendor != "" {
			o.prefixes[prefix] = vendor
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	o.loaded = true
	return nil
}

// LoadEmbeddedCurated seeds the table from the //go:embed oui_curated.txt
// asset — a small hand-maintained CC-BY-SA set of common vendor OUIs. Used by
// the engine as the out-of-box default when scanner.oui_path is empty, so a
// fresh install gets vendor inference for common devices without downloading
// the full IEEE registry. A subsequent Load(path) (user-configured full IEEE
// file) replaces this seed with the larger table.
func (o *OUI) LoadEmbeddedCurated() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	o.path = "(embedded curated)"
	o.prefixes = map[string]string{}
	o.loaded = false
	for _, line := range strings.Split(embeddedCurated, "\n") {
		prefix, vendor := parseOUILine(line)
		if prefix != "" && vendor != "" {
			o.prefixes[prefix] = vendor
		}
	}
	if len(o.prefixes) > 0 {
		o.loaded = true
	}
}

// Loaded reports whether a non-empty OUI table is in memory. False means
// Lookup will always return "" (callers may skip the MAC→vendor step).
func (o *OUI) Loaded() bool {
	if o == nil {
		return false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.loaded
}

// Lookup returns the vendor name for a MAC address via longest-prefix-match
// across the loaded MA-S (/36, 9 hex) → MA-M (/28, 7 hex) → MA-L (/24, 6 hex)
// registries, or "" if no prefix matches or no table is loaded. The MAC may use
// any of ":.- " separator styles (all normalize to uppercase hex). Use
// LookupFull to also get the matched prefix (for the oui_prefix field).
func (o *OUI) Lookup(mac string) string {
	vendor, _ := o.LookupFull(mac)
	return vendor
}

// LookupFull returns the vendor name AND the matched IEEE assignment prefix
// (6/7/9 uppercase hex, e.g. "8C1F64B14") for a MAC address, via longest-prefix
// match. Returns ("", "") if no prefix matches or no table is loaded. The
// matched prefix is useful to record which block (MA-L/MA-M/MA-S) the vendor
// was inferred from.
func (o *OUI) LookupFull(mac string) (vendor, prefix string) {
	if o == nil {
		return "", ""
	}
	// Extract up to 9 leading hex chars (covers the deepest registry, MA-S /36).
	// A canonical MAC has 12 hex chars; we only need the first 9 for matching.
	hex := normalizeHexPrefix(mac, 9)
	if len(hex) < 6 {
		return "", ""
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	// Longest-prefix match: try 9 → 7 → 6. A MAC starting 8C1F64B14.. must hit
	// the MA-S row "8C1F64B14" (Murata), not the MA-L row "8C1F64" (IEEE
	// Registration Authority) — see package doc.
	for _, n := range []int{9, 7, 6} {
		if len(hex) < n {
			continue
		}
		if v, ok := o.prefixes[hex[:n]]; ok {
			return v, hex[:n]
		}
	}
	return "", ""
}

// Size returns the number of OUI prefixes loaded.
func (o *OUI) Size() int {
	if o == nil {
		return 0
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.prefixes)
}

// NormalizeMACPrefix extracts the 6-character uppercase OUI prefix (first 3
// octets, the MA-L /24 block) from a MAC string, stripping any of ":.-"
// separators. Returns "" if the input has fewer than 6 hex digits in its first
// three octets. Kept for backward compatibility; internal lookup uses
// normalizeHexPrefix to also accept 7/9-hex (MA-M/MA-S) prefixes.
func NormalizeMACPrefix(mac string) string {
	return normalizeHexPrefix(mac, 6)
}

// normalizeHexPrefix extracts up to maxN leading uppercase hex digits from s,
// skipping ":.- " separators. Returns "" if the result would be fewer than 6
// hex digits (the minimum valid OUI/MA-L block) OR if a non-hex rune is
// encountered before reaching the cap. maxN is typically 6 (MA-L), 7 (MA-M),
// or 9 (MA-S). When the input has more than maxN hex digits, only the first
// maxN are kept.
func normalizeHexPrefix(s string, maxN int) string {
	var b strings.Builder
	b.Grow(maxN)
	for _, r := range s {
		switch r {
		case ':', '-', '.', ' ':
			continue
		}
		if !isHex(r) {
			// Non-hex (e.g. a typo or a truncated MAC) — bail out.
			return ""
		}
		b.WriteRune(toUpperHex(r))
		if b.Len() == maxN {
			break
		}
	}
	if b.Len() < 6 {
		return ""
	}
	return b.String()
}

// parseOUILine extracts (prefix, vendor) from one line of an OUI file. Two
// formats are accepted:
//
//	"<6|7|9-hex>\t<vendor>"      (MiBee curated / fetch-oui.sh merged format;
//	                              6=MA-L, 7=MA-M, 9=MA-S — full length preserved)
//	"<XX-XX-XX> (hex)\t<vendor>" (IEEE standard oui.txt format — MA-L only, as
//	                              the .txt form does not carry MA-S/MA-M)
//
// The "(base 16)" duplicate lines from the IEEE file collapse to the same
// prefix as the (hex) line, so either may appear. MA-S/MA-M data comes from
// IEEE's CSV registries and is converted into the curated "<hex>\t<vendor>"
// form by scripts/fetch-oui.sh before this loader sees it.
func parseOUILine(line string) (prefix, vendor string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
		return "", ""
	}
	// IEEE format: the interesting part is the first whitespace-delimited token
	// if it parses as a MAC prefix, then the vendor is everything after the
	// "(hex)" / "(base 16)" tag.
	if strings.Contains(line, "(hex)") || strings.Contains(line, "(base 16)") {
		// Find the closing paren of the tag, vendor is everything after the
		// next tab/space run.
		idx := strings.Index(line, ")")
		if idx < 0 {
			return "", ""
		}
		head := line[:idx]
		// Strip the " (hex" / " (base 16" suffix.
		head = strings.TrimSuffix(head, " (hex")
		head = strings.TrimSuffix(head, " (base 16")
		prefix = NormalizeMACPrefix(strings.TrimSpace(head))
		vendor = strings.TrimSpace(line[idx+1:])
		return prefix, vendor
	}

	// Curated format: "<prefix>\t<vendor>" or "<prefix> <vendor>". The prefix
	// may be 6 (MA-L), 7 (MA-M), or 9 (MA-S) hex; normalizeHexPrefix(…, 9)
	// preserves the full length so MA-S/MA-M sub-blocks index distinctly from
	// their parent /24 OUI.
	parts := strings.SplitN(line, "\t", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(line, " ", 2)
	}
	if len(parts) != 2 {
		return "", ""
	}
	prefix = normalizeHexPrefix(strings.TrimSpace(parts[0]), 9)
	vendor = strings.TrimSpace(parts[1])
	return prefix, vendor
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}

func toUpperHex(r rune) rune {
	if r >= 'a' && r <= 'f' {
		return r - ('a' - 'A')
	}
	return r
}
