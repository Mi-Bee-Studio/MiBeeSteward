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
// The data source is the IEEE OUI assignment list, an external text file with
// one record per line in either:
//
//	OUI             Vendor
//	BCAD28          Hikvision Digital Technology
//
// or the raw IEEE download format:
//
//	BC-AD-28   (hex)        Hikvision Digital Technology
//	BCAD28     (base 16)    Hikvision Digital Technology
//
// The loader tolerates both. The file path is configurable via the
// MIBEE_SCANNER_OUI_PATH env override or the scanner.oui_path config key.
// When the file is missing or unreadable, Lookup returns "" (silent
// degradation — MAC is still recorded, just no vendor).
package vendor

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

// OUI maps an 8-bit/24-bit OUI prefix to a vendor name. Keys are stored as a
// 6-character uppercase hex string WITHOUT separators ("BCAD28"). The MAC
// input to Lookup is normalized the same way.
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

// Lookup returns the vendor name for a MAC address, or "" if unknown or if no
// OUI table is loaded. The MAC may use any of these separator styles (all
// normalize to the same 6-char hex prefix): bc:ad:28:.., BC-AD-28-.., bcad28...
func (o *OUI) Lookup(mac string) string {
	if o == nil {
		return ""
	}
	prefix := NormalizeMACPrefix(mac)
	if prefix == "" {
		return ""
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.prefixes[prefix]
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
// octets) from a MAC string, stripping any of ":.-" separators. Returns "" if
// the input has fewer than 6 hex digits in its first three octets.
func NormalizeMACPrefix(mac string) string {
	var b strings.Builder
	b.Grow(6)
	for _, r := range mac {
		switch r {
		case ':', '-', '.', ' ':
			continue
		}
		if !isHex(r) {
			// Non-hex (e.g. a typo or a truncated MAC) — bail out.
			return ""
		}
		b.WriteRune(toUpperHex(r))
		if b.Len() == 6 {
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
//	"<6-hex>\t<vendor>"          (MiBee curated / custom format)
//	"<XX-XX-XX> (hex)\t<vendor>" (IEEE standard oui.txt format)
//
// The "(base 16)" duplicate lines from the IEEE file collapse to the same
// prefix as the (hex) line, so either may appear.
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

	// Curated format: "<prefix>\t<vendor>" or "<prefix> <vendor>".
	parts := strings.SplitN(line, "\t", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(line, " ", 2)
	}
	if len(parts) != 2 {
		return "", ""
	}
	prefix = NormalizeMACPrefix(strings.TrimSpace(parts[0]))
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
