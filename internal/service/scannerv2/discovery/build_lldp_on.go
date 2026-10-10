// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

//go:build WITH_LLDP

package discovery

// Companion to build_caps.go (#502): flips the introspection bit for a
// WITH_LLDP build. Kept as a separate file so the tag list here stays the
// single source of truth for "which optional capability is compiled in".
func init() { lldpBuilt = true }
