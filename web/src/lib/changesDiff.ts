/*
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
*/

/**
 * Change-log diff helpers.
 *
 * `device_changed` entries historically stored `after_data` as a ready-made
 * diff map `{field: [old, new]}`. The backend now stores full before/after
 * DeviceSnapshots (flat `{field: value}`) in `before_data`/`after_data`, so the
 * diff must be computed client-side. Legacy diff-map entries are still handled.
 * Never destructure a snapshot's value directly — a string value destructured
 * as a pair silently truncates to single characters.
 */

// A device_changed diff map: { fieldName: [oldValue, newValue] }.
export type DiffMap = Record<string, [unknown, unknown]>;
// A device snapshot: flat { fieldName: value } (values may be JSON strings).
export type Snapshot = Record<string, unknown>;

export function tryParse(raw?: string | null): unknown {
	if (!raw) return null;
	try {
		return JSON.parse(raw);
	} catch {
		return raw;
	}
}

// Is a parsed after_data a legacy diff map rather than a flat snapshot?
export function isDiffMap(v: unknown): v is DiffMap {
	if (typeof v !== 'object' || v === null || Array.isArray(v)) return false;
	const values = Object.values(v);
	return values.length > 0 && values.every((x) => Array.isArray(x) && x.length === 2);
}

function fmt(v: unknown): string {
	if (v === null || v === undefined) return '-';
	if (typeof v === 'object') {
		try {
			return JSON.stringify(v);
		} catch {
			return String(v);
		}
	}
	return String(v) || '-';
}

// Build the diff map for a device_changed entry: prefer the current backend
// shape (before/after full snapshots), falling back to a legacy stored diff
// map. Only fields whose values actually changed are included.
export function buildDiff(beforeRaw?: string | null, afterRaw?: string | null): DiffMap | null {
	const after = tryParse(afterRaw);
	if (isDiffMap(after)) return after;
	const before = tryParse(beforeRaw);
	if (
		typeof before !== 'object' ||
		typeof after !== 'object' ||
		before === null ||
		after === null
	) {
		return null;
	}
	const result: DiffMap = {};
	const fields = new Set([...Object.keys(before), ...Object.keys(after)]);
	for (const field of fields) {
		const b = (before as Snapshot)[field];
		const a = (after as Snapshot)[field];
		if (fmt(b) !== fmt(a)) result[field] = [b, a];
	}
	return result;
}
