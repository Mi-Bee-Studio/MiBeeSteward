/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { describe, expect, it } from 'vitest';
import { buildDiff, isDiffMap, tryParse } from '$lib/changesDiff';

// The snapshot fixtures below MUST mirror the backend contract: full
// DeviceSnapshot JSON in both before_data and after_data for device_changed
// rows (internal/changedetect DeviceSnapshot — pinned on the Go side by
// TestDeviceSnapshotJSONContract). If that contract changes, both sides'
// tests must be updated in the same PR.

const beforeSnapshot = JSON.stringify({
	name: 'redmi-notebook',
	type: 'pc',
	brand: '-',
	model: '-',
	mac_address: 'bc:22:28:3f:eb:ca',
	ip_address: '192.168.62.101',
	status: 'online',
	open_ports: '[]',
	detected_services: '[]',
	prometheus_url: '',
	node_exporter_url: '',
	scan_attributes: '{"hostname":"redmi-notebook","inferred_type":"pc"}'
});

const afterSnapshot = JSON.stringify({
	name: 'redmi-notebook',
	type: 'camera',
	brand: '-',
	model: '-',
	mac_address: 'bc:22:28:3f:eb:ca',
	ip_address: '192.168.62.41',
	status: 'online',
	open_ports: '[]',
	detected_services: '[]',
	prometheus_url: '',
	node_exporter_url: '',
	scan_attributes: '{"hostname":"mibee-rec","inferred_type":"camera"}'
});

describe('buildDiff — snapshot payloads (current backend shape)', () => {
	it('returns only changed fields with full before/after values', () => {
		const diff = buildDiff(beforeSnapshot, afterSnapshot);
		expect(diff).not.toBeNull();
		expect(Object.keys(diff!).sort()).toEqual(['ip_address', 'scan_attributes', 'type']);
		expect(diff!.ip_address).toEqual(['192.168.62.101', '192.168.62.41']);
		expect(diff!.type).toEqual(['pc', 'camera']);
	});

	it('never truncates values to single characters (the #328-era regression)', () => {
		// The bug: a snapshot's string value destructured as [old, new] yields
		// single characters ('r'/'o' for "router"). Values must stay whole.
		const diff = buildDiff(beforeSnapshot, afterSnapshot);
		expect(diff!.type[0]).toBe('pc');
		expect(diff!.type[1]).toBe('camera');
		expect(diff!.type[0]).toHaveLength(2);
	});

	it('treats empty-string and dash-equivalent values as changed when they differ', () => {
		const diff = buildDiff('{"prometheus_url":"","name":"x"}', '{"prometheus_url":"http://a/metrics","name":"x"}');
		expect(diff!.prometheus_url).toEqual(['', 'http://a/metrics']);
	});

	it('returns an empty diff for identical snapshots', () => {
		expect(buildDiff(beforeSnapshot, beforeSnapshot)).toEqual({});
	});

	it('includes fields present in only one side (added or removed)', () => {
		const diff = buildDiff('{"name":"x","brand":"B"}', '{"name":"x"}');
		expect(Object.keys(diff!)).toEqual(['brand']);
		expect(diff!.brand).toEqual(['B', undefined]);
	});
});

describe('buildDiff — legacy diff-map payloads', () => {
	it('passes through a stored {field: [old, new]} map untouched', () => {
		const legacy = JSON.stringify({ name: ['old', 'new'], type: ['pc', 'camera'] });
		expect(buildDiff(null, legacy)).toEqual({
			name: ['old', 'new'],
			type: ['pc', 'camera']
		});
	});
});

describe('isDiffMap', () => {
	it('accepts a map of two-element arrays', () => {
		expect(isDiffMap({ a: [1, 2], b: ['x', 'y'] })).toBe(true);
	});

	it('rejects snapshots (string values) — the incident shape', () => {
		expect(isDiffMap(JSON.parse(afterSnapshot))).toBe(false);
	});

	it('rejects null, arrays, and empty objects', () => {
		expect(isDiffMap(null)).toBe(false);
		expect(isDiffMap([['a', 1]])).toBe(false);
		expect(isDiffMap({})).toBe(false);
	});
});

describe('tryParse', () => {
	it('parses JSON, passes through raw strings, nulls out empties', () => {
		expect(tryParse('{"a":1}')).toEqual({ a: 1 });
		expect(tryParse('not json')).toBe('not json');
		expect(tryParse(undefined)).toBeNull();
	});
});
