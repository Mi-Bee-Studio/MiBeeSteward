/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * This file is part of MiBeeSteward, distributed under the GNU Affero General
 * Public License v3.0 or later. See LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate. See
 * LICENSE-COMMERCIAL.md.
 */

import { describe, expect, it } from 'vitest';
import { analyzeScanTarget, normalizeCIDR, SYNC_SCAN_LIMIT, TASK_LIMIT } from '$lib/utils/scanTargets';

// The reserved-space cases mirror internal/cidrutil's corpus (#317/#254):
// the form must reject at typing exactly what the backend rejects on submit,
// including endpoint-overlap blocks (126.0.0.0/7 half-loopback).
describe('analyzeScanTarget — reserved space', () => {
	it('rejects the reserved classes on a single IP', () => {
		for (const [ip, cls] of [
			['127.0.0.1', 'loopback'],
			['0.0.0.0', 'unspecified'],
			['169.254.1.1', 'link-local'],
			['224.0.0.1', 'multicast'],
			['239.255.255.254', 'multicast'],
			['255.255.255.255', 'limited broadcast'],
			['240.0.0.1', 'reserved (240.0.0.0/4)']
		] as const) {
			const info = analyzeScanTarget(ip);
			expect(info.error, ip).not.toBeNull();
			expect(info.error, ip).toContain(cls);
		}
	});

	it('rejects reserved CIDRs and endpoint overlaps', () => {
		expect(analyzeScanTarget('127.0.0.0/8').error).toContain('loopback');
		// Upper half of 126.0.0.0/7 is loopback: caught by the LAST endpoint.
		expect(analyzeScanTarget('126.0.0.0/7').error).toContain('overlaps');
		expect(analyzeScanTarget('169.254.0.0/16').error).toContain('link-local');
		// /0 starts at unspecified and ends at broadcast.
		expect(analyzeScanTarget('0.0.0.0/0').error).toContain('unspecified');
		// Private space is the bread and butter: NOT rejected.
		expect(analyzeScanTarget('192.168.1.0/24').error).toBeNull();
		expect(analyzeScanTarget('10.0.0.0/8').error).toBeNull();
	});

	it('rejects reserved ranges and reversed ranges', () => {
		expect(analyzeScanTarget('127.0.0.1-10').error).toContain('loopback');
		expect(analyzeScanTarget('169.254.0.1-5').error).toContain('link-local');
		expect(analyzeScanTarget('192.168.1.10-5').error).toContain('end must not precede');
	});

	it('rejects IPv6 explicitly instead of a generic syntax error', () => {
		for (const v of ['fe80::1', '2001:db8::/32', '192.168.1.0/24, ::1']) {
			expect(analyzeScanTarget(v).error, v).toContain('IPv6');
		}
	});
});

describe('analyzeScanTarget — capacity and limits', () => {
	it('counts addresses per shape', () => {
		expect(analyzeScanTarget('192.168.1.1').addresses).toBe(1);
		expect(analyzeScanTarget('10.0.0.0/24').addresses).toBe(256);
		expect(analyzeScanTarget('192.168.1.1-10').addresses).toBe(10);
		expect(analyzeScanTarget('192.168.1.5,10.0.0.0/24,10.0.1.0/30').addresses).toBe(1 + 256 + 4);
	});

	it('flags the sync (1024) and task (4096) caps exactly at the boundary', () => {
		// /22 = 1024: at the sync cap, not over it.
		const atSync = analyzeScanTarget('10.0.0.0/22');
		expect(atSync.addresses).toBe(SYNC_SCAN_LIMIT);
		expect(atSync.overSyncLimit).toBe(false);
		// /21 = 2048: over sync, fine for a task.
		const overSync = analyzeScanTarget('10.0.0.0/21');
		expect(overSync.overSyncLimit).toBe(true);
		expect(overSync.overTaskLimit).toBe(false);
		// /20 = 4096: at the task cap.
		const atTask = analyzeScanTarget('10.0.0.0/20');
		expect(atTask.addresses).toBe(TASK_LIMIT);
		expect(atTask.overTaskLimit).toBe(false);
		// /19 = 8192: over the task cap.
		expect(analyzeScanTarget('10.0.0.0/19').overTaskLimit).toBe(true);
	});
});

describe('analyzeScanTarget — singleCIDR (executor hint key)', () => {
	it('normalizes host bits and requires exactly one CIDR part', () => {
		expect(analyzeScanTarget('192.168.63.5/24').singleCIDR).toBe('192.168.63.0/24');
		expect(analyzeScanTarget('10.0.0.0/24').singleCIDR).toBe('10.0.0.0/24');
		expect(analyzeScanTarget('192.168.1.1').singleCIDR).toBeNull();
		expect(analyzeScanTarget('10.0.0.0/24,10.0.1.0/24').singleCIDR).toBeNull();
		expect(analyzeScanTarget('10.0.0.0/24,192.168.1.5').singleCIDR).toBeNull();
	});
});

describe('normalizeCIDR', () => {
	it('strips host bits and rejects non-CIDR input', () => {
		expect(normalizeCIDR('192.168.63.5/24')).toBe('192.168.63.0/24');
		expect(normalizeCIDR('10.1.2.3/32')).toBe('10.1.2.3/32');
		expect(normalizeCIDR('10.1.2.3')).toBeNull();
		expect(normalizeCIDR('10.1.2.3/33')).toBeNull();
		expect(normalizeCIDR('999.1.1.1/24')).toBeNull();
	});
});
