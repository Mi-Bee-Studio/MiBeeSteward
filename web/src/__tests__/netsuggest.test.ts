/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. See LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate. See
 * LICENSE-COMMERCIAL.md.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { bestLocalNetwork } from '$lib/utils/netSuggest';
import type { NetworkSuggestReport } from '$lib/utils/netSuggest';

const apiGet = vi.fn();

vi.mock('$lib/api/client', () => ({
	api: { get: (...args: unknown[]) => apiGet(...args) }
}));

function report(over: Partial<NetworkSuggestReport>): NetworkSuggestReport {
	return {
		interfaces: [
			{ name: 'docker0', ipv4: '172.17.0.1', prefix_len: 16, cidr: '172.17.0.0/16', kind: 'virtual', primary: false, addresses: 65536, suggested_cidr: '172.17.0.0/24' },
			{ name: 'eth0', ipv4: '192.168.1.10', prefix_len: 24, cidr: '192.168.1.0/24', kind: 'lan', primary: true, addresses: 256, suggested_cidr: '192.168.1.0/24' }
		],
		container: false,
		...over
	};
}

beforeEach(() => apiGet.mockReset());

describe('bestLocalNetwork', () => {
	it('prefers the default-route interface over the first listed', async () => {
		apiGet.mockResolvedValue(report({}));
		await expect(bestLocalNetwork()).resolves.toBe('192.168.1.0/24');
		expect(apiGet).toHaveBeenCalledWith('/system/network-interfaces');
	});

	it('falls back to the first lan interface when none is primary', async () => {
		const rep = report({});
		rep.interfaces = rep.interfaces.map((n) => ({ ...n, primary: false }));
		apiGet.mockResolvedValue(rep);
		await expect(bestLocalNetwork()).resolves.toBe('192.168.1.0/24');
	});

	it('returns empty on the no_lan warning', async () => {
		apiGet.mockResolvedValue(report({ warning: 'no_lan', interfaces: [] }));
		await expect(bestLocalNetwork()).resolves.toBe('');
	});
});
