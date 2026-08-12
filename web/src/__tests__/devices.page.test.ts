/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/svelte';

// Mock external-behavior modules so the page loads under jsdom. render-only —
// no submit/navigation exercised — so the spies exist only to resolve imports.
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/api/client', () => ({
	api: {
		// The device list fires 3 GETs on mount (devices, stats, networks).
		// Route each to an empty-but-shaped Promise so onMount doesn't throw.
		get: vi.fn((url: string) => {
			if (url.startsWith('/devices/stats')) return Promise.resolve({ by_status: {}, by_type: {} });
			if (url.startsWith('/devices')) return Promise.resolve({ devices: [], total: 0 });
			if (url.startsWith('/networks')) return Promise.resolve([]);
			return Promise.resolve([]);
		}),
		post: vi.fn(() => Promise.resolve({})),
		put: vi.fn(() => Promise.resolve({})),
		del: vi.fn(() => Promise.resolve({}))
	},
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

import Devices from '../routes/devices/+page.svelte';

describe('Devices page', () => {
	it('mounts and renders the page header (title + view controls)', () => {
		const { container } = render(Devices);

		// The page header (h2 title) is always rendered — not gated on the
		// loading state — so it's a stable "the page mounted" signal.
		const h2 = container.querySelector('h2');
		expect(h2).toBeTruthy();
		expect((h2?.textContent ?? '').trim().length).toBeGreaterThan(0);

		// The list/topology view toggle is part of the header chrome.
		expect(container.querySelector('button')).toBeTruthy();
	});
});
