/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/svelte';

// render-only — mock external-behavior modules so the page loads under jsdom.
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/api/client', () => ({
	api: {
		// onMount fetches the SNMP credential list for the dropdown.
		get: vi.fn((url: string) => {
			if (url.startsWith('/snmp-credentials')) return Promise.resolve([]);
			return Promise.resolve([]);
		}),
		post: vi.fn(() => Promise.resolve({ hosts: [] })),
		put: vi.fn(() => Promise.resolve({})),
		del: vi.fn(() => Promise.resolve({}))
	},
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

import Scanner from '../routes/devices/scanner/+page.svelte';

describe('Scanner page', () => {
	it('mounts and renders the scan form (heading + target inputs + scan button)', () => {
		const { container } = render(Scanner);

		// Page header is always rendered.
		const h2 = container.querySelector('h2');
		expect(h2).toBeTruthy();
		expect((h2?.textContent ?? '').trim().length).toBeGreaterThan(0);

		// The scan form has target inputs + a submit button.
		expect(container.querySelectorAll('input').length).toBeGreaterThanOrEqual(1);
		expect(container.querySelector('button')).toBeTruthy();
	});
});
