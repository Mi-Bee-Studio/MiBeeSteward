/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later; see LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate; see
 * LICENSE-COMMERCIAL.md.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

// render-only + list-render — mock the API surface the probes page touches:
// target list, per-target certificate summaries (badge), and auth store.
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/stores/auth', () => ({
	auth: {
		subscribe: (fn: (v: unknown) => void) => {
			fn({ token: 't', user: { username: 'admin', role: 'admin' } });
			return () => {};
		}
	}
}));
vi.mock('$lib/api/client', () => ({
	api: {
		get: vi.fn((url: string) => {
			if (url.startsWith('/probe-targets') && url.includes('/certificates')) {
				return Promise.resolve({ certificates: [], total: 0 });
			}
			return Promise.resolve({
				targets: [
					{
						id: 1,
						name: 'github-tls',
						module: 'tls',
						target: 'github.com:443',
						interval_seconds: 60,
						timeout_seconds: 10,
						enabled: true,
						notes: '',
						last_run_at: '2026-08-19T00:00:00Z',
						last_status: 'success',
						last_latency_ms: 42.5,
						created_at: '2026-08-19T00:00:00Z',
						updated_at: '2026-08-19T00:00:00Z'
					}
				],
				total: 1
			});
		}),
		post: vi.fn(() => Promise.resolve({})),
		put: vi.fn(() => Promise.resolve({})),
		delete: vi.fn(() => Promise.resolve({}))
	},
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

import Probes from '../routes/probes/+page.svelte';

describe('Probes page', () => {
	it('mounts and renders the target table with the seeded row', async () => {
		const { container } = render(Probes);

		// Header + add button always render.
		const h2 = container.querySelector('h2');
		expect(h2).toBeTruthy();
		expect((h2?.textContent ?? '').trim().length).toBeGreaterThan(0);

		// The seeded target row appears once the list resolves.
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
			expect(container.textContent).toContain('github.com:443');
		});
	});

	it('renders the module badge and last-status badge for the row', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const badges = container.querySelectorAll('.badge');
		const texts = Array.from(badges).map((b) => b.textContent ?? '');
		expect(texts.some((t) => t.includes('tls'))).toBe(true);
		expect(texts.some((t) => t.includes('success'))).toBe(true);
	});
});
