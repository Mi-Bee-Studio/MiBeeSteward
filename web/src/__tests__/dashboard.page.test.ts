/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

// Mock external-behavior modules so the page loads under jsdom. Chart.svelte
// guards echarts.init in try/catch, so the default cards render fine without
// a canvas.
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
// echarts cannot paint under jsdom (canvas getContext returns null → zrender
// crashes in $effect after the test finishes). The default cards mount Chart
// unconditionally, so stub the echarts barrel the Chart wrapper imports.
vi.mock('$lib/charts/echarts', () => ({
	echarts: {
		init: vi.fn(() => ({ setOption: vi.fn(), dispose: vi.fn(), resize: vi.fn() }))
	}
}));
vi.mock('$lib/api/client', () => ({
	api: {
		// The dashboard fires, on mount: configs, overview, stats, devices —
		// plus one fetch per builtin widget (here: /changes for the
		// recent-changes preset). Route each to a shaped Promise.
		get: vi.fn((url: string) => {
			if (url.startsWith('/dashboard/configs')) {
				return Promise.resolve({
					configs: [
						{
							id: '7',
							name: 'Recent Changes',
							type: 'list',
							data_source: 'builtin',
							query: 'builtin:recent_changes',
							refresh_interval: 30,
							position: 1,
							created_at: '2026-09-14T00:00:00Z',
							updated_at: '2026-09-14T00:00:00Z'
						}
					],
					total: 1
				});
			}
			if (url.startsWith('/dashboard/overview')) {
				return Promise.resolve({
					devices: {
						total: 2, online: 1, offline: 1, unknown: 0, online_rate: 0.5,
						by_type: { pc: 2 },
						by_location: {}
					},
					scanning: {
						tasks_total: 0, runs_total: 0, recent_runs: [], runs_by_status: {},
						last_discovery: undefined
					},
					abnormal: [
						{ id: 34, name: 'nanopineo', ip_address: '192.168.62.169', type: 'embedded', status: 'offline' }
					],
					generated: '2026-09-14T00:00:00Z'
				});
			}
			if (url.startsWith('/devices/stats')) {
				return Promise.resolve({ by_status: { online: 1, offline: 1, unknown: 0 } });
			}
			if (url.startsWith('/devices')) {
				return Promise.resolve({ devices: [], total: 0 });
			}
			if (url.startsWith('/changes')) {
				return Promise.resolve({
					changes: [
						{
							id: 1, change_type: 'device_added', entity_type: 'device',
							after_data: '{"name":"newcam","ip_address":"192.168.62.212"}',
							detected_at: '2026-09-13T18:00:01Z'
						},
						{
							id: 2, change_type: 'device_lost', entity_type: 'device',
							before_data: '{"name":"nanopineo","ip_address":"192.168.62.169"}',
							detected_at: '2026-09-13T17:00:01Z'
						}
					],
					total: 2
				});
			}
			if (url.startsWith('/probe-targets')) {
				return Promise.resolve({ targets: [], total: 0 });
			}
			return Promise.resolve({});
		}),
		post: vi.fn(() => Promise.resolve({})),
		put: vi.fn(() => Promise.resolve({})),
		delete: vi.fn(() => Promise.resolve({})),
		del: vi.fn(() => Promise.resolve({}))
	},
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

import Dashboard from '../routes/dashboard/+page.svelte';

describe('Dashboard page', () => {
	it('mounts and renders the header with the help button', () => {
		const { container } = render(Dashboard);

		const h2 = container.querySelector('h2');
		expect(h2).toBeTruthy();
		expect((h2?.textContent ?? '').trim().length).toBeGreaterThan(0);

		// The "?" guide button is available to every user (not admin-gated).
		const help = container.querySelector('button[aria-label]');
		expect(help).toBeTruthy();
	});

	it('renders builtin list widgets BELOW the default cards (append mode)', async () => {
		const { container } = render(Dashboard);

		// The custom widget (recent-changes preset) settles after its /changes
		// fetch resolves — its card must appear…
		await waitFor(() => {
			expect(container.querySelector('.widget-card')).toBeTruthy();
		});

		// …and each change row renders with its status chip + device link.
		const rows = container.querySelectorAll('.widget-list-row');
		expect(rows.length).toBe(2);
		const addedLink = container.querySelector('a.row-link[href="/devices?search=192.168.62.212"]');
		expect(addedLink).toBeTruthy();
		expect(container.querySelector('.row-status.status-added')).toBeTruthy();
		expect(container.querySelector('.row-status.status-lost')).toBeTruthy();

		// …but the DEFAULT grid must still render above it — adding a widget
		// no longer hides the overview cards (the old replace-mode trap).
		expect(container.querySelector('.custom-widgets-section')).toBeTruthy();
		// The page-level skeleton (whose placeholder grid shares the default
		// grid's classes) must be gone before we can assert on the real grid.
		await waitFor(() => {
			expect(container.querySelector('.skeleton-rect')).toBeNull();
		});
		const defaultGrid = container.querySelector('.grid.grid-cols-1');
		expect(defaultGrid).toBeTruthy();
		// Every default card carries a plain-language subtitle now.
		expect(
			defaultGrid?.querySelectorAll(':scope > div p.text-xs.text-muted').length ?? 0
		).toBeGreaterThanOrEqual(6);
	});
});
