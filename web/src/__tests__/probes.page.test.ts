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
import { render, waitFor, fireEvent } from '@testing-library/svelte';

// render-only + list-render + interaction: mock the API surface the probes
// page touches: target list, per-target certificate summaries (badge),
// per-target results history, networks (vantage selector's agent options),
// and the auth store. Assertions are data-driven (names / vantage tokens),
// never localized strings (except where an interaction must FIND a button;
// the suite runs under the en locale).
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
// echarts cannot paint under jsdom (canvas getContext returns null → zrender
// crashes in $effect); the history modal mounts Chart on its default tab.
vi.mock('$lib/charts/echarts', () => ({
	echarts: {
		init: vi.fn(() => ({ setOption: vi.fn(), dispose: vi.fn(), resize: vi.fn() }))
	}
}));
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
			if (url.startsWith('/networks')) {
				// #274 envelope: {networks, total} (was a bare array).
				return Promise.resolve({
					networks: [{ id: 1, name: 'lan-62', cidr: '192.168.62.0/24', agent_id: 'edge-1' }],
					total: 1
				});
			}
			if (url.startsWith('/probe-targets') && url.includes('/certificates')) {
				return Promise.resolve({ certificates: [], total: 0 });
			}
			if (url.startsWith('/probe-targets') && url.includes('/results')) {
				// Newest-first, two vantage tracks that DISAGREE (center succeeds,
				// agent fails): the case the multi-vantage summary exists for.
				return Promise.resolve({
					results: [
						resultRow(11, 'center', 'success', 42),
						resultRow(12, 'agent:edge-1', 'fail', 0),
						resultRow(13, 'center', 'success', 45),
						resultRow(14, 'agent:edge-1', 'fail', 0)
					],
					total: 4
				});
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
						vantage: 'all',
						vantage_latest: [
							{ vantage: 'center', status: 'success', latency_ms: 42.5, checked_at: '2026-09-17T00:00:02Z' },
							{
								vantage: 'agent:edge-1',
								status: 'fail',
								latency_ms: 0,
								error_message: 'connection refused',
								checked_at: '2026-09-17T00:00:01Z'
							}
						],
						created_at: '2026-08-19T00:00:00Z',
						updated_at: '2026-08-19T00:00:00Z'
					},
					{
						id: 2,
						name: 'intranet-gw',
						module: 'http',
						target: 'http://10.0.0.1/healthz',
						interval_seconds: 120,
						timeout_seconds: 10,
						enabled: true,
						notes: '',
						vantage: 'agent:edge-1',
						// Agent-only plan: last_* stays empty, the agent track is
						// the only signal (the case vantage_latest exists for).
						vantage_latest: [
							{ vantage: 'agent:edge-1', status: 'success', latency_ms: 88, checked_at: '2026-09-17T00:00:00Z' }
						],
						created_at: '2026-08-19T00:00:00Z',
						updated_at: '2026-08-19T00:00:00Z'
					}
				],
				total: 2
			});
		}),
		post: vi.fn(() => Promise.resolve({})),
		put: vi.fn(() => Promise.resolve({})),
		delete: vi.fn(() => Promise.resolve({}))
	},
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

function resultRow(id: number, vantage: string, status: string, latencyMs: number) {
	return {
		id,
		target_id: 1,
		status,
		latency_ms: latencyMs,
		status_code: status === 'success' ? 200 : 0,
		error_message: status === 'success' ? '' : 'connection refused',
		tls_version: '',
		cert_not_after: '',
		cert_trusted: null,
		checked_at: '2026-09-17T00:00:00Z',
		vantage
	};
}

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

	it('renders the module badge and per-vantage status lines (agent track visible)', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const badges = container.querySelectorAll('.badge');
		const texts = Array.from(badges).map((b) => b.textContent ?? '');
		expect(texts.some((t) => t.includes('tls'))).toBe(true);

		// Multi-vantage row: one line per track, status as a colored dot plus
		// the vantage label and latency. The failing agent track is right
		// there next to the succeeding center track (disagreement wrap).
		const dots = container.querySelectorAll('[class*="rounded-full"][class*="bg-"]');
		expect(dots.length).toBeGreaterThanOrEqual(3);
		expect(container.querySelector('[class*="bg-warning/5"]')).toBeTruthy();
		expect(container.textContent).toContain('agent:edge-1');
		expect(container.textContent).toContain('43ms');

		// Agent-only row with an agent track: its latency shows even though
		// last_* is empty (previously rendered as "Not probed yet").
		expect(container.textContent).toContain('88ms');
		expect(container.textContent).not.toContain('Not probed yet');
	});

	it('renders vantage badges: "all" as a badge, agent plans verbatim, center quiet', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('intranet-gw');
		});

		const badges = Array.from(container.querySelectorAll('.badge')).map((b) => b.textContent ?? '');
		expect(badges.some((t) => t.trim() === 'all')).toBe(true);
		expect(badges.some((t) => t.trim() === 'agent:edge-1')).toBe(true);
		// The default (center) renders as plain muted text, not a badge.
		expect(badges.some((t) => t.trim() === 'center')).toBe(false);
	});

	it('history modal shows the per-vantage summary with disagreement highlighted', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		// Open the first row's History modal (en-locale button text).
		const historyBtn = Array.from(container.querySelectorAll('button')).find((b) =>
			(b.textContent ?? '').trim() === 'History'
		) as HTMLElement;
		expect(historyBtn).toBeTruthy();
		await fireEvent.click(historyBtn);

		// The summary panel: heading + both vantage chips + sample counts.
		await waitFor(() => {
			expect(container.textContent).toContain('Latest per vantage');
		});
		expect(container.textContent).toContain('agent:edge-1');
		expect(container.textContent).toContain('2 samples');
		// Tracks disagree (center success / agent fail) → the diff badge shows.
		expect(container.textContent).toContain('results disagree');
	});

	it('history modal defaults to the chart view and toggles to the detail table', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const historyBtn = Array.from(container.querySelectorAll('button')).find((b) =>
			(b.textContent ?? '').trim() === 'History'
		) as HTMLElement;
		await fireEvent.click(historyBtn);
		await waitFor(() => {
			expect(container.textContent).toContain('Latest per vantage');
		});

		// Chart tab is the default: latency chart + per-vantage status timeline
		// (one strip of colored cells per track, with a success percentage).
		expect(container.textContent).toContain('Latency by vantage');
		expect(container.textContent).toContain('Status timeline');
		const strips = container.querySelectorAll('[role="img"]');
		expect(strips.length).toBe(2);
		// center 2/2 success, agent 0/2: the percentages render per strip.
		expect(container.textContent).toContain('100%');
		expect(container.textContent).toContain('0%');

		// The raw table is one tab away; switching shows the vantage column.
		const detailBtn = Array.from(container.querySelectorAll('button')).find((b) =>
			(b.textContent ?? '').trim() === 'Detail'
		) as HTMLElement;
		expect(detailBtn).toBeTruthy();
		await fireEvent.click(detailBtn);
		await waitFor(() => {
			expect(container.querySelector('table')).toBeTruthy();
		});
		expect(container.textContent).not.toContain('Status timeline');
	});

	it('create form offers the vantage selector with registered agents', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const addBtn = Array.from(container.querySelectorAll('button')).find((b) =>
			(b.textContent ?? '').includes('Add Target')
		) as HTMLElement;
		expect(addBtn).toBeTruthy();
		await fireEvent.click(addBtn);

		const select = container.querySelector('#probe-vantage') as HTMLSelectElement;
		expect(select).toBeTruthy();
		const values = Array.from(select.querySelectorAll('option')).map((o) => o.getAttribute('value'));
		expect(values).toContain('center');
		expect(values).toContain('all');
		expect(values).toContain('agent:edge-1');
	});
});
