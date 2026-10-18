/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * This file is part of Mi Bee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later; see LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate; see
 * LICENSE-COMMERCIAL.md.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';

// render-only + list-render + interaction: mock the API surface the probes
// page touches: target list, per-target certificate summaries (badge),
// per-target results history, networks (vantage selector's agent options),
// the per-category quality report (#608/#613), and the auth store.
// Assertions are data-driven (names / vantage tokens), never localized
// strings (except where an interaction must FIND a button or assert a
// localized label; the suite runs under the en locale).
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));

// Mutable target seed: individual tests swap the array (empty a category,
// search scenarios) and restore it in finally. vi.hoisted so the api mock
// factory below can close over it — factories run while the module graph
// loads, before any test-body statement executes.
const mockState = vi.hoisted(() => {
	const rows: Record<string, unknown>[] = [
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
		},
		{
			id: 3,
			name: 'sys-egress-http',
			module: 'http',
			target: 'http://203.0.113.9/',
			interval_seconds: 60,
			timeout_seconds: 10,
			enabled: true,
			notes: '',
			vantage: 'all',
			source: 'system',
			last_status: 'success',
			last_latency_ms: 30.4,
			vantage_latest: [
				{ vantage: 'center', status: 'success', latency_ms: 30.4, checked_at: '2026-09-17T00:00:03Z' },
				{ vantage: 'agent:edge-1', status: 'success', latency_ms: 45, checked_at: '2026-09-17T00:00:03Z' }
			],
			created_at: '2026-08-19T00:00:00Z',
			updated_at: '2026-08-19T00:00:00Z'
		},
		{
			id: 4,
			name: 'auto-nas-web',
			module: 'tcp',
			target: '192.168.2.168:5000',
			interval_seconds: 120,
			timeout_seconds: 10,
			enabled: true,
			notes: '',
			vantage: 'center',
			source: 'auto',
			device_id: 11,
			last_status: 'success',
			last_latency_ms: 3.2,
			vantage_latest: [
				{ vantage: 'center', status: 'success', latency_ms: 3.2, checked_at: '2026-09-17T00:00:04Z' }
			],
			created_at: '2026-08-19T00:00:00Z',
			updated_at: '2026-08-19T00:00:00Z'
		},
		// Manual target bound to a device (#613): covers the device_id>0
		// branch of the lan category (auto source is the other branch).
		{
			id: 5,
			name: 'nas-ssh',
			module: 'tcp',
			target: '192.0.2.168:22',
			interval_seconds: 120,
			timeout_seconds: 10,
			enabled: true,
			notes: '',
			vantage: 'center',
			device_id: 12,
			last_status: 'success',
			last_latency_ms: 1.8,
			vantage_latest: [
				{ vantage: 'center', status: 'success', latency_ms: 1.8, checked_at: '2026-09-17T00:00:05Z' }
			],
			created_at: '2026-08-19T00:00:00Z',
			updated_at: '2026-08-19T00:00:00Z'
		}
	];
	return { targets: rows };
});

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
					networks: [{ id: 1, name: 'lan-62', cidr: '192.168.2.0/24', agent_id: 'edge-1' }],
					total: 1
				});
			}
			if (url.startsWith('/probe-quality')) {
				// #613 per-category quality report: lan/external render as
				// compact window-health matrices; the quality category nests
				// the #608 config groups (primary with three vantage verdicts
				// + one reference group) verbatim.
				return Promise.resolve({
					window_minutes: 15,
					categories: [
						{
							category: 'lan',
							vantages: [
								{ vantage: 'agent:edge-1', network_name: 'LAN A', verdict: 'ok', score: 97, reasons: [] }
							],
							targets: [
								{
									name: 'nas-web',
									module: 'http',
									target: 'http://192.0.2.168:5000/',
									cross_vantage: 'ok',
									per_vantage: {
										'agent:edge-1': { ok_rate: 1, p50_ms: 3.2, samples: 10, last_status: 'success' }
									}
								}
							]
						},
						{
							category: 'external',
							vantages: [
								{ vantage: 'center', network_name: 'Main LAN', verdict: 'degraded', score: 70, reasons: ['ok_rate_low'] }
							],
							targets: [
								{
									name: 'ext-http',
									module: 'http',
									target: 'http://203.0.113.99/',
									cross_vantage: 'ok',
									per_vantage: {
										center: { ok_rate: 0.8, p50_ms: 120.4, samples: 10, last_status: 'success' }
									}
								}
							]
						},
						{
							category: 'quality',
							vantages: [],
							targets: [],
							groups: [
								{
									name: 'egress',
									role: 'primary',
									vantages: [
										{ vantage: 'center', network_name: 'Main LAN', verdict: 'ok', score: 98, reasons: [] },
										{ vantage: 'agent:edge-1', verdict: 'dns_fault', score: 41, reasons: ['dns_fault.direct_ok_name_resolution_dead', 'ok_rate_low'] },
										{ vantage: 'agent:edge-2', verdict: 'upstream_resolver', score: 55, reasons: ['upstream_resolver.failing:pub-dns'] }
									],
									targets: [
										{
											name: 'pub-http',
											module: 'http',
											target: 'http://203.0.113.9/',
											cross_vantage: 'ok',
											per_vantage: {
												center: { ok_rate: 1, p50_ms: 30.4, samples: 12, last_status: 'success' },
												'agent:edge-1': { ok_rate: 0.25, p50_ms: 88.2, samples: 8, last_status: 'fail' }
											}
										},
										{
											name: 'pub-dns',
											module: 'dns',
											target: 'www.example.com',
											cross_vantage: 'mixed',
											per_vantage: {
												center: { ok_rate: 1, p50_ms: 12, samples: 10, last_status: 'success' }
											}
										}
									]
								},
								{
									name: 'reference-alt',
									role: 'reference',
									vantages: [{ vantage: 'center', verdict: 'insufficient', score: 0, reasons: ['insufficient_data'] }],
									targets: []
								}
							]
						}
					]
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
				targets: mockState.targets,
				total: mockState.targets.length
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
import { api } from '$lib/api/client';
import { probeCategory } from '$lib/utils/probes';

describe('probeCategory helper (#613)', () => {
	it('derives the category from source and device binding', () => {
		expect(probeCategory({ source: 'system' })).toBe('quality');
		expect(probeCategory({ source: 'auto' })).toBe('lan');
		expect(probeCategory({ source: 'manual', device_id: 11 })).toBe('lan');
		expect(probeCategory({ source: 'manual' })).toBe('external');
		expect(probeCategory({})).toBe('external');
		// device_id 0/absent is not a binding (mirrors the backend's
		// DeviceID != nil check for real IDs).
		expect(probeCategory({ device_id: 0 })).toBe('external');
	});
});

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
		expect(historyBtn).toBeTruthy();
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

	// --- #605/#608 additions -------------------------------------------------

	it('module select offers dns and the per-module option fields follow the module', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const addBtn = Array.from(container.querySelectorAll('button')).find((b) =>
			(b.textContent ?? '').includes('Add Target')
		) as HTMLElement;
		expect(addBtn).toBeTruthy();
		await fireEvent.click(addBtn);

		const moduleSelect = container.querySelector('#probe-module') as HTMLSelectElement;
		expect(moduleSelect).toBeTruthy();
		const values = Array.from(moduleSelect.querySelectorAll('option')).map((o) => o.getAttribute('value'));
		expect(values).toEqual(['http', 'tls', 'tcp', 'icmp', 'dns']);

		// http (default): method/expected-status/keyword fields visible.
		expect(container.querySelector('#probe-opt-method')).toBeTruthy();
		expect(container.querySelector('#probe-opt-status')).toBeTruthy();
		expect(container.querySelector('#probe-opt-keyword')).toBeTruthy();
		expect(container.querySelector('#probe-opt-record')).toBeNull();

		// dns: record/resolver/expected-ips replace the http fields.
		await fireEvent.change(moduleSelect, { target: { value: 'dns' } });
		expect(container.querySelector('#probe-opt-record')).toBeTruthy();
		expect(container.querySelector('#probe-opt-resolver')).toBeTruthy();
		expect(container.querySelector('#probe-opt-ips')).toBeTruthy();
		expect(container.querySelector('#probe-opt-method')).toBeNull();

		// tcp: send/expect/expect-mode.
		await fireEvent.change(moduleSelect, { target: { value: 'tcp' } });
		expect(container.querySelector('#probe-opt-send')).toBeTruthy();
		expect(container.querySelector('#probe-opt-expect')).toBeTruthy();
		expect(container.querySelector('#probe-opt-expect-mode')).toBeTruthy();
		expect(container.querySelector('#probe-opt-record')).toBeNull();

		// tls / icmp take no options at all.
		await fireEvent.change(moduleSelect, { target: { value: 'tls' } });
		expect(container.querySelector('#probe-opt-method')).toBeNull();
		expect(container.querySelector('#probe-opt-send')).toBeNull();
		await fireEvent.change(moduleSelect, { target: { value: 'icmp' } });
		expect(container.querySelector('#probe-opt-send')).toBeNull();
	});

	it('submit payload carries the module options (empty values omitted)', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const addBtn = Array.from(container.querySelectorAll('button')).find((b) =>
			(b.textContent ?? '').includes('Add Target')
		) as HTMLElement;
		expect(addBtn).toBeTruthy();
		await fireEvent.click(addBtn);

		await fireEvent.input(container.querySelector('#probe-name')!, { target: { value: 'site-http' } });
		await fireEvent.input(container.querySelector('#probe-target')!, {
			target: { value: 'https://example.com/healthz' }
		});
		// http options: expected status list, keyword, ignore TLS. Defaults
		// (method GET, keyword_mode contains) must be omitted from the payload.
		await fireEvent.input(container.querySelector('#probe-opt-status')!, { target: { value: '200,204' } });
		await fireEvent.input(container.querySelector('#probe-opt-keyword')!, { target: { value: 'ok' } });
		// The options block's only checkbox is "ignore TLS errors".
		const optBlock = container.querySelector('#probe-opt-keyword')?.closest('.border');
		const checkbox = optBlock?.querySelector('input[type="checkbox"]') as HTMLInputElement;
		expect(checkbox).toBeTruthy();
		await fireEvent.click(checkbox);

		const form = container.querySelector('#probe-name')?.closest('form') as HTMLFormElement;
		await fireEvent.submit(form);

		await waitFor(() => {
			expect(vi.mocked(api.post)).toHaveBeenCalled();
		});
		const [url, body] = vi.mocked(api.post).mock.calls.at(-1)!;
		expect(url).toBe('/probe-targets/');
		expect(body).toMatchObject({
			module: 'http',
			target: 'https://example.com/healthz',
			options: {
				expected_status: [200, 204],
				keyword: 'ok',
				ignore_tls_errors: true
			}
		});
		// Defaults are omitted: no method / keyword_mode keys.
		const options = (body as Record<string, Record<string, unknown>>).options ?? {};
		expect('method' in options).toBe(false);
		expect('keyword_mode' in options).toBe(false);
	});

	it('prefills the create form from the ?create=1 deep link (device detail page)', async () => {
		window.history.replaceState(null, '', '/probes?create=1&module=tcp&target=192.0.2.10%3A8080&device_id=7');
		try {
			const { container } = render(Probes);
			await waitFor(() => {
				expect(container.querySelector('#probe-module')).toBeTruthy();
			});
			expect((container.querySelector('#probe-module') as HTMLSelectElement).value).toBe('tcp');
			expect((container.querySelector('#probe-target') as HTMLInputElement).value).toBe('192.0.2.10:8080');
			// tcp options render, http's don't.
			expect(container.querySelector('#probe-opt-send')).toBeTruthy();
			expect(container.querySelector('#probe-opt-method')).toBeNull();

			await fireEvent.input(container.querySelector('#probe-name')!, { target: { value: 'svc-tcp' } });
			const form = container.querySelector('#probe-name')?.closest('form') as HTMLFormElement;
			await fireEvent.submit(form);

			await waitFor(() => {
				expect(vi.mocked(api.post)).toHaveBeenCalled();
			});
			const [, body] = vi.mocked(api.post).mock.calls.at(-1)!;
			expect(body).toMatchObject({
				module: 'tcp',
				target: '192.0.2.10:8080',
				device_id: 7
			});
			// No options set → the create payload omits the key entirely.
			expect('options' in (body as Record<string, unknown>)).toBe(false);
		} finally {
			window.history.replaceState(null, '', '/probes');
		}
	});

	it('renders source badges for system and auto targets (manual gets none)', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('sys-egress-http');
			expect(container.textContent).toContain('auto-nas-web');
		});

		const systemIcon = container.querySelector('[title^="Built-in target"]');
		expect(systemIcon).toBeTruthy();
		expect(systemIcon?.querySelector('svg')).toBeTruthy();

		const autoIcon = container.querySelector('[title^="Auto-generated"]');
		expect(autoIcon).toBeTruthy();
		expect(autoIcon?.querySelector('svg')).toBeTruthy();

		// The manual rows (github-tls) carry no source icon.
		const manualRow = Array.from(container.querySelectorAll('tr')).find((r) =>
			r.textContent?.includes('github-tls')
		);
		expect(manualRow?.querySelector('[title^="Built-in target"]')).toBeNull();
		expect(manualRow?.querySelector('[title^="Auto-generated"]')).toBeNull();
	});

	it('egress-quality section renders vantage rows, verdict badges and reason chips', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('Main LAN');
		});

		// Vantage labels: network_name when present, raw vantage otherwise.
		expect(container.textContent).toContain('agent:edge-1');
		// Target columns render with ok-rate % and p50 latency.
		expect(container.textContent).toContain('pub-http');
		expect(container.textContent).toContain('100% · 30ms');
		expect(container.textContent).toContain('25% · 88ms');
		// A (vantage, target) cell with no data renders the muted dash.
		expect(container.textContent).toContain('—');

		// Verdict badges (en labels).
		expect(container.textContent).toContain('ok · 98');
		expect(container.textContent).toContain('DNS fault · 41');
		expect(container.textContent).toContain('upstream resolver · 55');
		expect(container.textContent).toContain('insufficient data · 0');

		// Reason chips for the non-ok vantage (localized, incl. the
		// upstream_resolver.failing:<name> suffix stripped to the name).
		expect(container.textContent).toContain('direct paths OK, name resolution dead');
		expect(container.textContent).toContain('success rate low');
		expect(container.textContent).toContain('resolver pub-dns failing');

		// Reference group renders with its secondary marker.
		expect(container.textContent).toContain('reference-alt');
		const refBadge = Array.from(container.querySelectorAll('.badge')).find((b) =>
			(b.textContent ?? '').trim() === 'reference'
		);
		expect(refBadge).toBeTruthy();
	});

	// --- #613 additions: per-category quality panel + list sections ---------

	it('quality panel renders quality groups then external, without the lan category (#615)', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('Main LAN');
		});

		const panel = container.querySelector('[data-quality-panel]') as HTMLElement;
		expect(panel).toBeTruthy();

		// Category headings in order quality → external; lan no longer has a
		// block in the panel (its health is the strip in the lan section).
		const headings = Array.from(panel.querySelectorAll('h4')).map((h) => (h.textContent ?? '').trim());
		expect(headings).toEqual(['Egress quality probes', 'External business probes']);

		// The lan category's matrix is gone from the panel: its vantage label,
		// target column and verdict badge appear nowhere in the panel section.
		expect(panel.textContent).not.toContain('LAN A');
		expect(panel.textContent).not.toContain('nas-web');
		expect(panel.textContent).not.toContain('ok · 97');
		expect(panel.textContent).not.toContain('100% · 3ms');

		// quality groups render as before, leading the panel now.
		expect(panel.textContent).toContain('pub-http');
		expect(panel.textContent).toContain('100% · 30ms');
		expect(panel.textContent).toContain('ok · 98');

		// external keeps its compact matrix: target cell + verdict badge +
		// reason chip.
		expect(panel.textContent).toContain('ext-http');
		expect(panel.textContent).toContain('80% · 120ms');
		expect(panel.textContent).toContain('degraded · 70');
		expect(panel.textContent).toContain('success rate low');
	});

	it('the lan section shows the per-vantage health strip when expanded (#615)', async () => {
		localStorage.removeItem('mibee.probes.sections');
		try {
			const { container } = render(Probes);
			await waitFor(() => {
				expect(container.textContent).toContain('auto-nas-web');
			});

			// Expanded by default: one quiet badge row inside the lan section.
			const strip = container.querySelector(
				'section[data-category="lan"] [data-lan-health]'
			) as HTMLElement;
			expect(strip).toBeTruthy();
			// Vantage label = network name; verdict badge with score, same
			// badge styling the panel uses (ok → badge-success).
			expect(strip.textContent).toContain('LAN A');
			expect(strip.textContent).toContain('ok · 97');
			expect(strip.querySelector('.badge')?.className).toContain('badge-success');
			// Quiet: no matrix, no lan target cells in the strip.
			expect(strip.querySelector('table')).toBeNull();
			expect(strip.textContent).not.toContain('nas-web');

			// The strip sits above the section's sub-table.
			const table = container.querySelector('section[data-category="lan"] table') as HTMLElement;
			expect(table).toBeTruthy();
			expect(strip.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();

			// Collapsing the lan section hides the strip with it.
			const toggle = container.querySelector(
				'button[aria-controls="probes-section-lan"]'
			) as HTMLElement;
			await fireEvent.click(toggle);
			expect(container.querySelector('[data-lan-health]')).toBeNull();
		} finally {
			localStorage.removeItem('mibee.probes.sections');
		}
	});

	it('groups the target list into three category sections in order', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const sectionOf = (name: string) =>
			Array.from(container.querySelectorAll('section[data-category]')).find((s) =>
				s.textContent?.includes(name)
			);

		// lan = auto source or device-bound; external = manual unbound;
		// quality = source system.
		expect(sectionOf('auto-nas-web')?.getAttribute('data-category')).toBe('lan');
		expect(sectionOf('nas-ssh')?.getAttribute('data-category')).toBe('lan');
		expect(sectionOf('github-tls')?.getAttribute('data-category')).toBe('external');
		expect(sectionOf('intranet-gw')?.getAttribute('data-category')).toBe('external');
		expect(sectionOf('sys-egress-http')?.getAttribute('data-category')).toBe('quality');

		const order = Array.from(container.querySelectorAll('section[data-category]')).map((s) =>
			s.getAttribute('data-category')
		);
		expect(order).toEqual(['lan', 'external', 'quality']);
	});

	it('section headers show the count and the enabled/ok/failing summary', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('nas-ssh');
		});

		// lan: 2 targets (auto-nas-web + nas-ssh), both enabled and succeeding.
		const lan = container.querySelector('section[data-category="lan"]');
		expect(lan?.textContent).toContain('LAN probes');
		expect(lan?.textContent).toContain('2 enabled · 2 ok · 0 failing');

		// external: github-tls (newest center track succeeds) + intranet-gw.
		const external = container.querySelector('section[data-category="external"]');
		expect(external?.textContent).toContain('2 enabled · 2 ok · 0 failing');

		// quality: the single system target row.
		const quality = container.querySelector('section[data-category="quality"]');
		expect(quality?.textContent).toContain('1 enabled · 1 ok · 0 failing');
	});

	it('collapsing a section hides its table and persists to localStorage', async () => {
		localStorage.removeItem('mibee.probes.sections');
		try {
			const { container } = render(Probes);
			await waitFor(() => {
				expect(container.textContent).toContain('github-tls');
			});

			// All sections expanded by default with their sub-tables rendered.
			expect(container.querySelector('#probes-section-quality table')).toBeTruthy();

			const toggle = container.querySelector(
				'button[aria-controls="probes-section-quality"]'
			) as HTMLElement;
			expect(toggle).toBeTruthy();
			expect(toggle.getAttribute('aria-expanded')).toBe('true');

			await fireEvent.click(toggle);
			// Collapsed: the section keeps its header, the content div is gone
			// (its only row disappears with it).
			expect(container.querySelector('#probes-section-quality')).toBeNull();
			const header = container.querySelector('section[data-category="quality"]');
			expect(header?.textContent).toContain('Egress quality probes');
			expect(header?.textContent).not.toContain('sys-egress-http');
			expect(toggle.getAttribute('aria-expanded')).toBe('false');

			// Persistence: expanded-state map stored under the stable key.
			expect(JSON.parse(localStorage.getItem('mibee.probes.sections') ?? '{}')).toEqual({
				lan: true,
				external: true,
				quality: false
			});
		} finally {
			localStorage.removeItem('mibee.probes.sections');
		}
	});

	it('an empty category keeps its header and renders the one-line hint', async () => {
		const seeded = mockState.targets;
		mockState.targets = seeded.filter((t) => probeCategory(t as { source?: string; device_id?: number }) !== 'lan');
		try {
			const { container } = render(Probes);
			await waitFor(() => {
				expect(container.textContent).toContain('github-tls');
			});

			const lan = container.querySelector('section[data-category="lan"]');
			expect(lan).toBeTruthy();
			expect(lan?.textContent).toContain('No LAN probes yet');
			// Hint only: no sub-table for the empty section.
			expect(lan?.querySelector('table')).toBeNull();
			// Sibling sections still render their tables.
			expect(container.querySelector('section[data-category="external"] table')).toBeTruthy();
		} finally {
			mockState.targets = seeded;
		}
	});

	it('the page-level search filters within sections and hides matchless ones', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const search = container.querySelector('input[aria-label="Search"]') as HTMLInputElement;
		expect(search).toBeTruthy();

		// "github" only matches an external-section row: lan/quality hide.
		await fireEvent.input(search, { target: { value: 'github' } });
		await waitFor(() => {
			expect(container.querySelectorAll('section[data-category]').length).toBe(1);
		});
		const visible = container.querySelector('section[data-category]');
		expect(visible?.getAttribute('data-category')).toBe('external');
		expect(visible?.textContent).toContain('github-tls');

		// No match anywhere: all sections hide, one no-match note shows.
		await fireEvent.input(search, { target: { value: 'zzz-no-such-target' } });
		await waitFor(() => {
			expect(container.querySelector('section[data-category]')).toBeNull();
		});
		expect(container.textContent).toContain('No match');
	});

	it('the section select-all checkbox selects that section\'s rows only', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('github-tls');
		});

		const external = container.querySelector('section[data-category="external"]');
		const selectAll = external?.querySelector(
			'input[aria-label^="Select all in"]'
		) as HTMLInputElement;
		expect(selectAll).toBeTruthy();
		await fireEvent.click(selectAll);

		// Batch toolbar appears with exactly the section's two rows.
		await waitFor(() => {
			expect(container.textContent).toContain('2 selected');
		});
		// Row-level checkboxes inside the OTHER sections stay unchecked.
		const qualityRow = container.querySelector(
			'section[data-category="quality"] tbody input[type="checkbox"]'
		) as HTMLInputElement;
		expect(qualityRow?.checked).toBe(false);
	});

	it('the quality panel help button carries the formula explanation tooltip', async () => {
		const { container } = render(Probes);
		await waitFor(() => {
			expect(container.textContent).toContain('Main LAN');
		});

		// The round help button is wired to the tooltip via aria-describedby.
		const btn = container.querySelector('button[aria-describedby="probes-quality-help"]') as HTMLElement;
		expect(btn).toBeTruthy();
		expect(btn.getAttribute('aria-label')).toContain('verdicts');

		// The tooltip content lives in the DOM (CSS-revealed on hover/focus,
		// visible to screen readers and jsdom regardless): window, cell math,
		// the simple-category rule (external matrix + LAN health strip, #615),
		// the verdict chain, config thresholds.
		const tip = container.querySelector('[data-quality-help]');
		expect(tip).toBeTruthy();
		expect(tip?.getAttribute('role')).toBe('tooltip');
		const text = tip?.textContent ?? '';
		expect(text).toContain('last 15 minutes');
		expect(text).toContain('successes ÷ total probes');
		expect(text).toContain('default 90%');
		expect(text).toContain('health strip');
		expect(text).toContain('egress down');
		expect(text).toContain('probe.quality config');
	});
});
