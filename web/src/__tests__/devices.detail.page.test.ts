/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

// The detail page derives deviceId from $page.params.id and reads the URL for
// tab deep links (?tab=heartbeat) — pin both via a hoisted route object.
const mocks = vi.hoisted(() => {
	const route = { id: '1', search: '' };
	// Mutable device fixture: the tags test cases swap .tags between renders.
	const device: Record<string, unknown> = {
		id: 1,
		name: 'zhimi-airp-ua1',
		type: 'iot',
		brand: 'Smartmi',
		model: 'UA1',
		location: '',
		purpose: '',
		description: '',
		status: 'online',
		ip_address: '192.168.62.168',
		mac_address: 'aa:bb:cc:dd:ee:ff',
		serial_number: '',
		purchase_date: '',
		warranty_expiry: '',
		tags: '["iot","Smartmi","miot"]',
		scan_source: 'scanner_v2',
		prometheus_labels: '{}',
		last_scanned_at: '2026-09-19T00:00:00Z',
		last_scan_task_id: 1,
		open_ports: '[]',
		detected_services: '[]',
		prometheus_url: '',
		node_exporter_url: '',
		last_scan_rtt_ms: 3,
		scan_attributes: '{}',
		user_attributes: '{}',
		network_id: 1,
		first_seen: '2026-09-01T00:00:00Z',
		last_seen: '2026-09-19T00:00:00Z',
		created_at: '2026-09-01T00:00:00Z',
		updated_at: '2026-09-19T00:00:00Z'
	};
	return { route, device };
});

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$app/stores', () => ({
	page: {
		subscribe: (fn: (v: { params: { id: string }; url: { search: string } }) => void) => {
			fn({ params: { id: mocks.route.id }, url: { search: mocks.route.search } });
			return () => {};
		}
	}
}));
vi.mock('$lib/charts/echarts', () => ({
	echarts: {
		init: vi.fn(() => ({ setOption: vi.fn(), dispose: vi.fn(), resize: vi.fn() }))
	}
}));
vi.mock('$lib/api/client', () => ({
	api: {
		// Route by path: the device itself, its heartbeat endpoints, and the
		// onMount systems/configs probes. ORDER MATTERS — the bare /devices/1
		// probe must be exact so it doesn't swallow the sub-resource paths.
		get: vi.fn((url: string) => {
			const path = url.split('?')[0];
			if (path === '/devices/1') {
				return Promise.resolve({ ...mocks.device });
			}
			if (path === '/devices/1/heartbeat-history') {
				return Promise.resolve({
					results: [
						{ id: 1, config_id: 1, status: 'success', latency_ms: 12, error_message: '', checked_at: '2026-09-19T00:00:30Z' },
						{ id: 2, config_id: 1, status: 'success', latency_ms: 14, error_message: '', checked_at: '2026-09-19T00:01:00Z' },
						{ id: 3, config_id: 1, status: 'fail', latency_ms: 0, error_message: 'timeout', checked_at: '2026-09-19T00:01:30Z' }
					],
					total: 3,
					page: 1,
					page_size: 1000
				});
			}
			if (path === '/devices/1/heartbeat-stats') {
				return Promise.resolve({ avg_latency_ms: 13, success_count: 2, fail_count: 1, timeout_count: 0 });
			}
			if (path === '/devices/1/heartbeat-configs') {
				if (url.includes('limit=1')) return Promise.resolve({ total: 1 });
				return Promise.resolve({ configs: [], total: 0 });
			}
			if (path === '/devices/1/systems') {
				return Promise.resolve({ systems: [], total: 0 });
			}
			return Promise.resolve({});
		}),
		post: vi.fn(() => Promise.resolve(undefined)),
		put: vi.fn(() => Promise.resolve(undefined)),
		del: vi.fn(() => Promise.resolve(undefined))
	},
	ApiError: class ApiError extends Error {
		status = 0;
	},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

// detail page must be imported AFTER the vi.mock calls so the mocks take effect.
import Detail from '../routes/devices/detail/[id]/+page.svelte';

describe('Device detail page', () => {
	beforeEach(() => {
		mocks.route.id = '1';
		mocks.route.search = '';
		mocks.device.tags = '["iot","Smartmi","miot"]';
	});

	// #429: tags on the wire are a JSON array string; the asset-info section
	// must render the VALUES as chips — never "0: iot" index-prefixed entries.
	it('renders tag chips as values without array indices (#429)', async () => {
		const { container } = render(Detail);

		await waitFor(() => {
			expect(container.textContent).toContain('zhimi-airp-ua1');
		});
		const badges = await waitFor(() => {
			const chips = Array.from(container.querySelectorAll('span.service-badge'));
			expect(chips.length).toBe(3);
			return chips;
		});
		const texts = badges.map((b) => (b.textContent ?? '').trim());
		expect(texts).toEqual(['iot', 'Smartmi', 'miot']);
	});

	// #429 (manual-edit shape): tags may also be a plain CSV string — the
	// manual edit form submits it that way.
	it('renders CSV tags as plain chips too (#429)', async () => {
		mocks.device.tags = 'camera,Chuangmi,miot';

		const { container } = render(Detail);

		await waitFor(() => {
			const chips = Array.from(container.querySelectorAll('span.service-badge'));
			expect(chips.length).toBe(3);
			const texts = chips.map((b) => (b.textContent ?? '').trim());
			expect(texts).toEqual(['camera', 'Chuangmi', 'miot']);
		});
	});

	// #440: the trend chart reads the history rows from the `results` key of
	// the generated HeartbeatResultList shape. Before the fix it read
	// `heartbeat_results` (never present) and the chart rendered the "no data"
	// empty state forever. Deep-link straight to the heartbeat tab — the page
	// reads ?tab= from window.location.search, so set it via replaceState.
	it('feeds the heartbeat trend chart from the results field (#440)', async () => {
		window.history.replaceState(null, '', '/devices/1?tab=heartbeat');

		const { container } = render(Detail);

		// The chart container only renders when buildTrendChart received
		// non-empty rows (trendOption stays {} on the empty path and the
		// template shows the No Data empty state instead).
		await waitFor(() => {
			const chart = container.querySelector('#tab-panel-heartbeat .echarts-container');
			expect(chart).toBeTruthy();
		});
		// And the "no data" empty state must NOT be showing inside the panel.
		const panel = container.querySelector('#tab-panel-heartbeat');
		expect(panel?.textContent).not.toContain('No Data');
	});
});
