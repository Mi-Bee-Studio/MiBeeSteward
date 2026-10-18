/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';

// The detail page derives deviceId from $page.params.id and reads the URL for
// tab deep links (?tab=heartbeat): pin both via a hoisted route object.
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
		ip_address: '192.168.2.168',
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
	// #606: probe targets bound to device 1 (Overview panel). Mutable so the
	// port-gone test case can point the target at a port the scan never saw.
	const probeTargets = [
		{
			id: 21,
			name: 'nas-web',
			module: 'http',
			target: 'http://192.168.2.168:5000/',
			interval_seconds: 60,
			timeout_seconds: 10,
			enabled: true,
			notes: '',
			vantage: 'center',
			device_id: 1,
			source: 'manual',
			last_status: 'success',
			last_latency_ms: 3.2,
			created_at: '2026-09-01T00:00:00Z',
			updated_at: '2026-09-19T00:00:00Z'
		}
	];
	return { route, device, probeTargets };
});

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));vi.mock('$app/stores', () => ({
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
		// onMount systems/configs probes. ORDER MATTERS: the bare /devices/1
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
			if (path === '/probe-targets/') {
				return Promise.resolve({ targets: mocks.probeTargets, total: mocks.probeTargets.length });
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
import { goto } from '$app/navigation';

describe('Device detail page', () => {
	beforeEach(() => {
		mocks.route.id = '1';
		mocks.route.search = '';
		mocks.device.tags = '["iot","Smartmi","miot"]';
		mocks.device.detected_services = '[]';
		mocks.device.open_ports = '[]';
		// The page hydrates ?tab= from window.location on mount; a prior test
		// may have deep-linked to ?tab=heartbeat (jsdom URL persists across
		// renders in this file) — always reset to the plain overview route.
		window.history.replaceState(null, '', '/devices/1');
		vi.mocked(goto).mockClear();
		mocks.probeTargets[0].target = 'http://192.168.2.168:5000/';
	});

	// #429: tags on the wire are a JSON array string; the asset-info section
	// must render the VALUES as chips: never "0: iot" index-prefixed entries.
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

	// #429 (manual-edit shape): tags may also be a plain CSV string: the
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
	// empty state forever. Deep-link straight to the heartbeat tab: the page
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

	// #606: the Overview tab lists the probe targets bound to this device.
	it('renders the bound-probes panel with status and the port-gone badge', async () => {
		// The latest scan saw port 5000 (no port-gone badge expected first).
		mocks.device.open_ports = '[{"port":5000,"service":"http"}]';
		mocks.device.detected_services = '[{"port":5000,"name":"http"}]';

		const { container } = render(Detail);
		await waitFor(() => {
			expect(container.textContent).toContain('nas-web');
		});

		const overview = container.querySelector('#tab-panel-overview');
		expect(overview?.textContent).toContain('http://192.168.2.168:5000/');
		expect(overview?.textContent).not.toContain('service not in the latest scan');

		// Re-render with a target whose port dropped out of the scan: the
		// amber read-time badge appears next to the row.
		mocks.probeTargets[0].target = 'http://192.168.2.168:8080/';
		const { container: c2 } = render(Detail);
		await waitFor(() => {
			expect(c2.textContent).toContain('nas-web');
		});
		expect(c2.textContent).toContain('service not in the latest scan');
	});

	// #606: per-service probe-create button deep-links to /probes prefilled.
	it('detected services offer a probe-create button that routes to /probes prefilled', async () => {
		mocks.device.detected_services = '[{"port":80,"name":"http"},{"port":22,"name":"ssh"}]';
		mocks.device.open_ports = '[{"port":80},{"port":22}]';

		const { container } = render(Detail);
		await waitFor(() => {
			expect(container.textContent).toContain('zhimi-airp-ua1');
		});

		const buttons = Array.from(container.querySelectorAll('button[aria-label^="Create a probe for this service"]'));
		expect(buttons.length).toBe(2);

		// http service → http module with an http:// URL bound to the device.
		await fireEvent.click(buttons[0]);
		expect(vi.mocked(goto)).toHaveBeenCalledWith(
			'/probes?create=1&module=http&target=' + encodeURIComponent('http://192.168.2.168:80/') + '&device_id=1'
		);

		// Any other TCP service (ssh) → tcp module against ip:port.
		await fireEvent.click(buttons[1]);
		expect(vi.mocked(goto)).toHaveBeenLastCalledWith(
			'/probes?create=1&module=tcp&target=' + encodeURIComponent('192.168.2.168:22') + '&device_id=1'
		);
	});
});
