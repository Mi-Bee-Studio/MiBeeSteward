/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero
 * General Public License v3.0 or later. See LICENSE for the full text.
 * A commercial license is available for use cases the AGPL does not
 * accommodate; see LICENSE-COMMERCIAL.md.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';

// render + interaction: mock the API surface the scan-results page touches:
// the task dropdown, the results list, and the run-history list. Assertions
// are data-driven (IPs / service names / run IDs), never localized strings.
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/api/client', () => ({
	api: {
		get: vi.fn((url: string) => {
			if (url.startsWith('/scanner/tasks')) {
				return Promise.resolve({
					tasks: [{ id: 1, name: 'lan-sweep', targets: '192.168.62.0/24', enabled: true }],
					total: 1
				});
			}
			if (url.startsWith('/scanner/results')) {
				return Promise.resolve({ results: [seedResult()], total: 1 });
			}
			if (url.startsWith('/scanner/runs')) {
				return Promise.resolve({ runs: [seedRun()], total: 1 });
			}
			return Promise.resolve([]);
		}),
		post: vi.fn(() => Promise.resolve({})),
		put: vi.fn(() => Promise.resolve({})),
		delete: vi.fn(() => Promise.resolve({})),
		download: vi.fn(() => Promise.resolve(new Blob([])))
	},
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

import ScanResults from '../routes/devices/scan-results/+page.svelte';

function seedResult() {
	return {
		id: 7,
		task_id: 1,
		run_id: 3,
		ip: '192.168.62.10',
		alive: true,
		rtt_ms: 3,
		ports: JSON.stringify([{ port: 80, service: 'http' }, { port: 22, service: 'ssh' }]),
		services: JSON.stringify([{ port: 80, service: 'http', version: 'nginx/1.24' }]),
		snmp_data: JSON.stringify({ sys_name: 'edge-router', sys_descr: 'Linux 5.15' }),
		prometheus_detected: true,
		prometheus_url: 'http://192.168.62.10:9090/metrics',
		node_exporter_detected: false,
		node_exporter_url: '',
		node_exporter_data: '{}',
		scanned_at: '2026-09-17T00:00:00Z'
	};
}

function seedRun() {
	return {
		id: 3,
		task_id: 1,
		status: 'completed',
		total_hosts: 4,
		alive_hosts: 2,
		new_hosts: 1,
		updated_hosts: 1,
		duration_ms: 5400,
		error_message: '',
		started_at: '2026-09-17T00:00:00Z',
		finished_at: '2026-09-17T00:01:00Z',
		created_at: '2026-09-17T00:00:00Z'
	};
}

// The tab switcher is the last bordered button-group in the filter bar
// (after the alive/dead filter group); its second button is Run History.
function runHistoryTab(container: HTMLElement): HTMLElement {
	const groups = container.querySelectorAll('.overflow-hidden');
	expect(groups.length).toBeGreaterThanOrEqual(2);
	const tabs = groups[groups.length - 1] as HTMLElement;
	const buttons = tabs.querySelectorAll('button');
	expect(buttons.length).toBe(2);
	return buttons[1] as HTMLElement;
}

describe('Scan-results page', () => {
	it('mounts and renders the results table with the seeded row', async () => {
		const { container } = render(ScanResults);

		const h2 = container.querySelector('h2');
		expect(h2).toBeTruthy();
		expect((h2?.textContent ?? '').trim().length).toBeGreaterThan(0);

		await waitFor(() => {
			expect(container.textContent).toContain('192.168.62.10');
		});
		// Services cell joins the parsed service names.
		expect(container.textContent).toContain('http');
	});

	it('expands a row on click to show SNMP detail', async () => {
		const { container } = render(ScanResults);
		await waitFor(() => {
			expect(container.textContent).toContain('192.168.62.10');
		});

		const row = Array.from(container.querySelectorAll('tbody tr')).find((tr) =>
			(tr.textContent ?? '').includes('192.168.62.10')
		) as HTMLElement;
		expect(row).toBeTruthy();
		await fireEvent.click(row);

		// The expanded detail panel parses snmp_data and shows sys_name;
		// this pins the parseJSON rendering path, not just the table shell.
		await waitFor(() => {
			expect(container.textContent).toContain('edge-router');
		});
	});

	it('switches to the run-history tab and renders the seeded run', async () => {
		const { container } = render(ScanResults);
		await waitFor(() => {
			expect(container.textContent).toContain('192.168.62.10');
		});

		await fireEvent.click(runHistoryTab(container));
		await waitFor(() => {
			expect(container.textContent).toContain('#3');
		});
		// Duration renders through formatDuration (5400ms → "5.4s"): a
		// single text node, so the assertion is whitespace-stable.
		expect(container.textContent).toContain('5.4s');
	});
});
