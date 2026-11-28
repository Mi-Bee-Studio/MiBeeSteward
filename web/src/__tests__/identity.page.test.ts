/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import type { IdentityCandidate, IdentityCandidateList, IdentityDevice } from '$lib/types';

const getMock = vi.hoisted(() => vi.fn());

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/api/client', () => ({
	api: { get: getMock },
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

import IdentityPage from '../routes/(assets)/identity/+page.svelte';

function device(overrides: Partial<IdentityDevice> = {}): IdentityDevice {
	return {
		id: 1,
		device_uuid: 'device-a-uuid',
		name: 'edge-a',
		type: 'server',
		brand: 'Acme',
		model: 'Edge 1',
		ip_address: '192.0.2.10',
		mac_address: '00:11:22:33:44:55',
		hostname: 'edge-a',
		serial_number: 'SERIAL-A',
		network_id: 7,
		status: 'online',
		mac_aliases: [],
		certificate_fingerprints: [],
		multi_homed: false,
		stale: false,
		evidence_coverage: 0.75,
		...overrides
	};
}

function candidate(overrides: Partial<IdentityCandidate> = {}): IdentityCandidate {
	return {
		id: 'candidate-1',
		kind: 'combined',
		confidence: 'high',
		score: 90,
		signals: ['hostname', 'serial'],
		evidence: [{
			signal: 'hostname',
			source: 'scanner_v2',
			detail: 'Same normalized hostname edge',
			vantage: 'lan',
			observed_at: '2026-11-20T10:00:00Z'
		}],
		counter_evidence: ['Different chassis serial numbers'],
		temporal_overlap: true,
		device_a: device(),
		device_b: device({
			id: 2,
			device_uuid: 'device-b-uuid',
			name: 'edge-b',
			ip_address: '192.0.2.11',
			mac_address: '00:11:22:33:44:66',
			hostname: 'edge-b',
			serial_number: 'SERIAL-B'
		}),
		...overrides
	};
}

function candidateList(overrides: Partial<IdentityCandidateList> = {}): IdentityCandidateList {
	return {
		candidates: [candidate()],
		summary: {
			total_devices: 24,
			candidate_count: 120,
			high_count: 90,
			medium_count: 20,
			low_count: 10,
			unknown_rate: 0.25,
			stale_rate: 0.125,
			evidence_coverage: 0.625
		},
		total: 120,
		limit: 50,
		offset: 0,
		...overrides
	};
}

function mockDefaults() {
	getMock.mockImplementation((url: string) => {
		if (url === '/networks') {
			return Promise.resolve({ networks: [{ id: 7, name: 'lan-7', cidr: '192.0.2.0/24' }], total: 1 });
		}
		if (url.startsWith('/identity/candidates')) return Promise.resolve(candidateList());
		if (url === '/devices/1/identity') {
			return Promise.resolve({ device: candidate().device_a, candidates: [candidate()] });
		}
		if (url === '/devices/2/identity') {
			return Promise.resolve({ device: candidate().device_b, candidates: [candidate()] });
		}
		return Promise.reject(new Error(`Unexpected GET ${url}`));
	});
}

describe('Identity Review page', () => {
	beforeEach(() => {
		getMock.mockReset();
		localStorage.setItem('lang', 'en');
		mockDefaults();
	});

	it('loads the scoped summary and renders both devices with explainable signals', async () => {
		render(IdentityPage);

		expect(await screen.findByText('edge-a')).toBeInTheDocument();
		expect(screen.getByText('edge-b')).toBeInTheDocument();
		expect(getMock).toHaveBeenCalledWith('/identity/candidates?limit=50&offset=0');
		expect(screen.getByText('Suggestions only — no automatic merge')).toBeInTheDocument();
		const row = document.querySelector('[data-candidate-id="candidate-1"]') as HTMLElement;
		expect(within(row).getByText('High')).toBeInTheDocument();
		expect(within(row).getByText('90')).toBeInTheDocument();
		expect(within(row).getByText('Hostname')).toBeInTheDocument();
		expect(within(row).getByText('Serial number')).toBeInTheDocument();
		expect(within(row).getByText('Different chassis serial numbers')).toBeInTheDocument();

		const cards = [
			['active-devices', '24'],
			['candidates', '120'],
			['high', '90'],
			['medium', '20'],
			['low', '10'],
			['unknown', '25%'],
			['stale', '13%'],
			['evidence-coverage', '63%']
		] as const;
		for (const [key, value] of cards) {
			expect(document.querySelector(`[data-summary-card="${key}"]`)?.textContent).toContain(value);
		}
	});

	it('sends confidence/network filters and limit/offset pagination parameters', async () => {
		render(IdentityPage);
		await screen.findByText('edge-a');

		await fireEvent.change(document.querySelector('[data-confidence-filter]') as HTMLSelectElement, {
			target: { value: 'high' }
		});
		await waitFor(() => {
			expect(getMock).toHaveBeenCalledWith('/identity/candidates?limit=50&offset=0&min_confidence=high');
		});

		await fireEvent.change(document.querySelector('[data-network-filter]') as HTMLSelectElement, {
			target: { value: '7' }
		});
		await waitFor(() => {
			expect(getMock).toHaveBeenCalledWith('/identity/candidates?limit=50&offset=0&min_confidence=high&network_id=7');
		});

		await screen.findByText('edge-a');
		await fireEvent.click(screen.getByRole('button', { name: 'Next' }));
		await waitFor(() => {
			expect(getMock).toHaveBeenCalledWith('/identity/candidates?limit=50&offset=50&min_confidence=high&network_id=7');
		});

		await screen.findByText('edge-a');
		await fireEvent.change(screen.getByLabelText('Rows per page'), { target: { value: '100' } });
		await waitFor(() => {
			expect(getMock).toHaveBeenCalledWith('/identity/candidates?limit=100&offset=0&min_confidence=high&network_id=7');
		});
	});

	it('reveals candidate evidence and opens a read-only per-device panel', async () => {
		render(IdentityPage);
		await screen.findByText('edge-a');
		expect(screen.queryByText('Same normalized hostname edge')).not.toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Show evidence' }));
		expect(screen.getByText('Same normalized hostname edge')).toBeInTheDocument();
		expect(screen.getByText('Source: scanner_v2')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Review identity: edge-a' }));
		const dialog = await screen.findByRole('dialog');
		expect(within(dialog).getByText('Identity facts')).toBeInTheDocument();
		expect(within(dialog).getByText('SERIAL-A')).toBeInTheDocument();
		expect(getMock).toHaveBeenCalledWith('/devices/1/identity');
		expect(within(dialog).queryByRole('button', { name: /merge|rename|split|push/i })).toBeNull();
	});

	it('shows a retryable error and an empty state', async () => {
		let candidateAttempts = 0;
		getMock.mockImplementation((url: string) => {
			if (url === '/networks') return Promise.resolve({ networks: [], total: 0 });
			if (url.startsWith('/identity/candidates')) {
				candidateAttempts += 1;
				if (candidateAttempts === 1) return Promise.reject(new Error('identity backend offline'));
				return Promise.resolve(candidateList({ candidates: [], total: 0 }));
			}
			return Promise.reject(new Error(`Unexpected GET ${url}`));
		});

		render(IdentityPage);
		expect(await screen.findByRole('alert')).toHaveTextContent('identity backend offline');
		await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
		expect(await screen.findByText('No identity candidates')).toBeInTheDocument();
		expect(screen.getByText('No possible duplicate rows match the current filters. Try another network or confidence level.')).toBeInTheDocument();
	});

	it('renders server strings as text rather than HTML', async () => {
		const unsafeName = '<img src=x onerror="window.identityXss=1">';
		getMock.mockImplementation((url: string) => {
			if (url === '/networks') return Promise.resolve({ networks: [], total: 0 });
			if (url.startsWith('/identity/candidates')) {
				return Promise.resolve(candidateList({
					candidates: [candidate({
						device_a: device({ name: unsafeName }),
						evidence: [{ signal: 'hostname', source: 'scanner', detail: '<script>window.identityXss=1</script>' }]
					})],
					total: 1
				}));
			}
			return Promise.reject(new Error(`Unexpected GET ${url}`));
		});

		const { container } = render(IdentityPage);
		await screen.findByText(unsafeName);
		await fireEvent.click(screen.getByRole('button', { name: 'Show evidence' }));
		expect(screen.getByText('<script>window.identityXss=1</script>', { exact: false })).toBeInTheDocument();
		expect(container.querySelector('img, script')).toBeNull();
	});
});
