/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte';
import type { DeviceIdentity, IdentityCandidate, IdentityDevice } from '$lib/types';

const getMock = vi.hoisted(() => vi.fn());

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/api/client', () => ({
	api: { get: getMock },
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

import IdentityReviewPanel from '$lib/components/IdentityReviewPanel.svelte';

function device(id: number, overrides: Partial<IdentityDevice> = {}): IdentityDevice {
	return {
		id,
		device_uuid: `device-${id}-uuid`,
		name: `edge-${id}`,
		type: 'server',
		brand: 'Acme',
		model: 'Edge',
		ip_address: `192.0.2.${id + 9}`,
		mac_address: `00:11:22:33:44:${String(id).padStart(2, '0')}`,
		hostname: `host-${id}`,
		serial_number: `SERIAL-${id}`,
		network_id: 7,
		status: 'online',
		first_seen: '2026-11-01T10:00:00Z',
		last_seen: '2026-11-20T10:00:00Z',
		mac_aliases: ['00:11:22:33:44:99'],
		certificate_fingerprints: ['SHA256:ABCDEF0123456789'],
		multi_homed: true,
		stale: true,
		evidence_coverage: 0.75,
		...overrides
	};
}

function candidate(): IdentityCandidate {
	return {
		id: 'candidate-7-8',
		kind: 'combined',
		confidence: 'medium',
		score: 62,
		signals: ['mac_alias', 'certificate'],
		evidence: [
			{
				signal: 'mac_alias',
				source: 'passive_discovery',
				detail: 'Shared MAC alias',
				vantage: 'lan',
				observed_at: '2026-11-20T10:00:00Z'
			},
			{
				signal: 'certificate',
				source: 'tls_scan',
				detail: 'Matching certificate fingerprint'
			}
		],
		counter_evidence: ['Serial numbers differ'],
		temporal_overlap: false,
		device_a: device(7),
		device_b: device(8)
	};
}

function identity(overrides: Partial<DeviceIdentity> = {}): DeviceIdentity {
	return {
		device: device(7),
		candidates: [candidate()],
		...overrides
	};
}

describe('IdentityReviewPanel', () => {
	beforeEach(() => {
		getMock.mockReset();
		localStorage.setItem('lang', 'en');
	});

	it('fetches device identity and renders facts, candidates, evidence, and counter-evidence', async () => {
		getMock.mockResolvedValue(identity());
		render(IdentityReviewPanel, { deviceId: 7 });

		expect(await screen.findByText('Identity facts')).toBeInTheDocument();
		expect(getMock).toHaveBeenCalledWith('/devices/7/identity');
		expect(screen.getByText('host-7')).toBeInTheDocument();
		expect(screen.getByText('SERIAL-7')).toBeInTheDocument();
		expect(screen.getByText('00:11:22:33:44:99')).toBeInTheDocument();
		expect(screen.getByText('SHA256:ABCDEF0123456789')).toBeInTheDocument();
		expect(screen.getByText('75%')).toBeInTheDocument();
		expect(screen.getAllByText('Multi-homed').length).toBeGreaterThan(0);
		expect(screen.getAllByText('Stale').length).toBeGreaterThan(0);
		expect(screen.getByText('Possible match')).toBeInTheDocument();
		expect(screen.getByText('edge-8')).toBeInTheDocument();
		expect(screen.getByText('Medium')).toBeInTheDocument();
		expect(screen.getByText('Shared MAC alias')).toBeInTheDocument();
		expect(screen.getByText('Source: passive_discovery')).toBeInTheDocument();
		expect(screen.getByText('Serial numbers differ')).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: /merge|rename|split|push/i })).toBeNull();
	});

	it('refetches and resets the projection when deviceId changes', async () => {
		getMock.mockResolvedValueOnce(identity()).mockResolvedValueOnce(identity({
			device: device(8, { hostname: 'replacement-host', serial_number: 'SERIAL-REPLACEMENT' }),
			candidates: []
		}));
		const { rerender } = render(IdentityReviewPanel, { deviceId: 7 });
		await screen.findByText('host-7');

		await rerender({ deviceId: 8 });
		expect(await screen.findByText('replacement-host')).toBeInTheDocument();
		expect(getMock).toHaveBeenCalledWith('/devices/8/identity');
		expect(screen.queryByText('host-7')).not.toBeInTheDocument();
		expect(screen.getByText('No identity candidates')).toBeInTheDocument();
	});

	it('shows a retryable error before loading an empty candidate state', async () => {
		getMock.mockRejectedValueOnce(new Error('device identity offline')).mockResolvedValueOnce(identity({ candidates: [] }));
		render(IdentityReviewPanel, { deviceId: 7 });

		expect(await screen.findByRole('alert')).toHaveTextContent('device identity offline');
		await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
		expect(await screen.findByText('Identity facts')).toBeInTheDocument();
		expect(screen.getByText('No identity candidates')).toBeInTheDocument();
		expect(screen.getByText('No possible duplicate rows were found for this device. Nothing has been merged or changed.')).toBeInTheDocument();
	});
});
