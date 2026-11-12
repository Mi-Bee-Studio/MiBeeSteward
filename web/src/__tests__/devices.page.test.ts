/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

// Mutable per-test fixture data, readable inside the hoisted vi.mock factory.
const h = vi.hoisted(() => ({
	stats: { by_status: {} as Record<string, number>, by_type: {} as Record<string, number> },
	networks: [] as Array<{ id: number; name: string; cidr: string }>,
	tags: [] as Array<{ id: number; key: string; name: string; color: string; builtin: number }>,
	devices: [] as Array<Record<string, unknown>>,
	total: 0
}));

// Mock external-behavior modules so the page loads under jsdom.
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/api/client', () => ({
	api: {
		// Mount fires devices + stats + networks (+ tag dictionary); the
		// compact filter bar's applyFilters re-fires /devices.
		get: vi.fn((url: string) => {
			if (url.startsWith('/devices/stats')) return Promise.resolve(h.stats);
			if (url.startsWith('/devices')) return Promise.resolve({ devices: h.devices, total: h.total });
			if (url.startsWith('/networks')) return Promise.resolve({ networks: h.networks, total: h.networks.length });
			if (url.includes('/tags')) return Promise.resolve({ tags: h.tags });
			return Promise.resolve([]);
		}),
		post: vi.fn(() => Promise.resolve({})),
		put: vi.fn(() => Promise.resolve({})),
		del: vi.fn(() => Promise.resolve({}))
	},
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

import { api } from '$lib/api/client';
import Devices from '../routes/devices/+page.svelte';

describe('Devices page', () => {
	beforeEach(() => {
		h.stats = { by_status: {}, by_type: {} };
		h.networks = [];
		h.tags = [];
		h.devices = [];
		h.total = 0;
		vi.mocked(api.get).mockClear();
	});

	it('mounts and renders the page header (title + view controls)', () => {
		const { container } = render(Devices);

		// The page header (h2 title) is always rendered: not gated on the
		// loading state: so it's a stable "the page mounted" signal.
		const h2 = container.querySelector('h2');
		expect(h2).toBeTruthy();
		expect((h2?.textContent ?? '').trim().length).toBeGreaterThan(0);

		// The list/topology view toggle is part of the header chrome.
		expect(container.querySelector('button')).toBeTruthy();
	});
});

describe('Compact filter bar (#UI-compact)', () => {
	beforeEach(() => {
		h.stats = { by_status: { online: 74, offline: 44, unknown: 0 }, by_type: {} };
		h.networks = [{ id: 1, name: 'lan-62', cidr: '192.168.2.0/24' }];
		h.tags = [{ id: 3, key: 'external', name: '外部设备', color: '#888', builtin: 1 }];
		h.devices = [];
		h.total = 0;
		vi.mocked(api.get).mockClear();
	});

	it('renders status pills with live counts and NO stacked selects in the bar', async () => {
		const { container } = render(Devices);
		// Wait for the stats round-trip, not just the bar skeleton.
		await waitFor(() => {
			expect(container.querySelector('[data-status-pills]')?.textContent).toContain('74');
		});
		const bar = container.querySelector('[data-filter-bar]') as HTMLElement;
		// The whole point: zero <select> as a DIRECT child of the bar — the
		// four secondary axes live in the popover, not stacked full-width.
		expect(bar.querySelector(':scope > select')).toBeNull();
		// Pills carry the counts (在线 · 74 / 离线 · 44 / 未知 · 0).
		const pills = bar.querySelectorAll('[data-status-pills] button');
		expect(pills.length).toBe(4);
		const text = Array.from(pills).map((p) => p.textContent ?? '').join('|');
		expect(text).toContain('74');
		expect(text).toContain('44');
		expect(text).toContain('0');
	});

	it('status pill click filters (aria-pressed + refetch with status param)', async () => {
		const { container } = render(Devices);
		await waitFor(() => {
			expect(container.querySelector('[data-status-pills]')).toBeTruthy();
		});
		const before = vi.mocked(api.get).mock.calls.length;
		const pills = container.querySelectorAll('[data-status-pills] button');
		// index 1 = 在线 (after 全部).
		await fireEvent.click(pills[1]);
		await waitFor(() => {
			expect(pills[1].getAttribute('aria-pressed')).toBe('true');
		});
		// applyFilters refires /devices with the status param.
		await waitFor(() => {
			const calls = vi.mocked(api.get).mock.calls.slice(before);
			expect(calls.some(([u]) => String(u).includes('status=online'))).toBe(true);
		});
	});

	it('popover holds the four secondary axes; picking one renders a removable chip', async () => {
		const { container } = render(Devices);
		await waitFor(() => {
			expect(container.querySelector('[data-filter-menu-btn]')).toBeTruthy();
		});
		// Closed by default: no menu panel.
		expect(container.querySelector('[data-filter-menu]')).toBeNull();
		await fireEvent.click(container.querySelector('[data-filter-menu-btn]') as HTMLElement);
		await waitFor(() => {
			expect(container.querySelector('[data-filter-menu]')).toBeTruthy();
		});
		// Four axes inside the panel.
		const menu = container.querySelector('[data-filter-menu]') as HTMLElement;
		expect(menu.querySelectorAll('select').length).toBe(4);

		// Pick a type → chip appears outside the popover with a ✕ clear.
		const typeSelect = menu.querySelector('select') as HTMLSelectElement;
		await fireEvent.change(typeSelect, { target: { value: 'nas' } });
		await waitFor(() => {
			expect(container.querySelector('[data-active-filter-chip="type"]')).toBeTruthy();
		});
		const chip = container.querySelector('[data-active-filter-chip="type"]') as HTMLElement;
		expect(chip.textContent).toContain('NAS');

		// Chip click clears the filter (chip disappears, refetch without type).
		const before = vi.mocked(api.get).mock.calls.length;
		await fireEvent.click(chip);
		await waitFor(() => {
			expect(container.querySelector('[data-active-filter-chip="type"]')).toBeNull();
			const calls = vi.mocked(api.get).mock.calls.slice(before);
			expect(calls.some(([u]) => !String(u).includes('type=nas'))).toBe(true);
		});
	});
});

describe('Devices page — parked rows (#737)', () => {
	it('a parked IP (#park:<id>) renders the release badge, never the raw sentinel', async () => {
		h.stats = { by_status: { offline: 1 }, by_type: { other: 1 } };
		h.networks = [{ id: 1, name: 'lan-62', cidr: '192.0.2.0/24' }];
		h.devices = [
			{
				id: 6,
				name: 'esp32c6-11DB60',
				type: 'other',
				ip_address: '#park:6',
				mac_address: 'aa:bb:cc:dd:ee:06',
				status: 'offline',
				scan_source: 'scanner_v2',
				network_id: 1
			}
		];
		h.total = 1;
		const { container } = render(Devices);
		await waitFor(() => {
			expect(container.textContent).toContain('esp32c6-11DB60');
		});
		expect(container.textContent).toContain('address released');
		expect(container.textContent).not.toContain('#park:6');
	});
});
