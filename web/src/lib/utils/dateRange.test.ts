import { describe, expect, it } from 'vitest';

import { defaultRange, presetWindowMs, toLocalDateInput, toLocalDateTimeInput } from '$lib/utils/dateRange';

describe('toLocalDateInput / toLocalDateTimeInput', () => {
	it('formats with zero padding on the local timezone', () => {
		// Construct parts in LOCAL time so the assertion is tz-independent.
		const d = new Date(2026, 10, 9, 7, 5); // 2026-11-09 07:05 local
		expect(toLocalDateInput(d)).toBe('2026-11-09');
		expect(toLocalDateTimeInput(d)).toBe('2026-11-09T07:05');
	});
});

describe('defaultRange', () => {
	it('date-only inputs clamp the window to day granularity', () => {
		// 2026-11-10 23:30 local, 1h window → from falls on the same day:
		// today → today.
		const now = new Date(2026, 10, 10, 23, 30);
		expect(defaultRange('date', 3600_000, now)).toEqual({ from: '2026-11-10', to: '2026-11-10' });
	});
	it('date-only inputs span multiple days for wider windows', () => {
		const now = new Date(2026, 10, 10, 12, 0);
		expect(defaultRange('date', 7 * 24 * 3600_000, now)).toEqual({
			from: '2026-11-03',
			to: '2026-11-10'
		});
	});
	it('datetime-local inputs keep hour precision', () => {
		const now = new Date(2026, 10, 10, 15, 30);
		expect(defaultRange('datetime-local', 3600_000, now)).toEqual({
			from: '2026-11-10T14:30',
			to: '2026-11-10T15:30'
		});
	});
});

describe('presetWindowMs', () => {
	it('maps the heartbeat-trend presets', () => {
		expect(presetWindowMs('1h')).toBe(3600_000);
		expect(presetWindowMs('6h')).toBe(6 * 3600_000);
		expect(presetWindowMs('24h')).toBe(24 * 3600_000);
		expect(presetWindowMs('7d')).toBe(7 * 24 * 3600_000);
		expect(presetWindowMs('30d')).toBe(30 * 24 * 3600_000);
		// fallback = 24h
		expect(presetWindowMs('custom')).toBe(24 * 3600_000);
	});
});
