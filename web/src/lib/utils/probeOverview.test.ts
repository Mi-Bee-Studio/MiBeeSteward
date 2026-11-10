import { describe, expect, it } from 'vitest';

import type { ProbePathSample, ProbeQualityEpisode } from '$lib/types';
import {
 episodeBars,
 groupPathsByTarget,
 healthSegments,
 latencyHeat,
 pathState
} from '$lib/utils/probeOverview';

const path = (over: Partial<ProbePathSample>): ProbePathSample =>
	({
		id: 1,
		target_id: 1,
		target_name: 'web',
		vantage: 'center',
		method: 'tcp',
		end_state: 'reached',
		reached_ttl: 11,
		reply_ttl: 55,
		visible_hops: 2,
		hops: [],
		trigger: 'baseline',
		err: '',
		traced_at: '2026-11-10T10:00:00Z',
		...over
	}) as ProbePathSample;

describe('groupPathsByTarget', () => {
	it('collapses per-(target, vantage) rows into one row per target', () => {
		const rows = groupPathsByTarget([
			path({ id: 1, target_id: 1, target_name: 'web', vantage: 'center' }),
			path({ id: 2, target_id: 1, target_name: 'web', vantage: 'agent:rig' }),
			path({ id: 3, target_id: 2, target_name: 'api', vantage: 'center' })
		]);
		expect(rows).toHaveLength(2);
		expect(rows.map((r) => r.targetName).sort()).toEqual(['api', 'web']);
		expect(rows.find((r) => r.targetName === 'web')?.cells).toHaveLength(2);
	});

	it('sorts rows problem-first (error > max_ttl > reached), then name', () => {
		const rows = groupPathsByTarget([
			path({ id: 1, target_id: 1, target_name: 'aaa', end_state: 'reached' }),
			path({ id: 2, target_id: 2, target_name: 'zzz', end_state: 'max_ttl' }),
			path({ id: 3, target_id: 3, target_name: 'bbb', end_state: 'error' })
		]);
		expect(rows.map((r) => r.targetName)).toEqual(['bbb', 'zzz', 'aaa']);
		expect(rows[0].worst).toBe('error');
	});

	it('keeps the newest sample per vantage and orders center first', () => {
		const rows = groupPathsByTarget([
			path({ id: 1, target_id: 1, vantage: 'agent:rig', traced_at: '2026-11-10T09:00:00Z' }),
			path({ id: 2, target_id: 1, vantage: 'agent:rig', traced_at: '2026-11-10T09:30:00Z', reached_ttl: 9 }),
			path({ id: 3, target_id: 1, vantage: 'center', traced_at: '2026-11-10T09:15:00Z' })
		]);
		const cells = rows[0].cells;
		expect(cells[0].sample.vantage).toBe('center');
		// newest agent sample wins
		expect(cells[1].sample.reached_ttl).toBe(9);
	});

	it('tracks the group-wide newest trace time and worst state', () => {
		const rows = groupPathsByTarget([
			path({ id: 1, target_id: 1, target_name: 'web', end_state: 'reached', traced_at: '2026-11-10T09:00:00Z' }),
			path({ id: 2, target_id: 1, target_name: 'web', vantage: 'agent:rig', end_state: 'max_ttl', traced_at: '2026-11-10T09:30:00Z' })
		]);
		expect(rows[0].worst).toBe('max_ttl');
		expect(rows[0].tracedAt).toBe('2026-11-10T09:30:00Z');
	});
});

describe('pathState', () => {
	it('maps end_state onto the three states', () => {
		expect(pathState(path({ end_state: 'reached' }))).toBe('reached');
		expect(pathState(path({ end_state: 'error' }))).toBe('error');
		expect(pathState(path({ end_state: 'max_ttl' }))).toBe('max_ttl');
	});
});

describe('latencyHeat', () => {
	it('tints only the slow legs relative to the best vantage', () => {
		// best 10ms: 14ms calm, 25ms warm, 50ms hot
		expect(latencyHeat([14, 25, 50, 10])).toEqual([null, 'warm', 'hot', null]);
	});
	it('needs two measurable values and a positive minimum', () => {
		expect(latencyHeat([10])).toEqual([null]);
		// 0ms legs count as no-data; the real minimum (5ms) still anchors the tint.
		expect(latencyHeat([0, 5, 20])).toEqual([null, null, 'hot']);
		expect(latencyHeat([null, null])).toEqual([null, null]);
		expect(latencyHeat([0, 0, 0])).toEqual([null, null, null]);
	});
	it('treats missing values as no-tint cells', () => {
		expect(latencyHeat([10, null, 40])).toEqual([null, null, 'hot']);
	});
});

describe('episodeBars', () => {
	const now = Date.parse('2026-11-10T12:00:00Z');
	const ep = (over: Partial<ProbeQualityEpisode>): ProbeQualityEpisode =>
		({
			id: 1,
			kind: 'network',
			vantage_group: 'center',
			target_group: '',
			started_at: '2026-11-10T10:00:00Z',
			last_seen_at: '2026-11-10T11:00:00Z',
			windows: 2,
			metric_degraded: [],
			attribution: [],
			notified: true,
			resolved_at: '2026-11-10T11:00:00Z',
			recover_notified: true,
			...over
		}) as ProbeQualityEpisode;

	it('lays out episodes over the 24h window', () => {
		const bars = episodeBars([ep({})], now);
		expect(bars).toHaveLength(1);
		// window = [11-09 12:00, 11-10 12:00]; 10:00 sits 22h from the left edge.
		expect(bars[0].leftPct).toBeCloseTo((22 / 24) * 100, 1);
		expect(bars[0].widthPct).toBeCloseTo((1 / 24) * 100, 1);
		// resolved → warn even though notified
		expect(bars[0].cls).toBe('bar-warn');
	});

	it('marks notified AND active episodes red, runs them to the right edge', () => {
		const bars = episodeBars(
			[ep({ resolved_at: '', last_seen_at: '2026-11-10T11:59:00Z' })],
			now
		);
		expect(bars[0].cls).toBe('bar-error');
		expect(bars[0].leftPct + bars[0].widthPct).toBeCloseTo(100, 1);
	});

	it('clamps episodes that started before the window and widens slivers', () => {
		// started 11-08 (before the window), resolved 11-09 18:00 — 6h inside.
		const bars = episodeBars(
			[ep({ started_at: '2026-11-08T00:00:00Z', resolved_at: '2026-11-09T18:00:00Z' })],
			now
		);
		expect(bars[0].leftPct).toBe(0);
		expect(bars[0].widthPct).toBeCloseTo(25, 0);

		const sliver = episodeBars(
			[ep({ started_at: '2026-11-10T11:59:50Z', resolved_at: '2026-11-10T11:59:55Z' })],
			now
		);
		expect(sliver[0].widthPct).toBeGreaterThanOrEqual(0.75);
	});

	it('drops episodes that ended before the window opens', () => {
		const bars = episodeBars(
			[ep({ started_at: '2026-11-08T00:00:00Z', resolved_at: '2026-11-08T01:00:00Z' })],
			now
		);
		expect(bars).toHaveLength(0);
	});
});

describe('healthSegments', () => {
	it('returns percent segments in fixed order, dropping zeros', () => {
		const segs = healthSegments({ ok: 30, fail: 10, timeout: 10, nodata: 0, paused: 50 });
		expect(segs.map((s) => s.key)).toEqual(['ok', 'fail', 'timeout', 'paused']);
		expect(segs[0].pct).toBeCloseTo(30, 5);
		expect(segs[3].pct).toBeCloseTo(50, 5);
	});
	it('returns empty for an all-zero board', () => {
		expect(healthSegments({ ok: 0, fail: 0, timeout: 0, nodata: 0, paused: 0 })).toEqual([]);
	});
});
