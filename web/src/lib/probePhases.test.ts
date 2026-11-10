import { describe, expect, it } from 'vitest';

import type { ProbePhaseRow } from '$lib/types';
import {
	PHASE_STAGES,
	hasPhaseData,
	phaseTracks,
	stageData,
	stageMs,
	ttlData
} from '$lib/probePhases';

const row = (over: Partial<ProbePhaseRow>): ProbePhaseRow =>
	({
		target_id: 1,
		module: 'http',
		vantage: 'center',
		checked_at: '2026-11-09T01:00:00Z',
		latency_ms: 50,
		...over
	}) as ProbePhaseRow;

describe('stageMs', () => {
	it('reads the four ms stages and defaults absent fields to 0', () => {
		const r = row({ dns_ms: 8, connect_ms: 20, tls_ms: 12, ttfb_ms: 5 });
		expect(stageMs(r, 'dns')).toBe(8);
		expect(stageMs(r, 'connect')).toBe(20);
		expect(stageMs(r, 'tls')).toBe(12);
		expect(stageMs(r, 'ttfb')).toBe(5);
		// tcp row: only connect measured
		const tcp = row({ module: 'tcp', connect_ms: 41 });
		expect(stageMs(tcp, 'dns')).toBe(0);
		expect(stageMs(tcp, 'connect')).toBe(41);
	});
});

describe('hasPhaseData', () => {
	it('is false for empty and stage-less rows', () => {
		expect(hasPhaseData([])).toBe(false);
		expect(hasPhaseData([row({ dns_ms: 0, connect_ms: 0 })])).toBe(false);
	});
	it('counts any measured stage, a reply TTL, or a resolved address', () => {
		expect(hasPhaseData([row({ ttfb_ms: 1 })])).toBe(true);
		expect(hasPhaseData([row({ module: 'icmp', reply_ttl: 54 })])).toBe(true);
		expect(hasPhaseData([row({ resolved_ip: '203.0.113.9' })])).toBe(true);
	});
});

describe('phaseTracks', () => {
	it('groups per vantage, center first, rows chronological', () => {
		// API order is newest-first.
		const rows = [
			row({ vantage: 'agent:rig', checked_at: '2026-11-09T01:00:30Z' }),
			row({ vantage: 'agent:rig', checked_at: '2026-11-09T01:00:00Z' }),
			row({ vantage: 'center', checked_at: '2026-11-09T01:00:20Z' })
		];
		const tracks = phaseTracks(rows);
		expect(tracks.map((t) => t.vantage)).toEqual(['center', 'agent:rig']);
		expect(tracks[1].rows.map((r) => r.checked_at)).toEqual([
			'2026-11-09T01:00:00Z',
			'2026-11-09T01:00:30Z'
		]);
	});
	it('treats an empty vantage as center', () => {
		const tracks = phaseTracks([row({ vantage: '' })]);
		expect(tracks[0].vantage).toBe('center');
	});
});

describe('stageData', () => {
	it('keeps every row (0-ms stages included) so stacks align on the time axis', () => {
		const track = { vantage: 'center', rows: [row({ dns_ms: 8 }), row({ dns_ms: 0 })] };
		const data = stageData(track, 'dns');
		expect(data).toHaveLength(2);
		expect(data[0].ms).toBe(8);
		expect(data[1].ms).toBe(0);
		expect(data[0].stage).toBe('dns');
	});
});

describe('ttlData', () => {
	it('filters to rows carrying a reply TTL', () => {
		const rows = [
			row({ module: 'icmp', reply_ttl: 54, checked_at: '2026-11-09T01:00:30Z' }),
			row({ module: 'icmp', checked_at: '2026-11-09T01:01:00Z' }),
			row({ module: 'http', dns_ms: 8 })
		];
		expect(ttlData(rows)).toEqual([['2026-11-09T01:00:30Z', 54]]);
	});
});

describe('PHASE_STAGES', () => {
	it('pins the draw order (bottom → top)', () => {
		expect([...PHASE_STAGES]).toEqual(['dns', 'connect', 'tls', 'ttfb']);
	});
});
