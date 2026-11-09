// Per-stage timing helpers (#717): pure functions that turn probe_phases rows
// into the stacked-chart shapes the results modal renders. Kept side-effect
// free (and UI-framework free) so the stacking math is unit-testable.

import type { ProbePhaseRow } from '$lib/types';

/** The ms stages a stacked bar can carry, in draw order (bottom → top). */
export const PHASE_STAGES = ['dns', 'connect', 'tls', 'ttfb'] as const;
export type PhaseStage = (typeof PHASE_STAGES)[number];

/** Stage ms off a row; absent stages (tcp/icmp rows) read as 0. */
export function stageMs(row: ProbePhaseRow, stage: PhaseStage): number {
	switch (stage) {
		case 'dns':
			return row.dns_ms ?? 0;
		case 'connect':
			return row.connect_ms ?? 0;
		case 'tls':
			return row.tls_ms ?? 0;
		case 'ttfb':
			return row.ttfb_ms ?? 0;
	}
}

/**
 * True when at least one row carries a measurable stage — the gate for even
 * showing the phases toggle in the history modal. reply_ttl-only icmp rows
 * count too: their view is the TTL series rather than a stack.
 */
export function hasPhaseData(rows: ProbePhaseRow[]): boolean {
	return rows.some(
		(r) =>
			PHASE_STAGES.some((s) => stageMs(r, s) > 0) ||
			(r.reply_ttl ?? 0) > 0 ||
			!!r.resolved_ip
	);
}

/**
 * Chronological per-vantage grouping (API rows arrive newest-first). Each
 * entry keeps its rows oldest → newest so charts read left-to-right.
 */
export interface PhaseTrack {
	vantage: string;
	rows: ProbePhaseRow[];
}

export function phaseTracks(rows: ProbePhaseRow[]): PhaseTrack[] {
	const map = new Map<string, ProbePhaseRow[]>();
	for (const r of rows) {
		const key = r.vantage || 'center';
		const list = map.get(key) ?? [];
		list.push(r);
		map.set(key, list);
	}
	const order = (v: string) => (v === 'center' ? 0 : 1);
	return [...map.entries()]
		.map(([vantage, list]) => ({ vantage, rows: list.reverse() }))
		.sort((a, b) => order(a.vantage) - order(b.vantage) || a.vantage.localeCompare(b.vantage));
}

/**
 * One stacked-bar datum: [time, ms, tooltip extras]. The tooltip payload is
 * what makes icmp rows useful in a ms chart (no bar, but hover shows TTL and
 * the resolved address).
 */
export interface PhaseDatum {
	time: string;
	stage: PhaseStage;
	ms: number;
	row: ProbePhaseRow;
}

/** Flatten a track into per-stage chronological data. */
export function stageData(track: PhaseTrack, stage: PhaseStage): PhaseDatum[] {
	return track.rows.map((row) => ({ time: row.checked_at, stage, ms: stageMs(row, stage), row }));
}

/**
 * The reply-TTL series (icmp): [time, ttl] points, one per row that has a
 * TTL. Empty for http/tcp-only targets — the caller hides the series.
 */
export function ttlData(rows: ProbePhaseRow[]): Array<[string, number]> {
	return rows.filter((r) => (r.reply_ttl ?? 0) > 0).map((r) => [r.checked_at, r.reply_ttl ?? 0]);
}
