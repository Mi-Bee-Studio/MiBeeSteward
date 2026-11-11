// Probe-page overview helpers: pure functions that turn the raw probe data
// (paths, quality tracks, episodes, per-status counts) into the compact
// chart-shaped views — the path matrix, the matrix heat tint, the episode
// 24h timeline strip, and the health stacked bar. UI-framework free so the
// layout math is unit-testable.

import type { ProbePathSample, ProbeQualityEpisode } from '$lib/types';

// --- Paths: 39-row table → one row per target ------------------------------

export type PathState = 'reached' | 'max_ttl' | 'error';

export interface PathCell {
	sample: ProbePathSample;
	state: PathState;
}

export interface PathGroupRow {
	targetId: number;
	targetName: string;
	/** newest sample per vantage, center first */
	cells: PathCell[];
	/** worst cell state in the group — drives the row's border */
	worst: PathState | null;
	/** newest trace time in the group */
	tracedAt: string;
}

export function pathState(p: ProbePathSample): PathState {
	if (p.end_state === 'reached') return 'reached';
	if (p.end_state === 'error') return 'error';
	return 'max_ttl';
}

const PATH_RANK: Record<PathState, number> = { reached: 0, max_ttl: 1, error: 2 };
const VANTAGE_ORDER = (v: string) => (v === 'center' ? 0 : 1);

/**
 * Collapse the newest-sample-per-(target, vantage) path list into one row
 * per target. Rows sort problem-first (error > max_ttl > reached, then
 * name); cells sort center-first then vantage token, newest sample wins
 * per vantage.
 */
export function groupPathsByTarget(paths: ProbePathSample[]): PathGroupRow[] {
	const map = new Map<number, PathGroupRow>();
	for (const p of paths) {
		let row = map.get(p.target_id);
		if (!row) {
			row = { targetId: p.target_id, targetName: p.target_name || String(p.target_id), cells: [], worst: null, tracedAt: '' };
			map.set(p.target_id, row);
		}
		if (!row.tracedAt || p.traced_at > row.tracedAt) row.tracedAt = p.traced_at;
		const existing = row.cells.find((c) => c.sample.vantage === p.vantage);
		if (existing) {
			if (p.traced_at >= existing.sample.traced_at) existing.sample = p;
		} else {
			row.cells.push({ sample: p, state: pathState(p) });
		}
	}
	const rows = [...map.values()];
	for (const r of rows) {
		r.cells.sort((a, b) => VANTAGE_ORDER(a.sample.vantage) - VANTAGE_ORDER(b.sample.vantage) || a.sample.vantage.localeCompare(b.sample.vantage));
		r.worst = r.cells.reduce<PathState | null>((w, c) => (!w || PATH_RANK[c.state] > PATH_RANK[w] ? c.state : w), null);
	}
	return rows.sort((a, b) => {
		const wa = a.worst ? PATH_RANK[a.worst] : -1;
		const wb = b.worst ? PATH_RANK[b.worst] : -1;
		return wb - wa || a.targetName.localeCompare(b.targetName);
	});
}

// --- Quality matrix: latency heat tint -------------------------------------

export type Heat = 'hot' | 'warm' | null;

/**
 * Per-index heat tint for one matrix column (the p50 values of every
 * vantage, same order as the rows). The BEST vantage is the baseline:
 * ≤1.8× calm, ≤3× warm, beyond hot. Fewer than two measurable values or a
 * non-positive minimum (0ms loopback rows) → no tint anywhere.
 */
export function latencyHeat(values: Array<number | null | undefined>): Heat[] {
	const nums = values.map((v) => (typeof v === 'number' && v > 0 ? v : null));
	const min = Math.min(...nums.filter((v): v is number => v !== null));
	if (!Number.isFinite(min) || min <= 0) return values.map(() => null);
	return nums.map((v) => {
		if (v === null) return null;
		const ratio = v / min;
		if (ratio > 3) return 'hot';
		if (ratio > 1.8) return 'warm';
		return null;
	});
}

// --- Episodes: 24h timeline strip ------------------------------------------

export interface EpisodeBar {
	leftPct: number;
	widthPct: number;
	/** error = notified AND still active; warn = everything else */
	cls: 'bar-error' | 'bar-warn';
	episode: ProbeQualityEpisode;
}

/**
 * Layout episodes over a [now-windowMs, now] strip. Episodes that started
 * before the window clamp to the left edge; active ones run to the right
 * edge. Bars under 0.75% wide widen to 0.75% so single-window episodes
 * stay visible. Non-overlapping episodes are dropped (the caller fetched a
 * wider window than the strip shows).
 */
export function episodeBars(episodes: ProbeQualityEpisode[], nowMs: number, windowMs = 24 * 3600 * 1000): EpisodeBar[] {
	const start = nowMs - windowMs;
	const t = (iso: string) => {
		const ms = Date.parse(iso);
		return Number.isFinite(ms) ? ms : start;
	};
	const bars: EpisodeBar[] = [];
	for (const e of episodes) {
		const s = t(e.started_at);
		const resolved = e.resolved_at ? t(e.resolved_at) : nowMs;
		const end = Math.max(resolved, s);
		if (end <= start) continue;
		const clampedStart = Math.max(s, start);
		// Keep at least a 0.75%-wide sliver visible: bars at the very right
		// edge pull back left so the min-width never overflows the strip.
		const leftPct = Math.min(((clampedStart - start) / windowMs) * 100, 99.25);
		const widthPct = Math.min(Math.max(((end - clampedStart) / windowMs) * 100, 0.75), 100 - leftPct);
		const active = !e.resolved_at;
		bars.push({
			leftPct,
			widthPct,
			cls: active && e.notified ? 'bar-error' : 'bar-warn',
			episode: e
		});
	}
	return bars.sort((a, b) => a.leftPct - b.leftPct);
}

export interface EpisodeAxisTick {
	/** horizontal position as % of the strip width */
	pct: number;
	/** tick time in ms — the caller formats it */
	atMs: number;
	/** tick sits on local midnight — the caller prefixes the date */
	midnight: boolean;
}

/**
 * Clock-aligned tick times for the episode strip's axis. Ticks land on
 * local-time boundaries (default every 6h) so a bar can be matched to
 * wall-clock time at a glance; ticks on local midnight set `midnight` so
 * the caller can show which day it is. Window edges are deliberately NOT
 * ticked: rolling "now/−24h" labels go stale between polls, clock-aligned
 * ones keep their meaning. Empty when the window is shorter than one step.
 */
export function episodeAxisTicks(nowMs: number, windowMs = 24 * 3600 * 1000, stepHours = 6): EpisodeAxisTick[] {
	const start = nowMs - windowMs;
	// Round the window start down to the hour, then advance to the next
	// local hour that is a multiple of stepHours (setHours keeps local
	// alignment across DST shifts; fixed-ms stepping would drift).
	const first = new Date(start);
	first.setMinutes(0, 0, 0);
	first.setHours(first.getHours() + ((stepHours - (first.getHours() % stepHours)) % stepHours));
	if (first.getTime() < start) first.setHours(first.getHours() + stepHours);
	const ticks: EpisodeAxisTick[] = [];
	for (const t = new Date(first); t.getTime() <= nowMs; t.setHours(t.getHours() + stepHours)) {
		ticks.push({ pct: ((t.getTime() - start) / windowMs) * 100, atMs: t.getTime(), midnight: t.getHours() === 0 });
	}
	return ticks;
}

// --- Health summary: stacked bar segments ----------------------------------

export type HealthKey = 'ok' | 'fail' | 'timeout' | 'nodata' | 'paused';

export interface HealthSeg {
	key: HealthKey;
	count: number;
	pct: number;
}

/**
 * Percent segments for the summary card's stacked bar (order: ok, fail,
 * timeout, nodata, paused). Zero-count segments are dropped; the total is
 * whatever the caller passes (pcts sum to ~100, rounding gaps are fine —
 * the bar uses flex weights, not absolute positioning).
 */
export function healthSegments(counts: Record<HealthKey, number>): HealthSeg[] {
	const total = Object.values(counts).reduce((a, b) => a + b, 0);
	if (total <= 0) return [];
	const order: HealthKey[] = ['ok', 'fail', 'timeout', 'nodata', 'paused'];
	return order.filter((k) => counts[k] > 0).map((k) => ({ key: k, count: counts[k], pct: (counts[k] / total) * 100 }));
}
