/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * Isometric pseudo-3D option builders for the dashboard's 2D/3D chart
 * toggle. Purely custom-series canvas drawing (zrender polygons), so it
 * needs NO extra dependency: echarts-gl is not echarts-6-compatible and
 * three.js would be disproportionate for widget-sized cards.
 *
 * All builders are pure functions over fully-resolved inputs (colors are
 * hex strings resolved from CSS vars by the caller), which keeps them
 * unit-testable without an echarts runtime.
 */

import type { EChartsOption } from '$lib/charts/echarts';

// ── Color helpers ────────────────────────────────────────────────────────────

/** Parse #rgb / #rrggbb; null when the input is not a plain hex literal. */
function parseHex(hex: string): [number, number, number] | null {
	const m = /^#([0-9a-f]{6}|[0-9a-f]{3})$/i.exec(hex.trim());
	if (!m) return null;
	let s = m[1];
	if (s.length === 3) s = s[0] + s[0] + s[1] + s[1] + s[2] + s[2];
	return [parseInt(s.slice(0, 2), 16), parseInt(s.slice(2, 4), 16), parseInt(s.slice(4, 6), 16)];
}

const toHex = (n: number) => Math.round(n).toString(16).padStart(2, '0');

/**
 * Mix a hex color toward white (ratio>0) or black (ratio<0). ratio 1 / -1
 * returns the pure target; unparseable input passes through untouched (the
 * caller resolved theme CSS vars, but stay defensive).
 */
export function mixColor(hex: string, ratio: number): string {
	const rgb = parseHex(hex);
	if (!rgb) return hex;
	const target = ratio >= 0 ? [255, 255, 255] : [0, 0, 0];
	const r = Math.min(Math.abs(ratio), 1);
	const [nr, ng, nb] = rgb.map((c, i) => c + (target[i] - c) * r);
	return `#${toHex(nr)}${toHex(ng)}${toHex(nb)}`;
}

const tint = (hex: string, r: number) => mixColor(hex, r);
const shade = (hex: string, r: number) => mixColor(hex, -r);

// ── Shared shape ─────────────────────────────────────────────────────────────

export interface Pie3dItem {
	name: string;
	value: number;
	color: string;
}

export interface Bar3dEntry {
	label: string;
	value: number;
}

export interface Bar3dStyle {
	color: string;
	/** Per-entry bar color overrides (indexed like entries). */
	colors?: string[];
	labelColor: string;
	axisColor: string;
	splitColor: string;
	valueLabelColor?: string;
	/** Vertical-bar x-label rotation in degrees. */
	rotate?: number;
	/** Max label characters before ellipsis truncation. */
	truncate?: number;
}

type Pt = [number, number];

/** Render-marked empty option: Chart.svelte shows its EmptyState for it. */
function emptyOption(): EChartsOption {
	return { backgroundColor: 'transparent' };
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type RenderItem = (params: any, api: any) => any;

const polygon = (points: Pt[], fill: string) => ({
	type: 'polygon',
	shape: { points },
	style: { fill }
});

const truncate = (label: string, max?: number) =>
	max != null && label.length > max ? label.substring(0, max) + '...' : label;

// ── 3D pie ───────────────────────────────────────────────────────────────────

// Screen-coordinate parametrization: angle θ grows clockwise VISUALLY
// (y grows downward), θ = -π/2 is the top of the screen — matching the
// default startAngle of the 2D pies.
const piePoint = (cx: number, cy: number, rx: number, ry: number, a: number): Pt => [
	cx + rx * Math.cos(a),
	cy + ry * Math.sin(a)
];

/**
 * Isometric extruded pie (the classic 3D饼图 look): elliptical top face,
 * outer rim wall, and the two radial cut faces per slice. Slices are drawn
 * far-to-near (ascending screen-y of the mid angle) so the painter's order
 * reads correctly; the extrusion depth is kept ≤ ry so back walls stay
 * hidden behind the pie body.
 *
 * Legend is display-only (selectedMode: false): custom series does not
 * guarantee legend selection filtering, and a dead click is worse than no
 * click. Detail lives in the tooltip, which keeps the 2D pie's
 * "name: value (pct%)" shape.
 */
export function buildPie3d(items: Pie3dItem[]): EChartsOption {
	const total = items.reduce((a, it) => a + Math.max(0, it.value), 0);
	if (total <= 0) return emptyOption();

	// Per-slice geometry in DATA order: clockwise from the top, spans
	// proportional to value.
	interface SliceGeo {
		a1: number;
		a2: number;
		/** Painter's-order rank: 0 = farthest, drawn first. */
		rank: number;
	}
	const geo: (SliceGeo | null)[] = [];
	let cursor = -Math.PI / 2;
	for (const it of items) {
		if (it.value <= 0) {
			geo.push(null);
			continue;
		}
		const span = (it.value / total) * Math.PI * 2;
		geo.push({ a1: cursor, a2: cursor + span, rank: 0 });
		cursor += span;
	}
	// Depth order: far slices (mid angle toward the top of the screen,
	// sin(mid) < 0) first, near slices last.
	const visible = geo
		.map((g, i) => ({ g, i, depth: g ? Math.sin((g.a1 + g.a2) / 2) : 0 }))
		.filter((e) => e.g !== null)
		.sort((p, q) => p.depth - q.depth);
	visible.forEach((e, rank) => {
		e.g!.rank = rank;
	});
	if (visible.length === 0) return emptyOption();

	const renderItem: RenderItem = (params, api) => {
		const idx = params.dataIndex as number;
		const it = items[idx];
		const g = geo[idx];
		if (!it || !g) return; // zero-value slices carry no geometry

		const w = api.getWidth() as number;
		const h = api.getHeight() as number;
		const cx = w * 0.4;
		const cy = h * 0.48;
		const rx = Math.min(w * 0.27, h * 0.32);
		const ry = rx * 0.45;
		const depth = Math.min(rx * 0.18, ry * 0.9);

		// Sample the elliptical arc finely enough that chords read as a curve.
		const steps = Math.max(8, Math.ceil((g.a2 - g.a1) / (Math.PI / 24)));
		const arc = (yOff = 0): Pt[] => {
			const pts: Pt[] = [];
			for (let i = 0; i <= steps; i++) {
				const a = g.a1 + ((g.a2 - g.a1) * i) / steps;
				pts.push(piePoint(cx, cy + yOff, rx, ry, a));
			}
			return pts;
		};

		const topArc = arc();
		const bottomArc = arc(depth);
		// Within a slice, walls sit under the cut faces, which sit under the
		// top face; ranks are spaced so neighboring slices interleave correctly.
		const baseZ = g.rank * 10;
		const children: unknown[] = [
			// Outer rim wall: top arc forward, bottom arc back.
			{
				type: 'polygon',
				z: baseZ,
				shape: { points: [...topArc, ...bottomArc.reverse()] },
				style: { fill: shade(it.color, 0.38) }
			},
			// Radial cut faces — visible only when the edge points toward the
			// viewer (screen-y positive); otherwise they would stick out of the
			// body's back.
			...[g.a1, g.a2]
				.filter((a) => Math.sin(a) > 0)
				.map((a) => ({
					type: 'polygon',
					z: baseZ + 1,
					shape: {
						points: [
							[cx, cy],
							piePoint(cx, cy, rx, ry, a),
							piePoint(cx, cy + depth, rx, ry, a)
						]
					},
					style: { fill: shade(it.color, 0.22) }
				})),
			// Top face: sampled elliptical sector; stroked in its own color so
			// adjacent slices have no hairline seams.
			{
				type: 'polygon',
				z: baseZ + 2,
				shape: { points: [[cx, cy], ...topArc] },
				style: { fill: it.color, stroke: it.color, lineWidth: 1 }
			}
		];

		// Name + percent label on the top face when the slice is wide enough.
		// 0.4 rad ≈ 6.4% share: below that, labels collide on many-slice pies
		// (the 62.40 eight-type pie) — the tooltip still names every slice.
		// (The legend component collects per-SERIES names only — legend.data
		// entries matching data-item names never render for custom series —
		// so the slice label is the only on-chart name mapping in 3D mode.)
		if (g.a2 - g.a1 >= 0.4) {
			const p = piePoint(cx, cy, rx * 0.62, ry * 0.62, (g.a1 + g.a2) / 2);
			const pct = Math.round((it.value / total) * 100);
			const text = it.name.length <= 6 ? `${it.name} ${pct}%` : `${pct}%`;
			children.push({
				type: 'text',
				silent: true,
				z: baseZ + 3,
				style: {
					text,
					x: p[0],
					y: p[1],
					align: 'center',
					verticalAlign: 'middle',
					fill: '#ffffff',
					font: '600 11px sans-serif'
				}
			});
		}

		return { type: 'group', children };
	};

	const pctFormatter = (p: { dataIndex: number }) => {
		const it = items[p.dataIndex];
		if (!it) return '';
		const pct = total > 0 ? Math.round((it.value / total) * 100) : 0;
		return `${it.name}: ${it.value} (${pct}%)`;
	};

	return {
		backgroundColor: 'transparent',
		tooltip: { trigger: 'item', formatter: pctFormatter },
		// No legend: echarts collects legend entries per SERIES for custom
		// series (legend.data matched against data-item names never renders),
		// so the slice labels carry the name mapping instead.
		series: [
			{
				type: 'custom',
				renderItem,
				data: items.map((it) => ({ name: it.name, value: it.value })),
				// Custom series defaults to a cartesian grid — without axes in the
				// option the first setOption throws ("xAxis 0 not found"). The pie
				// lays itself out from api.getWidth/getHeight instead.
				coordinateSystem: 'none'
			}
		]
	} as EChartsOption;
}

// ── 3D bars (vertical / horizontal) ──────────────────────────────────────────

// Fixed isometric offset for the extrusion, in pixels — small enough for
// widget-sized cards.
const DX = 9;
const DY = 5;

/**
 * Vertical isometric bars over a 2D cartesian grid: cuboid = front rect +
 * top parallelogram + right parallelogram. Axes stay 2D for readability.
 */
export function buildVBar3d(entries: Bar3dEntry[], style: Bar3dStyle): EChartsOption {
	// All-zero input reads as "no data" (the 2D builders' contract): rendering
	// an empty 3D grid would show bare axes where 2D shows the EmptyState.
	if (entries.length === 0 || !entries.some((e) => e.value > 0)) return emptyOption();

	const renderItem: RenderItem = (params, api) => {
		const idx = params.dataIndex as number;
		const value = api.value(1) as number;
		if (!Number.isFinite(value) || value <= 0) return;

		const pt = api.coord([idx, value]) as Pt;
		const y0 = api.coord([idx, 0])[1] as number;
		const band = api.size([1, 0])[0] as number;
		const bw = Math.min(band * 0.5, 42);
		const x = pt[0];
		const yV = pt[1];
		if (y0 - yV < 1) return;

		const color = style.colors?.[idx] ?? style.color;
		return {
			type: 'group',
			children: [
				// Right side face.
				polygon(
					[
						[x + bw / 2, yV],
						[x + bw / 2 + DX, yV - DY],
						[x + bw / 2 + DX, y0 - DY],
						[x + bw / 2, y0]
					],
					shade(color, 0.28)
				),
				// Front face.
				polygon(
					[
						[x - bw / 2, yV],
						[x + bw / 2, yV],
						[x + bw / 2, y0],
						[x - bw / 2, y0]
					],
					color
				),
				// Top face.
				polygon(
					[
						[x - bw / 2, yV],
						[x + bw / 2, yV],
						[x + bw / 2 + DX, yV - DY],
						[x - bw / 2 + DX, yV - DY]
					],
					tint(color, 0.35)
				)
			]
		};
	};

	return {
		backgroundColor: 'transparent',
		tooltip: { trigger: 'axis' },
		grid: { left: '3%', right: '4%', top: 18, bottom: '3%', containLabel: true },
		xAxis: {
			type: 'category',
			data: entries.map((e) => e.label),
			axisLabel: {
				color: style.labelColor,
				fontSize: 11,
				rotate: style.rotate ?? 0,
				formatter: (v: string) => truncate(v, style.truncate)
			},
			axisLine: { lineStyle: { color: style.axisColor } }
		},
		yAxis: {
			type: 'value',
			axisLabel: { color: style.labelColor },
			splitLine: { lineStyle: { color: style.splitColor } }
		},
		series: [
			{
				type: 'custom',
				renderItem,
				data: entries.map((e) => [e.label, e.value]),
				encode: { x: 0, y: 1 }
			}
		]
	} as EChartsOption;
}

/**
 * Horizontal isometric bars (mirrors the 2D lifecycle/tag cards): extruded
 * toward the upper-right, value label kept after the cap.
 */
export function buildHBar3d(entries: Bar3dEntry[], style: Bar3dStyle): EChartsOption {
	// All-zero input reads as "no data" (the 2D builders' contract).
	if (entries.length === 0 || !entries.some((e) => e.value > 0)) return emptyOption();

	const renderItem: RenderItem = (params, api) => {
		const idx = params.dataIndex as number;
		const value = api.value(1) as number;
		if (!Number.isFinite(value) || value <= 0) return;

		const pt = api.coord([value, idx]) as Pt;
		const x0 = api.coord([0, idx])[0] as number;
		const band = api.size([0, 1])[1] as number;
		const bh = Math.min(band * 0.55, 20);
		const xV = pt[0];
		const y = pt[1];
		if (xV - x0 < 1) return;

		const color = style.colors?.[idx] ?? style.color;
		const children: unknown[] = [
			// Right cap face.
			polygon(
				[
					[xV, y - bh / 2],
					[xV + DX, y - bh / 2 - DY],
					[xV + DX, y + bh / 2 - DY],
					[xV, y + bh / 2]
				],
				shade(color, 0.28)
			),
			// Front face.
			polygon(
				[
					[x0, y - bh / 2],
					[xV, y - bh / 2],
					[xV, y + bh / 2],
					[x0, y + bh / 2]
				],
				color
			),
			// Top face.
			polygon(
				[
					[x0, y - bh / 2],
					[xV, y - bh / 2],
					[xV + DX, y - bh / 2 - DY],
					[x0 + DX, y - bh / 2 - DY]
				],
				tint(color, 0.35)
			)
		];
		if (style.valueLabelColor) {
			children.push({
				type: 'text',
				silent: true,
				style: {
					text: String(value),
					x: xV + DX + 6,
					y: y - DY,
					align: 'left',
					verticalAlign: 'middle',
					fill: style.valueLabelColor,
					font: '11px sans-serif'
				}
			});
		}
		return { type: 'group', children };
	};

	return {
		backgroundColor: 'transparent',
		tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
		grid: { left: '3%', right: '8%', top: '3%', bottom: '3%', containLabel: true },
		xAxis: {
			type: 'value',
			axisLabel: { color: style.labelColor },
			splitLine: { lineStyle: { color: style.splitColor } }
		},
		yAxis: {
			type: 'category',
			data: entries.map((e) => truncate(e.label, style.truncate)),
			axisLabel: { color: style.labelColor, fontSize: 11 },
			axisLine: { lineStyle: { color: style.axisColor } }
		},
		series: [
			{
				type: 'custom',
				renderItem,
				data: entries.map((e) => [e.label, e.value]),
				encode: { x: 1, y: 0 }
			}
		]
	} as EChartsOption;
}
