/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect } from 'vitest';
import { buildPie3d, buildVBar3d, buildHBar3d, mixColor } from '$lib/charts/chart3d';

describe('mixColor', () => {
	it('mixes toward white and black by ratio', () => {
		expect(mixColor('#000000', 1)).toBe('#ffffff');
		expect(mixColor('#ffffff', -1)).toBe('#000000');
		expect(mixColor('#808080', 0)).toBe('#808080');
		expect(mixColor('#ff0000', 0.5)).toBe('#ff8080');
	});

	it('handles short hex and passes through non-hex input', () => {
		expect(mixColor('#0f0', 0)).toBe('#00ff00');
		expect(mixColor('not-a-color', 0.5)).toBe('not-a-color');
	});
});

describe('buildPie3d', () => {
	const items = [
		{ name: '在线', value: 7, color: '#6366f1' },
		{ name: '离线', value: 2, color: '#ef4444' },
		{ name: '未知', value: 1, color: '#6b7280' }
	];

	it('builds a custom series with aligned data, legend, and tooltip', () => {
		const opt = buildPie3d(items, { legendColor: '#6b7280' });
		const series = opt.series as { type: string; data: { name: string; value: number }[] }[];
		expect(series).toHaveLength(1);
		expect(series[0].type).toBe('custom');
		expect(series[0].data.map((d) => d.name)).toEqual(['在线', '离线', '未知']);
		expect(series[0].data.map((d) => d.value)).toEqual([7, 2, 1]);
		expect(typeof (series[0] as { renderItem?: unknown }).renderItem).toBe('function');

		const legend = opt.legend as { data: string[]; selectedMode: boolean };
		expect(legend.data).toEqual(['在线', '离线', '未知']);
		// Display-only legend: selection filtering is not guaranteed for
		// custom series, so clicking must not be offered at all.
		expect(legend.selectedMode).toBe(false);

		const tooltip = opt.tooltip as { trigger: string; formatter: (p: { dataIndex: number }) => string };
		expect(tooltip.trigger).toBe('item');
		// Percent shape mirrors the 2D pies: "name: value (pct%)".
		expect(tooltip.formatter({ dataIndex: 0 })).toBe('在线: 7 (70%)');
		expect(tooltip.formatter({ dataIndex: 1 })).toBe('离线: 2 (20%)');
	});

	it('keeps zero-value items in legend/tooltip data but renders no slice', () => {
		const withZero = [...items, { name: '空', value: 0, color: '#000000' }];
		const opt = buildPie3d(withZero, { legendColor: '#6b7280' });
		const series = opt.series as { data: unknown[] }[];
		expect(series[0].data).toHaveLength(4);
		const legend = opt.legend as { data: string[] };
		expect(legend.data).toContain('空');
	});

	it('returns an empty option (no series) for all-zero input', () => {
		const opt = buildPie3d(
			[
				{ name: 'a', value: 0, color: '#000000' },
				{ name: 'b', value: 0, color: '#111111' }
			],
			{ legendColor: '#6b7280' }
		);
		expect(opt.series).toBeUndefined();
	});
});

describe('buildVBar3d', () => {
	const entries = [
		{ label: '机房', value: 12 },
		{ label: '办公室', value: 5 }
	];

	it('builds a custom series over a 2D grid with the axis labels kept', () => {
		const opt = buildVBar3d(entries, {
			color: '#6366f1',
			labelColor: '#6b7280',
			axisColor: '#1f2937',
			splitColor: '#1f293740',
			rotate: 30,
			truncate: 8
		});
		const series = opt.series as { type: string; encode: { x: number; y: number }; data: [string, number][] }[];
		expect(series).toHaveLength(1);
		expect(series[0].type).toBe('custom');
		expect(series[0].encode).toEqual({ x: 0, y: 1 });
		expect(series[0].data).toEqual([
			['机房', 12],
			['办公室', 5]
		]);
		const xAxis = opt.xAxis as { type: string; data: string[] };
		expect(xAxis.type).toBe('category');
		expect(xAxis.data).toEqual(['机房', '办公室']);
	});

	it('returns an empty option for no entries', () => {
		expect((buildVBar3d([], { color: '#000', labelColor: '', axisColor: '', splitColor: '' }).series)).toBeUndefined();
	});
});

describe('buildHBar3d', () => {
	const entries = [
		{ label: 'in_use', value: 9 },
		{ label: 'spare', value: 0 },
		{ label: 'retired', value: 3 }
	];

	it('builds a horizontal custom series with per-entry colors', () => {
		const opt = buildHBar3d(entries, {
			color: '#6366f1',
			colors: ['#34d399', '#6366f1', '#6b7280'],
			labelColor: '#6b7280',
			axisColor: '#1f2937',
			splitColor: '#1f293740',
			valueLabelColor: '#6b7280'
		});
		const series = opt.series as { type: string; encode: { x: number; y: number }; data: [string, number][] }[];
		expect(series[0].type).toBe('custom');
		// Horizontal bars: value on x, category on y.
		expect(series[0].encode).toEqual({ x: 1, y: 0 });
		expect(series[0].data).toEqual([
			['in_use', 9],
			['spare', 0],
			['retired', 3]
		]);
		const yAxis = opt.yAxis as { type: string; data: string[] };
		expect(yAxis.type).toBe('category');
		expect(yAxis.data).toEqual(['in_use', 'spare', 'retired']);
	});

	it('truncates long category labels with an ellipsis', () => {
		const opt = buildHBar3d([{ label: 'very-long-tag-name', value: 4 }], {
			color: '#6366f1',
			labelColor: '#6b7280',
			axisColor: '#1f2937',
			splitColor: '#1f293740',
			truncate: 10
		});
		const yAxis = opt.yAxis as { data: string[] };
		expect(yAxis.data[0]).toBe('very-long-...');
	});
});
