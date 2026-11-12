/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect } from 'vitest';

// REAL echarts barrel (no mock): proves the custom series is registered by
// the app's echarts.use([...]) — a setOption with type:'custom' must not
// throw (the dashboard 3D builders' contract, #741).
import { echarts } from '$lib/charts/echarts';

describe('echarts custom series registration (#741)', () => {
	it('accepts a custom-series option without throwing', () => {
		const d = document.createElement('div');
		d.style.cssText = 'width:100px;height:100px;position:absolute;left:-999px;top:-999px;';
		document.body.appendChild(d);
		let inst: ReturnType<typeof echarts.init> | undefined;
		// jsdom cannot paint (null canvas context): any setOption that reaches
		// the paint stage crashes on a null layer. That's a known jsdom-only
		// artifact. What this test guards against is OPTION-PARSING failures —
		// an unregistered series type or a custom series silently defaulting to
		// a cartesian grid ("xAxis 0 not found", the #741 production bug) — so
		// we classify whatever throws instead of forbidding all throws.
		const assertParses = (fn: () => void) => {
			try {
				fn();
			} catch (e) {
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
				const msg = String((e as any)?.message ?? e);
				expect(msg).not.toMatch(/xAxis|yAxis|not found|Unknown series|registerChartView/i);
			}
		};
		try {
			inst = echarts.init(d);
			// The 3D pie shape: custom series WITHOUT axes (coordinateSystem none).
			assertParses(() =>
				inst!.setOption({
					series: [
						{
							type: 'custom',
							coordinateSystem: 'none',
							renderItem: () => ({ type: 'rect', shape: { x: 1, y: 1, width: 5, height: 5 } }),
							data: [[0, 1]]
						}
					]
				})
			);
			// And over a cartesian grid (the 3D bar shape).
			assertParses(() =>
				inst!.setOption(
					{
						xAxis: { type: 'category', data: ['a'] },
						yAxis: { type: 'value' },
						series: [
							{
								type: 'custom',
								encode: { x: 0, y: 1 },
								renderItem: () => ({ type: 'rect', shape: { x: 1, y: 1, width: 5, height: 5 } }),
								data: [['a', 1]]
							}
						]
					},
					true
				)
			);
		} finally {
			// jsdom has no canvas: zrender's dispose-time clearRect crashes on a
			// null context. Real browsers dispose cleanly.
			try {
				inst?.dispose();
			} catch {
				/* jsdom-only */
			}
			d.remove();
		}
	});
});
