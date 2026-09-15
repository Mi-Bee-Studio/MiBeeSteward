/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 */

import { describe, it, expect } from 'vitest';
import {
	CRON_PRESETS,
	CUSTOM_KEY,
	cronForPresetKey,
	normalizeCron,
	presetKeyForCron
} from '$lib/utils/cron';

describe('cron presets', () => {
	it('every preset round-trips: preset key → cron → same key', () => {
		for (const p of CRON_PRESETS) {
			expect(cronForPresetKey(p.key)).toBe(p.cron);
			expect(presetKeyForCron(p.cron)).toBe(p.key);
		}
	});

	it('maps whitespace-padded expressions to their preset (edit round-trip)', () => {
		// Tasks saved long ago may carry extra spaces; the form must still
		// recognize them as a preset instead of dumping the user into custom.
		expect(presetKeyForCron('  0  2   * * * ')).toBe('daily_2am');
	});

	it('unknown expressions map to the CUSTOM sentinel, not a wrong preset', () => {
		expect(presetKeyForCron('*/5 8-20 * * 1-5')).toBe(CUSTOM_KEY);
		expect(presetKeyForCron('')).toBe(CUSTOM_KEY);
	});

	it('CUSTOM_KEY and unknown keys resolve to no expression', () => {
		expect(cronForPresetKey(CUSTOM_KEY)).toBeNull();
		expect(cronForPresetKey('nope')).toBeNull();
	});

	it('all preset expressions are distinct (a dropdown entry must mean one schedule)', () => {
		const crons = CRON_PRESETS.map((p) => p.cron);
		expect(new Set(crons).size).toBe(crons.length);
		const keys = CRON_PRESETS.map((p) => p.key);
		expect(new Set(keys).size).toBe(keys.length);
	});

	it('normalizeCron collapses runs of whitespace but preserves content', () => {
		expect(normalizeCron('0   2  *  *  *')).toBe('0 2 * * *');
		expect(normalizeCron('\t15 7 * * *\n')).toBe('15 7 * * *');
	});
});
