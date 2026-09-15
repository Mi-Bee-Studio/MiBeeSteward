/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. See LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate; see
 * LICENSE-COMMERCIAL.md.
 */

/**
 * Cron scheduling presets for scanner tasks. Most operators don't know cron
 * syntax (and shouldn't have to) — the task form offers these as a dropdown
 * and only falls back to the raw-expression input when a task uses something
 * outside the preset set (CUSTOM_KEY). Pure data + pure functions so it is
 * unit-testable without i18n; the page maps preset.key → localized labels.
 */

export interface CronPreset {
	/** Stable identifier used by the form + label maps. */
	key: string;
	/** The 5-field cron expression the preset writes. */
	cron: string;
}

/** Sentinel key for "user is typing a raw cron expression". */
export const CUSTOM_KEY = 'custom';

export const CRON_PRESETS: CronPreset[] = [
	{ key: 'every_30m', cron: '*/30 * * * *' },
	{ key: 'hourly', cron: '0 * * * *' },
	{ key: 'every_6h', cron: '0 */6 * * *' },
	{ key: 'every_12h', cron: '0 */12 * * *' },
	{ key: 'daily_2am', cron: '0 2 * * *' },
	{ key: 'daily_4am', cron: '0 4 * * *' },
	{ key: 'weekly_mon_3am', cron: '0 3 * * 1' },
	{ key: 'monthly_1st_3am', cron: '0 3 1 * *' }
];

/** Normalizes whitespace so `0  2 * * *` and `0 2 * * *` compare equal. */
export function normalizeCron(expr: string): string {
	return expr.trim().split(/\s+/).join(' ');
}

/**
 * Reverse lookup: which preset (if any) produces this expression? Returns
 * CUSTOM_KEY for anything unrecognized so the form can round-trip arbitrary
 * existing tasks without data loss.
 */
export function presetKeyForCron(expr: string): string {
	const n = normalizeCron(expr);
	const hit = CRON_PRESETS.find((p) => p.cron === n);
	return hit ? hit.key : CUSTOM_KEY;
}

/** The cron expression a preset key writes (CUSTOM_KEY → null). */
export function cronForPresetKey(key: string): string | null {
	if (key === CUSTOM_KEY) return null;
	const hit = CRON_PRESETS.find((p) => p.key === key);
	return hit ? hit.cron : null;
}
