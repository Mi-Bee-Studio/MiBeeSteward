/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { getLocale } from '$lib/i18n-paraglide';

/**
 * Locale-aware date+time formatting. Uses the paraglide-selected locale (not the
 * browser default), so a Chinese-UI user on an English browser sees Chinese
 * dates (#168). Falls back to the raw input on parse failure, and to '-' for
 * empty/null/undefined — matching the per-page `formatTime` helpers this
 * replaces.
 */
export function formatDateTime(iso: string | number | Date | null | undefined): string {
	if (iso == null || iso === '') return '-';
	try {
		// `as any` because TS's lib.dom DateLocaleOptions typing varies across
		// versions; the runtime accepts the standard options object.
		const locale = getLocale();
		return new Date(iso).toLocaleString(locale === 'zh' ? 'zh-CN' : 'en-US');
	} catch {
		return String(iso);
	}
}

/**
 * Locale-aware time-only formatting (no date). Same locale behaviour as
 * formatDateTime; used by dashboard widgets that show just the clock time.
 */
export function formatTime(iso: string | number | Date | null | undefined): string {
	if (iso == null || iso === '') return '-';
	try {
		const locale = getLocale();
		return new Date(iso).toLocaleTimeString(locale === 'zh' ? 'zh-CN' : 'en-US');
	} catch {
		return String(iso);
	}
}

/**
 * Human-readable duration from milliseconds ("940ms" / "108.3s"), shared by
 * the scan-results run history and the dashboard scan-activity table — the
 * two surfaces used to disagree (raw ms vs formatted) for the same column
 * (#251).
 */
export function formatDuration(ms: number): string {
	if (ms < 1000) return `${ms}ms`;
	return `${(ms / 1000).toFixed(1)}s`;
}
