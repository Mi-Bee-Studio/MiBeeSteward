/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. You may use, modify, and redistribute it under
 * those terms; see LICENSE for the full text. A commercial license is available
 * for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

/**
 * Paraglide i18n wrapper.
 *
 * Provides type-safe message functions compiled by @inlang/paraglide-js.
 *
 * Usage:
 *   import { m, getLocale, setLocale } from '$lib/i18n-paraglide';
 *   m["navigation.Dashboard"]()     // "Dashboard" / "仪表盘"
 *   setLocale('en')
 *   getLocale()                     // "en"
 */
import {
	baseLocale,
	getLocale as pgGetLocale,
	setLocale as pgSetLocale,
	overwriteGetLocale,
	overwriteSetLocale
} from '../paraglide/runtime.js';
import type { Locale } from '../paraglide/runtime.js';

export { baseLocale };

export { m } from '../paraglide/messages.js';

/** Re-export message type helpers. */
export type { LocalizedString, Locale } from '../paraglide/runtime.js';

/** Storage key matching the existing i18n.ts convention. */
const STORAGE_KEY = 'lang';

/**
 * Resolve the current locale:
 *   1. localStorage (matching existing i18n.ts 'lang' key)
 *   2. navigator.language
 *   3. base locale ("en")
 */
function resolveLocale(): string {
	if (typeof localStorage !== 'undefined') {
		const stored = localStorage.getItem(STORAGE_KEY);
		if (stored === 'en' || stored === 'zh') return stored;
	}
	if (typeof navigator !== 'undefined') {
		const lang = navigator.language?.split('-')[0];
		if (lang === 'en' || lang === 'zh') return lang;
	}
	return baseLocale;
}

// Install custom locale resolution. resolveLocale() is narrowed to 'en' | 'zh'
// (matching baseLocale) above, so this is a safe Locale cast — not an `as any`.
overwriteGetLocale(() => resolveLocale() as Locale);

/**
 * Set the locale persistently.
 *
 * Saves to localStorage under the `lang` key and reloads the page
 * so all compiled messages reflect the new locale.
 */
export function setLocale(
	newLocale: string
	): void {
	if (newLocale !== 'en' && newLocale !== 'zh') return;
	localStorage.setItem(STORAGE_KEY, newLocale);
	// newLocale is now guaranteed 'en' | 'zh' — cast to Locale (the runtime
	// accepts the full Locale union which both satisfy), not `as any`.
	pgSetLocale(newLocale as Locale, { reload: false });
	window.location.reload();
}

/**
 * Get the current locale string ("en" | "zh").
 */
export function getLocale(): string {
	return pgGetLocale() as string;
}
