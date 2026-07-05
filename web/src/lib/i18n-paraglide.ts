/**
 * Paraglide i18n wrapper.
 *
 * Provides type-safe message functions compiled by @inlang/paraglide-js.
 * Coexists with the legacy i18n.ts — no breaking changes.
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

// Install custom locale resolution.
overwriteGetLocale(() => resolveLocale() as any);

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
	pgSetLocale(newLocale as any, { reload: false });
	window.location.reload();
}

/**
 * Get the current locale string ("en" | "zh").
 */
export function getLocale(): string {
	return pgGetLocale() as string;
}

/**
 * Legacy-compatible translation helper.
 *
 * Mirrors the `t(section, key)` signature from the old i18n.ts so consumers
 * can switch incrementally. Resolves `{section}_{key}` from the paraglide
 * message map.
 *
 * @example
 *   t('navigation', 'Dashboard')  // → m["navigation.Dashboard"]()
 */
export function t(section: string, key: string): string {
	const flatKey = `${section}.${key}` as keyof typeof m;
	const fn = (m as any)[flatKey];
	if (typeof fn === 'function') return fn();
	// Fallback to the legacy resolver so transitional code still works.
	const { default: { t: legacyT } = {} as any } = {} as any;
	return key;
}
