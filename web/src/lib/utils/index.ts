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

export { getErrorMessage } from './error.js';
export { html } from './html.js';
export type { HtmlString } from './html.js';

/** escapeHtml escapes a string for safe interpolation into an HTML context
 *  (element text or a single- or double-quoted attribute value). DataTable
 *  columns render via {@html}, so any user-controlled field (device name,
 *  location, vendor, MAC, …) must be escaped before being placed into the
 *  template string — otherwise a name containing `"` breaks the surrounding
 *  `data-name="..."` attribute and a name containing `<` is an XSS vector.
 *
 *  The order matters: ampersand must be escaped first.
 */
export function escapeHtml(s: string): string {
	if (s == null) return '';
	return String(s)
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

/** escapeAttr is an alias for escapeHtml clarifying intent at call sites that
 *  build attribute strings (e.g. `data-name="${escapeAttr(name)}"`). */
export const escapeAttr = escapeHtml;

/**
 * sanitizeUrl returns the URL if it uses a safe scheme (http/https/ftp/mailto,
 * case-insensitive) or is a relative/anchor path, and '' otherwise. This is a
 * defense-in-depth guard for `href="${sanitizeUrl(url)}"` interpolations: even
 * though escapeHtml neutralises quote-breaking, a `javascript:` URL would still
 * execute on click, so unsafe schemes must be dropped before reaching the DOM.
 * Callers should treat an empty result as "no link" (render the text verbatim).
 */
export function sanitizeUrl(url: string): string {
	if (url == null) return '';
	const trimmed = String(url).trim();
	if (trimmed === '') return '';
	// Relative paths, anchors, and protocol-free URLs are safe.
	if (/^[a-z]+:/i.test(trimmed)) {
		// Has a scheme — allow only the known-safe ones.
		if (/^(https?|ftp|mailto):/i.test(trimmed)) return trimmed;
		return ''; // javascript:, data:, vbscript:, etc.
	}
	return trimmed; // relative (#foo, /foo, foo/bar) — safe
}
