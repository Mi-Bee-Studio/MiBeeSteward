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

import { escapeHtml } from './index.js';

/**
 * HtmlString brands a string that has already been escaped for safe insertion
 * into HTML (element text or a quoted attribute value). It is a type alias (not
 * a real brand) — the intent is to make the "this is already-safe HTML" contract
 * visible at DataTable `render` call sites. Build one with the {@link html}
 * tagged template; do NOT cast raw strings to it.
 */
export type HtmlString = string;

/**
 * Tagged-template HTML builder for DataTable `render` callbacks (and any other
 * `{@html}` sink). Every `${...}` interpolation is HTML-escaped (via
 * {@link escapeHtml}), while the literal template parts (markup like
 * `<span class="x">`) pass through untouched.
 *
 * This is the safe-by-default replacement for raw string concatenation in
 * render callbacks: a column like
 *
 *   render: (row) => `<span class="font-medium">${row.username}</span>`
 *
 * is an XSS vector (username is user-controlled), but
 *
 *   render: (row) => html`<span class="font-medium">${row.username}</span>`
 *
 * escapes username automatically. The same escaping covers attribute values
 * (e.g. `html\`<a href="${row.url}">\``), because escapeHtml escapes `"` too.
 *
 * If you need a value verbatim in the output WITHOUT escaping (e.g. nesting an
 * already-built HtmlString), use a second `html` call and interpolate its
 * result — but only for values you have already constructed safely. There is no
 * "opt out of escaping" escape hatch on purpose.
 *
 * @example
 * html`<span>${row.name}</span>`                      // escapes name
 * html`<a href="${url}" title="${name}">${label}</a>` // escapes url, name, label
 * html`<b>static</b>`                                  // no interpolation → verbatim
 */
export function html(strings: TemplateStringsArray, ...values: unknown[]): HtmlString {
	let out = strings[0];
	for (let i = 0; i < values.length; i++) {
		// String() coerces null/undefined/number/boolean/object to a string;
		// escapeHtml handles null/empty but its signature expects string.
		out += escapeHtml(String(values[i] ?? '')) + strings[i + 1];
	}
	return out;
}
