/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for
 * use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { marked } from 'marked';
import DOMPurify from 'dompurify';
import type { HtmlString } from './html.js';

// GFM covers tables/strikethrough/task lists (the docs-site flavor); `breaks`
// renders single newlines as <br> — matches how people actually write ops
// notes in plain editors.
marked.setOptions({ gfm: true, breaks: true });

// External links open in a new tab — markdown bodies routinely reference
// vendor docs, and navigating the SPA away would lose app state.
DOMPurify.addHook('afterSanitizeAttributes', (node) => {
	if (node.tagName === 'A' && node.getAttribute('href')) {
		node.setAttribute('target', '_blank');
		node.setAttribute('rel', 'noopener noreferrer');
	}
});

/**
 * renderMarkdown converts markdown source to sanitized HTML for a `{@html}`
 * sink (document preview). The returned HtmlString is safe by construction:
 * DOMPurify strips scripts, event handlers and javascript:/data: URLs, and
 * the surviving inline HTML is intentional — README-style documents mix
 * markdown with HTML fragments. Uploaded content is untrusted; sanitize here
 * is the ONLY rendering path for it (never `{@html}` raw file text).
 */
export function renderMarkdown(src: string): HtmlString {
	const raw = marked.parse(src ?? '', { async: false });
	return DOMPurify.sanitize(raw, {
		// DOMPurify's default profile already excludes scripts/iframes/forms.
		// input stays allowed — GFM task lists render as checkbox inputs
		// (event handlers are stripped regardless); everything else here is
		// belt-and-braces stating the intent for document previews.
		FORBID_TAGS: ['style', 'form', 'button', 'textarea', 'select', 'iframe', 'object', 'embed'],
		FORBID_ATTR: ['style']
	});
}
