/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for
 * use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '$lib/utils/markdown';

describe('renderMarkdown', () => {
	it('renders GFM structure (headings, lists, code, tables)', () => {
		const out = renderMarkdown('# Title\n\n- item\n\n```bash\nls -la\n```\n\n| a | b |\n| - | - |\n| 1 | 2 |');
		expect(out).toContain('<h1>Title</h1>');
		expect(out).toContain('<li>item</li>');
		expect(out).toContain('<pre><code class="language-bash">ls -la');
		expect(out).toContain('<table>');
		expect(out).toContain('<td>2</td>');
	});

	it('strips script tags, event handlers and javascript: URLs', () => {
		const out = renderMarkdown(
			'# ok\n\n<script>alert(1)</' + 'script>\n\n<img src=x onerror="alert(1)">\n\n[a](javascript:alert(1))'
		);
		expect(out).toContain('<h1>ok</h1>');
		expect(out).not.toContain('alert(1)');
		expect(out).not.toContain('<script');
		expect(out).not.toContain('onerror');
		expect(out).not.toContain('javascript:');
	});

	it('opens links in a new tab with rel=noopener', () => {
		const out = renderMarkdown('[docs](https://example.com/x)');
		expect(out).toContain('href="https://example.com/x"');
		expect(out).toContain('target="_blank"');
		expect(out).toContain('rel="noopener noreferrer"');
	});

	it('renders task-list checkboxes (GFM)', () => {
		const out = renderMarkdown('- [x] done\n- [ ] todo');
		expect(out).toContain('type="checkbox"');
		expect(out).toContain('checked');
	});

	it('renders inline HTML fragments that survive sanitization', () => {
		const out = renderMarkdown('<div class="note">plain div is fine</div>');
		expect(out).toContain('plain div is fine');
	});

	it('handles empty and null-ish input', () => {
		expect(renderMarkdown('')).toBe('');
		expect(renderMarkdown(undefined as unknown as string)).toBe('');
	});
});
