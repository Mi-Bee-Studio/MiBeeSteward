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

import { describe, it, expect } from 'vitest';
import { html, sanitizeUrl } from '$lib/utils/index';

describe('html tagged-template helper', () => {
	it('escapes a single interpolated value', () => {
		const out = html`<b>${'<script>alert(1)</script>'}</b>`;
		expect(out).toBe('<b>&lt;script&gt;alert(1)&lt;/script&gt;</b>');
	});

	it('keeps literal markup untouched', () => {
		const out = html`<span class="font-medium">hi</span>`;
		expect(out).toBe('<span class="font-medium">hi</span>');
	});

	it('escapes multiple interpolations', () => {
		const out = html`<a href="${'https://ok'}" title="${'x"onclick="y'}">${'z'}</a>`;
		// the quote in the title value is escaped so it cannot break the attribute
		expect(out).toContain('title="x&quot;onclick=&quot;y"');
		expect(out).toContain('href="https://ok"');
		expect(out).toContain('>z<');
	});

	it('handles null / undefined / number / boolean interpolations', () => {
		expect(html`<span>${null}</span>`).toBe('<span></span>');
		expect(html`<span>${undefined}</span>`).toBe('<span></span>');
		expect(html`<span>${42}</span>`).toBe('<span>42</span>');
		expect(html`<span>${true}</span>`).toBe('<span>true</span>');
	});

	it('has no interpolation passthrough when none given', () => {
		expect(html`<div></div>`).toBe('<div></div>');
	});

	// --- XSS regression cases (the reason this helper exists) ---

	it('neutralises an <img onerror> XSS payload in a DataTable-style column', () => {
		// Simulates a render callback that interpolates a malicious username.
		const username = '<img src=x onerror=alert(1)>';
		const out = html`<span class="font-medium">${username}</span>`;
		// No live tag survives: there is no `<img` element, only escaped text.
		// (The literal text "onerror=alert" may appear, but as inert element
		// content — what matters is it is not a live <img onerror> attribute.)
		expect(out).not.toContain('<img');
		expect(out).toContain('&lt;img src=x onerror=alert(1)&gt;');
	});

	it('neutralises a quote-breaking attribute-injection payload', () => {
		// Simulates `data-scan-id="${agentId}"` where agentId tries to break out.
		const agentId = 'x" onmouseover="alert(1)';
		const out = html`<button data-scan-id="${agentId}">scan</button>`;
		// The embedded quote is escaped, so onmouseover never becomes an attribute.
		expect(out).not.toContain('onmouseover="alert');
		expect(out).toContain('data-scan-id="x&quot; onmouseover=&quot;alert(1)"');
	});
});

describe('sanitizeUrl', () => {
	it('allows http, https, ftp, mailto schemes', () => {
		expect(sanitizeUrl('http://example.com')).toBe('http://example.com');
		expect(sanitizeUrl('https://example.com')).toBe('https://example.com');
		expect(sanitizeUrl('ftp://example.com')).toBe('ftp://example.com');
		expect(sanitizeUrl('mailto:a@b.com')).toBe('mailto:a@b.com');
	});

	it('allows scheme-relative and relative URLs', () => {
		expect(sanitizeUrl('//example.com')).toBe('//example.com');
		expect(sanitizeUrl('/api/v1/x')).toBe('/api/v1/x');
		expect(sanitizeUrl('#anchor')).toBe('#anchor');
		expect(sanitizeUrl('foo/bar')).toBe('foo/bar');
	});

	it('drops dangerous schemes (javascript:, data:, vbscript:)', () => {
		expect(sanitizeUrl('javascript:alert(1)')).toBe('');
		expect(sanitizeUrl('JAVASCRIPT:alert(1)')).toBe('');
		expect(sanitizeUrl('data:text/html,<script>alert(1)</script>')).toBe('');
		expect(sanitizeUrl('vbscript:msgbox')).toBe('');
	});

	it('returns empty for null / empty', () => {
		expect(sanitizeUrl('')).toBe('');
		expect(sanitizeUrl('   ')).toBe('');
	});
});
