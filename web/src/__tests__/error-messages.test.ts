/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { describe, expect, it } from 'vitest';
import { getErrorMessage } from '$lib/utils/error';
import { m } from '$lib/i18n-paraglide';

// #569: backend errors are English literal strings and used to render raw
// into the localized UI. getErrorMessage now maps the known families to
// localized copy (asserted against m itself, so translated wording changes
// do not break these tests) and passes everything else through unchanged.
describe('getErrorMessage backend-string mapping (#569)', () => {
	it('maps the #317 reserved-address-space scan guard', () => {
		const raw = 'target in reserved address space: 127.0.0.1/32 is loopback';
		expect(getErrorMessage(new Error(raw))).toBe(m['errors.Reserved Target Space']());
		expect(getErrorMessage({ error: raw })).toBe(m['errors.Reserved Target Space']());
	});

	it('maps the same-password change guard', () => {
		expect(getErrorMessage(new Error('new password must be different'))).toBe(
			m['errors.Same Password']()
		);
	});

	it('maps the weak-password family (prefix with wrapped detail)', () => {
		expect(
			getErrorMessage(new Error('password does not meet requirements: min length 8'))
		).toBe(m['errors.Weak Password']());
	});

	it('maps the user-delete self guard (batch + single delete share the wording)', () => {
		expect(getErrorMessage('cannot delete yourself')).toBe(m['errors.Cannot Delete Self']());
	});

	it('maps the scan server-timeout guard', () => {
		expect(
			getErrorMessage('scan exceeded server timeout; reduce the target range or use the async task API')
		).toBe(m['errors.Scan Server Timeout']());
	});

	it('passes unknown backend strings through unchanged (operators keep exact diagnostics)', () => {
		expect(getErrorMessage(new Error('some future server string'))).toBe('some future server string');
	});

	it('falls back to the localized unknown-error text for non-message values', () => {
		expect(getErrorMessage(null)).toBe(m['errors.Unknown Error Desc']());
		expect(getErrorMessage(undefined)).toBe(m['errors.Unknown Error Desc']());
		expect(getErrorMessage(42)).toBe(m['errors.Unknown Error Desc']());
	});
});
