/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { m } from '$lib/i18n-paraglide';

/**
 * Backend errors arrive as English literal strings (the API has no error
 * codes on the wire yet), and toasts/banners rendered them raw into the
 * Chinese UI (#569). The entries below map the strings users actually hit —
 * matched case-insensitively by prefix — to localized copy. An unrecognized
 * message keeps its original server wording: operators still get the exact
 * diagnostic text instead of a generic blanket translation. When the API
 * grows error codes, this table is the single place to swap.
 */
const BACKEND_ERROR_MAP: Array<[prefix: string, message: () => string]> = [
	// #317 scanner guard: "target in reserved address space: 127.0.0.1/32 is loopback"
	['target in reserved address space', () => m['errors.Reserved Target Space']()],
	// ErrSamePassword (forced/admin password change)
	['new password must be different', () => m['errors.Same Password']()],
	// ErrWeakPassword family (validatePassword wraps the rule as detail)
	['password does not meet requirements', () => m['errors.Weak Password']()],
	// Batch + single user delete self-guard
	['cannot delete yourself', () => m['errors.Cannot Delete Self']()],
	// Scanner write-timeout guard
	['scan exceeded server timeout', () => m['errors.Scan Server Timeout']()],
	['invalid credentials', () => m['errors.Invalid Credentials']()]
];

/**
 * Safely extracts a human-readable error message from an unknown error value.
 *
 * Handles common error shapes encountered throughout the app:
 * - `Error` instances (native JS errors)
 * - plain `string` messages
 * - API error responses shaped as `{ error: string }`
 * - `null`, `undefined`, and anything else
 *
 * Known backend strings are localized (see BACKEND_ERROR_MAP); everything
 * else surfaces as-is.
 */
export function getErrorMessage(err: unknown): string {
	const raw = extractErrorMessage(err);
	const lower = raw.toLowerCase();
	for (const [prefix, message] of BACKEND_ERROR_MAP) {
		if (lower.startsWith(prefix)) {
			return message();
		}
	}
	return raw;
}

function extractErrorMessage(err: unknown): string {
	if (err instanceof Error) {
		return err.message;
	}

	if (typeof err === 'string') {
		return err;
	}

	if (typeof err === 'object' && err !== null && 'error' in err) {
		const maybe = (err as Record<string, unknown>).error;
		if (typeof maybe === 'string') {
			return maybe;
		}
	}

	return m['errors.Unknown Error Desc']();
}
