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
 * Safely extracts a human-readable error message from an unknown error value.
 *
 * Handles common error shapes encountered throughout the app:
 * - `Error` instances (native JS errors)
 * - plain `string` messages
 * - API error responses shaped as `{ error: string }`
 * - `null`, `undefined`, and anything else
 */
export function getErrorMessage(err: unknown): string {
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

	return 'An unexpected error occurred';
}
