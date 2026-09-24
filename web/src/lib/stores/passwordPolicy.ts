/*
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
*/

/**
 * Effective password strength policy (#332 made auth.password_policy
 * admin-tunable; GET /api/v1/auth/password-policy serves it, public: strength
 * knobs only, no secrets). Client-side validation and hint text MUST follow
 * this, not hardcoded values: a UI-side min(8) silently blocks passwords the
 * backend (e.g. min_length lowered to 4) would accept: the exact
 * backend-evolved/frontend-stale drift class this store exists to prevent.
 */

import { get, writable } from 'svelte/store';
import { api } from '$lib/api/client';

export interface PasswordPolicy {
	min_length: number;
	require_uppercase: boolean;
	require_lowercase: boolean;
	require_digit: boolean;
	require_special: boolean;
}

// Must mirror the backend defaults (service.DefaultPasswordPolicy): used
// until the fetch resolves (and as the offline fallback).
export const DEFAULT_PASSWORD_POLICY: PasswordPolicy = {
	min_length: 8,
	require_uppercase: false,
	require_lowercase: false,
	require_digit: false,
	require_special: false
};

export const passwordPolicy = writable<PasswordPolicy>(DEFAULT_PASSWORD_POLICY);

let loadPromise: Promise<void> | null = null;

function fetchPolicy(): Promise<void> {
	return api
		.get<PasswordPolicy>('/auth/password-policy')
		.then((p) => {
			if (p && typeof p.min_length === 'number') passwordPolicy.set(p);
		})
		.catch(() => {
			/* keep defaults; backend enforces the real policy */
		});
}

// Fetch the effective policy once per session (single-flight). Failures keep
// the defaults: the backend still enforces the real policy on submit.
export function ensurePasswordPolicyLoaded(): Promise<void> {
	if (!loadPromise) {
		loadPromise = fetchPolicy();
	}
	return loadPromise;
}

// Force a re-fetch: the settings/security page calls this after PUT
// /settings/auth so the single-flight cache doesn't serve the stale
// pre-edit policy for the rest of the session.
export function refreshPasswordPolicy(): Promise<void> {
	loadPromise = fetchPolicy();
	return loadPromise;
}

// Snapshot for zod refines (evaluated at validation time, not import time).
export function currentPasswordPolicy(): PasswordPolicy {
	return get(passwordPolicy);
}
