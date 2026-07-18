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

import { writable } from 'svelte/store';

interface User {
	id: number;
	username: string;
	email: string;
	role: string;
}
function createAuthStore() {
	// Try to restore from localStorage on init
	let initialUser: User | null = null;
	let initialToken: string | null = null;
	try {
		const stored = localStorage.getItem('auth');
		if (stored) {
			const parsed = JSON.parse(stored);
			initialUser = parsed.user ?? null;
			initialToken = parsed.token ?? null;
		}
	} catch {
		// localStorage not available (SSR) or invalid JSON
	}

	const { subscribe, set, update } = writable<{ user: User | null; token: string | null }>({
		user: initialUser,
		token: initialToken
	});

	function persist(user: User | null, token: string | null) {
		try {
			if (token && user) {
				localStorage.setItem('auth', JSON.stringify({ user, token }));
			} else {
				localStorage.removeItem('auth');
			}
		} catch {
			// localStorage not available
		}
	}

	return {
		subscribe,
		login: (user: User, token?: string) => {
			const t = token ?? null;
			persist(user, t);
			set({ user, token: t });
		},
		logout: () => {
			persist(null, null);
			set({ user: null, token: null });
		},
		setUser: (user: User) => update((s) => {
			persist(user, s.token);
			return { ...s, user };
		})
	};
}

export const auth = createAuthStore();
export type { User };
