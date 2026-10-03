/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.
 */

import { describe, it, expect, vi, beforeAll } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';

// The theme detection in the settings page reads prefers-color-scheme via
// window.matchMedia, which jsdom does not implement.
beforeAll(() => {
	Object.defineProperty(window, 'matchMedia', {
		writable: true,
		value: vi.fn().mockImplementation((query: string) => ({
			matches: false,
			media: query,
			onchange: null,
			addListener: vi.fn(),
			removeListener: vi.fn(),
			addEventListener: vi.fn(),
			removeEventListener: vi.fn(),
			dispatchEvent: vi.fn()
		}))
	});
});

const mocks = vi.hoisted(() => ({
	authState: {
		user: { id: 1, username: 'admin', email: 'admin@example.com', role: 'admin' },
		token: 'test-token'
	}
}));

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/stores/auth', () => ({
	auth: {
		subscribe: (fn: (s: typeof mocks.authState) => void) => {
			fn(mocks.authState);
			return () => {};
		},
		login: vi.fn(),
		logout: vi.fn(),
		setUser: vi.fn()
	}
}));
vi.mock('$lib/stores/toast', () => ({
	addToast: vi.fn()
}));

// GET routing: the hub fires /auth/profile + /auth/2fa/status on mount; the
// fingerprint section fires /fingerprints on first expansion. The other
// sections' data loads only when opened, so their endpoints resolve empty.
vi.mock('$lib/api/client', () => ({
	api: {
		get: vi.fn((url: string) => {
			if (url === '/auth/profile') {
				return Promise.resolve({ id: 1, username: 'admin', email: 'admin@example.com', role: 'admin' });
			}
			if (url === '/auth/2fa/status') return Promise.resolve({ enabled: false });
			if (url === '/fingerprints') {
				return Promise.resolve({
					source: 'embedded',
					rev: 'abcdef0123456789',
					rule_count: 2632,
					files: [{ name: 'banner.yaml', size: 7091 }],
					bytes: 7091,
					prev_available: false,
					uploads_enabled: true
				});
			}
			return Promise.resolve({});
		}),
		post: vi.fn(() => Promise.resolve({})),
		put: vi.fn(() => Promise.resolve({})),
		del: vi.fn(() => Promise.resolve({}))
	},
	ApiError: class ApiError extends Error {
		status = 0;
	}
}));

import Settings from '../routes/settings/+page.svelte';
import { api } from '$lib/api/client';
import { load as loadFingerprintsRedirect } from '../routes/settings/fingerprints/+page.ts';
import { load as loadNotificationsRedirect } from '../routes/settings/notifications/+page.ts';
import { load as loadSnmpRedirect } from '../routes/settings/snmp-credentials/+page.ts';
import { load as loadSecurityRedirect } from '../routes/settings/security/+page.ts';

const SECTION_IDS = [
	'profile',
	'password',
	'appearance',
	'2fa',
	'notifications',
	'snmp',
	'fingerprints',
	'security',
	'language'
] as const;

function panel(id: string): HTMLElement | null {
	return document.getElementById(`settings-panel-${id}`);
}

function hidden(el: HTMLElement | null): boolean {
	return !!el?.classList.contains('hidden');
}

describe('Settings page accordion', () => {
	it('renders all nine sections with only the default (profile) expanded', async () => {
		const { container } = render(Settings);
		await waitFor(() => expect(panel('profile')).toBeTruthy());

		for (const id of SECTION_IDS) {
			expect(container.querySelector(`#settings-${id}`), `section ${id}`).toBeTruthy();
		}

		// Default: profile open; every other section's content is lazy and
		// has not mounted at all.
		expect(hidden(panel('profile'))).toBe(false);
		expect(panel('password')).toBeNull();
		expect(panel('fingerprints')).toBeNull();
	});

	it('expands the fingerprint section in place and collapses the others', async () => {
		const { container } = render(Settings);
		await waitFor(() => expect(panel('profile')).toBeTruthy());

		await fireEvent.click(container.querySelector('#settings-fingerprints button')!);

		// The fingerprint content mounts and fetches its status; the profile
		// panel stays mounted (keep-alive) but is collapsed via CSS.
		await waitFor(() => expect(panel('fingerprints')).toBeTruthy());
		expect(api.get).toHaveBeenCalledWith('/fingerprints');
		expect(hidden(panel('fingerprints'))).toBe(false);
		expect(hidden(panel('profile'))).toBe(true);
	});

	it('re-toggling swaps the open section back', async () => {
		const { container } = render(Settings);
		await waitFor(() => expect(panel('profile')).toBeTruthy());

		await fireEvent.click(container.querySelector('#settings-fingerprints button')!);
		await waitFor(() => expect(panel('fingerprints')).toBeTruthy());

		await fireEvent.click(container.querySelector('#settings-profile button')!);
		expect(hidden(panel('profile'))).toBe(false);
		expect(hidden(panel('fingerprints'))).toBe(true);
	});
});

describe('Legacy settings sub-route redirects', () => {
	const cases: Array<[string, () => void, string]> = [
		['fingerprints', loadFingerprintsRedirect, '/settings#fingerprints'],
		['notifications', loadNotificationsRedirect, '/settings#notifications'],
		['snmp-credentials', loadSnmpRedirect, '/settings#snmp'],
		['security', loadSecurityRedirect, '/settings#security']
	];

	for (const [name, load, location] of cases) {
		it(`${name} redirects to the accordion hash`, () => {
			expect(() => load()).toThrowError(
				expect.objectContaining({ status: 307, location }) as unknown as Error
			);
		});
	}
});
