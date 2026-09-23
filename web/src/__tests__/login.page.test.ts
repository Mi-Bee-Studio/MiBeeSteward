/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';

// Mock the modules with external behavior so the page module loads cleanly
// under jsdom. The api methods resolve (not reject) by default: the page's
// onMount polls /auth/setup-status and pre-fetches the password policy, and a
// mock returning undefined outright would explode on .then() before the
// render-level assertions even run.
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
// The auth store must be controllable per-test: the #430 redirect check reads
// it imperatively (get(auth)) at mount. A hoisted mutable state + store-shaped
// object lets each test set the session without localStorage ordering games.
const authMock = vi.hoisted(() => {
	const state = {
		user: null as null | { id: number; username: string; email: string; role: string },
		token: null as string | null
	};
	return {
		state,
		auth: {
			subscribe: (fn: (s: typeof state) => void) => {
				fn(state);
				return () => {};
			},
			login: vi.fn(),
			logout: vi.fn(),
			setUser: vi.fn()
		}
	};
});
vi.mock('$lib/stores/auth', () => ({ auth: authMock.auth }));
vi.mock('$lib/api/client', () => ({
	api: {
		get: vi.fn(() => Promise.resolve(undefined)),
		post: vi.fn(() => Promise.resolve(undefined)),
		put: vi.fn(() => Promise.resolve(undefined)),
		del: vi.fn(() => Promise.resolve(undefined))
	},
	ApiError: class ApiError extends Error {
		status = 0;
	},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

// login page must be imported AFTER the vi.mock calls so the mocks take effect.
import Login from '../routes/login/+page.svelte';
import { api } from '$lib/api/client';
import { goto } from '$app/navigation';

describe('Login page', () => {
	it('mounts and renders the credential form (username + password)', () => {
		const { container } = render(Login);

		// The default login view shows a username (text) + password input.
		expect(container.querySelector('input[type="text"]')).toBeTruthy();
		expect(container.querySelector('input[type="password"]')).toBeTruthy();
		// And a submit button to send the credentials.
		expect(container.querySelector('button[type="submit"]')).toBeTruthy();
	});

	it('does not show the 2FA or force-password views on initial render', () => {
		const { container } = render(Login);

		// The 2FA code field (inputmode numeric, maxlength 6) is conditional;
		// absent until a 2FA challenge is returned. Absence on mount is the
		// contract that the default credential form is the initial view.
		const twoFactorInput = container.querySelector('input[inputmode="numeric"][maxlength="6"]');
		expect(twoFactorInput).toBeFalsy();
	});

	// First-run setup: when the bootstrap admin has no password yet
	// (/auth/setup-status → required), the login form is REPLACED by the
	// create-admin-password form: nothing to log in with.
	it('renders the setup form instead of the login form when setup is pending', async () => {
		vi.mocked(api.get).mockImplementation((path: string) =>
			path === '/auth/setup-status'
				? Promise.resolve({ required: true })
				: Promise.resolve(undefined)
		);

		const { container } = render(Login);

		await waitFor(() => {
			expect(container.querySelector('#setup-new-password')).toBeTruthy();
		});
		// The credential form is hidden: there is no password to enter yet.
		expect(container.querySelector('input[type="text"]')).toBeFalsy();
	});

	it('submits the setup form to /auth/setup and enters the app', async () => {
		vi.mocked(api.get).mockImplementation((path: string) =>
			path === '/auth/setup-status'
				? Promise.resolve({ required: true })
				: Promise.resolve(undefined)
		);
		vi.mocked(api.post).mockResolvedValue({
			token: 'setup-token',
			user: { id: 1, username: 'admin', role: 'admin', must_change_password: false }
		});

		const { container } = render(Login);

		// The expect inside makes waitFor retry while null (a bare querySelector
		// return would end the wait immediately with null).
		const newPassword = await waitFor(() => {
			const el = container.querySelector<HTMLInputElement>('#setup-new-password');
			expect(el).toBeTruthy();
			return el!;
		});
		await fireEvent.input(newPassword, { target: { value: 'NewP@ssw0rd2' } });
		const confirm = container.querySelector<HTMLInputElement>('#setup-confirm-password');
		expect(confirm).toBeTruthy();
		await fireEvent.input(confirm!, { target: { value: 'NewP@ssw0rd2' } });

		const form = newPassword!.closest('form')!;
		await fireEvent.submit(form);

		await waitFor(() => {
			expect(api.post).toHaveBeenCalledWith('/auth/setup', { new_password: 'NewP@ssw0rd2' });
		});
	});

	// #427: an empty submit must show in-DOM, localized field errors: not rely
	// on the native required bubble (silent under automation): and must never
	// reach the API.
	it('shows localized field errors on empty submit and does not call the API (#427)', async () => {
		authMock.state.user = null;
		authMock.state.token = null;
		vi.mocked(api.get).mockImplementation((path: string) =>
			path === '/auth/setup-status'
				? Promise.resolve({ required: false })
				: Promise.resolve(undefined)
		);
		vi.mocked(api.post).mockClear();

		const { container } = render(Login);

		const form = await waitFor(() => {
			const f = container.querySelector('form');
			expect(f).toBeTruthy();
			return f!;
		});
		await fireEvent.submit(form);

		// Field-level errors render in-DOM, translated (never the raw
		// "validation.*" paraglide key).
		await waitFor(() => {
			const msgs = Array.from(container.querySelectorAll('p.text-error'));
			expect(msgs.length).toBeGreaterThanOrEqual(2);
			for (const p of msgs) {
				expect(p.textContent).not.toContain('validation.');
				expect((p.textContent ?? '').trim().length).toBeGreaterThan(0);
			}
		});
		// The empty submit never reached the login endpoint.
		expect(api.post).not.toHaveBeenCalled();
	});

	// #430: a visitor with a live session landing on /login is bounced straight
	// to the dashboard instead of rendering the login form.
	it('redirects an already-authenticated visitor to /dashboard (#430)', async () => {
		authMock.state.user = { id: 1, username: 'admin', email: 'a@b.c', role: 'admin' };
		authMock.state.token = 'live-token';

		render(Login);

		await waitFor(() => {
			expect(goto).toHaveBeenCalledWith('/dashboard');
		});

		// Restore for any test that runs after this one.
		authMock.state.user = null;
		authMock.state.token = null;
	});
});
