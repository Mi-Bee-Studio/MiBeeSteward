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

		// The 2FA code field (inputmode numeric, maxlength 6) is conditional —
		// absent until a 2FA challenge is returned. Absence on mount is the
		// contract that the default credential form is the initial view.
		const twoFactorInput = container.querySelector('input[inputmode="numeric"][maxlength="6"]');
		expect(twoFactorInput).toBeFalsy();
	});

	// First-run setup: when the bootstrap admin has no password yet
	// (/auth/setup-status → required), the login form is REPLACED by the
	// create-admin-password form — nothing to log in with.
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
		// The credential form is hidden — there is no password to enter yet.
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
});
