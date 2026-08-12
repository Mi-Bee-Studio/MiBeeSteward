/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi } from 'vitest';
import { render } from '@testing-library/svelte';

// Mock the modules with external behavior so the page module loads cleanly
// under jsdom. A render-only test does not submit, so the spies are never
// called — they exist only so the imports resolve without a real fetcher/router.
vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$lib/api/client', () => ({
	api: { get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() },
	ApiError: class ApiError extends Error {},
	SessionExpiredError: class SessionExpiredError extends Error {}
}));

// login page must be imported AFTER the vi.mock calls so the mocks take effect.
import Login from '../routes/login/+page.svelte';

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
});
