/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 */

import { describe, it, expect, vi, beforeEach, beforeAll } from 'vitest';
import { render, waitFor } from '@testing-library/svelte';

// Sidebar children (ThemeToggle's prefers-color-scheme probe) need
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

// The layout reads session state ($lib/stores/auth) and the current route
// ($app/stores page) — both are controllable per-test via hoisted mutable
// state so each case can pin (token, pathname) independently.
const mocks = vi.hoisted(() => {
	const authState = {
		user: null as null | { id: number; username: string; email: string; role: string },
		token: null as string | null
	};
	const route = { pathname: '/dashboard' };
	return { authState, route };
});

vi.mock('$app/navigation', () => ({ goto: vi.fn() }));
vi.mock('$app/stores', () => ({
	page: {
		subscribe: (fn: (v: { url: { pathname: string } }) => void) => {
			fn({ url: { pathname: mocks.route.pathname } });
			return () => {};
		}
	}
}));
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
vi.mock('$lib/stores/demo', () => ({ probeDemoMode: vi.fn(() => Promise.resolve(false)) }));
vi.mock('$lib/stores/passwordPolicy', () => ({
	ensurePasswordPolicyLoaded: vi.fn(() => Promise.resolve()),
	passwordPolicy: {
		subscribe: (fn: (v: Record<string, unknown>) => void) => {
			fn({});
			return () => {};
		}
	}
}));
// NotificationBell (sidebar footer) polls /notification/logs on mount; its
// undefined-shape failure path is caught internally, so a bare resolve is fine.
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

// layout must be imported AFTER the vi.mock calls so the mocks take effect.
import Layout from '../routes/+layout.svelte';

describe('App layout', () => {
	beforeEach(() => {
		mocks.route.pathname = '/dashboard';
		mocks.authState.user = { id: 1, username: 'admin', email: 'a@b.c', role: 'admin' };
		mocks.authState.token = 'live-token';
	});

	// An authenticated app page renders the sidebar shell.
	it('renders the sidebar for an authenticated user on an app page', async () => {
		const { container } = render(Layout, { children: () => {} });

		await waitFor(() => {
			expect(container.querySelector('aside')).toBeTruthy();
		});
	});

	// #430: /login renders standalone. Previously an authenticated visitor
	// landing on /login got the login form AND the logged-in sidebar in one
	// mixed layout; the sidebar (and its hamburger) must be gated off there.
	it('does not render the sidebar or hamburger on /login even when authenticated (#430)', async () => {
		mocks.route.pathname = '/login';

		const { container } = render(Layout, { children: () => {} });

		await waitFor(() => {
			expect(container.querySelector('aside')).toBeNull();
		});
		// The mobile hamburger button is inside the same {#if} — verify it too,
		// since it is fixed-positioned and would float over the login form.
		const hamburger = container.querySelector('button[aria-label]');
		expect(hamburger).toBeNull();
	});
});
