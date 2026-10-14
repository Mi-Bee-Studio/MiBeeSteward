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
// ($app/stores page): both are controllable per-test via hoisted mutable
// state so each case can pin (token, pathname) independently.
const mocks = vi.hoisted(() => {
	const authState = {
		user: null as null | { id: number; username: string; email: string; role: string },
		token: null as string | null
	};
	const route = { pathname: '/dashboard' };
	const demoMode = { on: false };
	return { authState, route, demoMode };
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
vi.mock('$lib/stores/demo', () => ({
	// Per-test controllable: the demo banner test flips this on.
	probeDemoMode: vi.fn(() => Promise.resolve(mocks.demoMode.on))
}));
// serverVersion: pinned value so the footer line is deterministic (the real
// store fetches /health once per session — covered by the login page tests).
vi.mock('$lib/stores/serverVersion', () => ({
	serverVersion: {
		subscribe: (fn: (v: string) => void) => {
			fn('v1.2.3-test');
			return () => {};
		}
	},
	loadServerVersion: vi.fn()
}));
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
		mocks.demoMode.on = false;
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
		// The mobile hamburger button is inside the same {#if}: verify it too,
		// since it is fixed-positioned and would float over the login form.
		const hamburger = container.querySelector('button[aria-label]');
		expect(hamburger).toBeNull();
	});

	// #566: the demo banner used to be a flex child of the h-screen shell,
	// stretching into a full-height column between aside and main that crushed
	// the dashboard at 1280 and intercepted pointer events across the dead
	// strip. It must be a fixed bottom strip, pointer-transparent except its
	// own button, with main reserving the strip height.
	it('pins the demo banner as a fixed bottom strip that does not join the shell flex row (#566)', async () => {
		mocks.demoMode.on = true;

		const { container } = render(Layout, { children: () => {} });

		const banner = await waitFor(() => {
			const el = container.querySelector('div.fixed.bottom-0');
			expect(el).toBeTruthy();
			return el as HTMLElement;
		});
		expect(banner.className).toContain('fixed');
		expect(banner.className).toContain('bottom-0');
		// Pointer events pass through the strip; only the wipe button is live,
		// so the strip can never shadow the content behind it.
		expect(banner.className).toContain('pointer-events-none');
		const wipe = banner.querySelector('button');
		expect(wipe?.className).toContain('pointer-events-auto');
		// Main reserves the strip height so scrolled content rests above it.
		const main = container.querySelector('#main-content');
		expect(main?.className).toContain('pb-9');
	});

	it('renders no demo banner when demo mode is off', async () => {
		const { container } = render(Layout, { children: () => {} });
		await waitFor(() => {
			expect(container.querySelector('aside')).toBeTruthy();
		});
		expect(container.querySelector('div.fixed.bottom-0')).toBeNull();
	});
});
