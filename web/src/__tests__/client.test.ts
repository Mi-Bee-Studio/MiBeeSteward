/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';

// vi.mock factories are hoisted above all imports, so the spies they close
// over must be created with vi.hoisted (also hoisted): plain top-level const
// would be in the temporal dead zone when the factory runs.
const { logoutSpy, gotoSpy } = vi.hoisted(() => ({
	logoutSpy: vi.fn(),
	gotoSpy: vi.fn()
}));
vi.mock('$lib/stores/auth', () => ({ auth: { logout: logoutSpy } }));
vi.mock('$app/navigation', () => ({ goto: gotoSpy }));

import { api, ApiError, SessionExpiredError } from '$lib/api/client';

// Build a fetch Response without coupling to the full Response API.
function jsonResponse(body: unknown, init: { status: number }): Response {
	return new Response(JSON.stringify(body), {
		status: init.status,
		headers: { 'Content-Type': 'application/json' }
	});
}

// We use REAL timers (not fake) on purpose: the retry loop interleaves fetch
// microtasks with setTimeout-driven backoff sleeps, and driving that correctly
// under fake timers requires pumping the queue in a loop. The total backoff is
// small (RETRY_BASE_DELAY_MS=150 → 150ms + 300ms = 450ms for the full 2-retry
// exhaustion path), so letting real time elapse keeps the test honest and far
// simpler. Each retry-capable case is awaited to settlement.
// #570: the synchronous scan endpoint legitimately runs longer than the
// client's 30s default (a demo /28 of unroutable IPs ran 36s server-side
// while the client had already reported "request timeout"). These tests pin
// the per-request timeoutMs override with fake timers and a fetch that never
// resolves on its own - it only rejects when the request's abort signal
// fires, exactly how a real fetch behaves on timeout.
describe('per-request timeout override (#570)', () => {
	afterEach(() => {
		vi.unstubAllGlobals();
	});

	function hangingFetch() {
		return vi.fn().mockImplementation(
			(_url: string, init?: RequestInit) =>
				new Promise((_resolve, reject) => {
					init?.signal?.addEventListener('abort', () => reject(init.signal!.reason));
				})
		) as unknown as typeof fetch;
	}

	it('aborts at the 30s default when no override is given', async () => {
		vi.useFakeTimers();
		try {
			vi.stubGlobal('fetch', hangingFetch());

			const pending = api.post('/slow', {}).catch((e) => e);
			await vi.advanceTimersByTimeAsync(29_000);
			expect(await Promise.race([pending, Promise.resolve('pending')])).toBe('pending');

			await vi.advanceTimersByTimeAsync(2_000);
			expect(await pending).toBeInstanceOf(Error);
		} finally {
			vi.useRealTimers();
		}
	});

	it('honors a timeoutMs wider than the default (scan-shaped request)', async () => {
		vi.useFakeTimers();
		try {
			vi.stubGlobal('fetch', hangingFetch());

			const pending = api.post('/scanner/scan', {}, { timeoutMs: 300_000 }).catch((e) => e);
			// 35s: past the old 30s default where the false failure fired (#570).
			await vi.advanceTimersByTimeAsync(35_000);
			expect(await Promise.race([pending, Promise.resolve('pending')])).toBe('pending');

			await vi.advanceTimersByTimeAsync(300_000);
			expect(await pending).toBeInstanceOf(Error);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe('api client retry / 401 handling', () => {
	let fetchMock: ReturnType<typeof vi.fn>;

	beforeEach(() => {
		fetchMock = vi.fn();
		vi.stubGlobal('fetch', fetchMock);
		logoutSpy.mockClear();
		gotoSpy.mockClear();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('retries GET on HTTP 500 and succeeds once the server recovers', async () => {
		fetchMock
			.mockResolvedValueOnce(jsonResponse({ error: 'boom' }, { status: 500 }))
			.mockResolvedValueOnce(jsonResponse({ ok: true }, { status: 200 }));

		const result = await api.get<{ ok: boolean }>('/anything');

		expect(result).toEqual({ ok: true });
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('exhausts retries on persistent GET 500 and throws ApiError(500)', async () => {
		// MAX_RETRIES = 2 → 3 attempts total (initial + 2 retries).
		fetchMock.mockResolvedValue(jsonResponse({ error: 'down' }, { status: 500 }));

		// Catch once and assert against the captured error.
		const err = await api.get('/down').catch((e) => e);
		expect(err).toBeInstanceOf(ApiError);
		expect((err as ApiError).status).toBe(500);
		expect(fetchMock).toHaveBeenCalledTimes(3);
	});

	it('does NOT retry POST on 500 (non-idempotent)', async () => {
		fetchMock.mockResolvedValue(jsonResponse({ error: 'down' }, { status: 500 }));

		await expect(api.post('/write', { x: 1 })).rejects.toBeInstanceOf(ApiError);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('does NOT retry 4xx (client errors are not transient)', async () => {
		fetchMock.mockResolvedValue(jsonResponse({ error: 'bad' }, { status: 422 }));

		await expect(api.get('/bad')).rejects.toBeInstanceOf(ApiError);
		expect(fetchMock).toHaveBeenCalledTimes(1);
	});

	it('401 logs out, redirects, and throws SessionExpiredError without retrying', async () => {
		fetchMock.mockResolvedValue(jsonResponse({ error: 'no' }, { status: 401 }));

		await expect(api.get('/secret')).rejects.toBeInstanceOf(SessionExpiredError);
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(logoutSpy).toHaveBeenCalledTimes(1);
		expect(gotoSpy).toHaveBeenCalledWith('/login');
	});

	it('retries GET on a network-level failure (fetch rejects)', async () => {
		fetchMock
			.mockRejectedValueOnce(new TypeError('Failed to fetch'))
			.mockResolvedValueOnce(jsonResponse({ ok: true }, { status: 200 }));

		const result = await api.get<{ ok: boolean }>('/flaky');

		expect(result).toEqual({ ok: true });
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});
});
