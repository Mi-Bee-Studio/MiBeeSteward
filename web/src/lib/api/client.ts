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

function getCSRFToken(): string {
	const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
	return match ? decodeURIComponent(match[1]) : '';
}

import { goto } from '$app/navigation';
import { auth } from '$lib/stores/auth';
import { getErrorMessage } from '$lib/utils/error';
import { m } from '$lib/i18n-paraglide';

// API base path. Defaults to the same-origin /api/v1 prefix (the SPA is served
// by the Go binary, so same-origin is the norm). Override with
// VITE_API_BASE when the frontend talks to a different origin (e.g. local dev
// against a remote backend). Opt-in: unset → /api/v1, preserving existing behavior.
const API_BASE = import.meta.env.VITE_API_BASE ?? '/api/v1';

/**
 * Thrown by all three request paths (request / download / upload) on HTTP 401,
 * after the user has been logged out and redirected to /login. Callers that
 * need to distinguish "session expired" from other errors must check
 * `err instanceof SessionExpiredError` — NOT string-match on the message
 * (the message is localized and varies by locale).
 */
export class SessionExpiredError extends Error {
	constructor() {
		super(m['api.Session Expired']());
		this.name = 'SessionExpiredError';
	}
}

/**
 * Thrown by all three request paths (request / download / upload) on any non-2xx
 * response OTHER than 401 (401 has its own SessionExpiredError). Carries the
 * HTTP status code so callers can branch on `err.status` instead of
 * string-matching the (localized, locale-dependent) message. Subclass of Error
 * so existing `getErrorMessage(err)` / generic `catch` handlers are unaffected.
 *
 * Note: network failures (TypeError), aborts, and parse errors have no HTTP
 * status — those are still thrown as plain Error and are distinguishable from
 * ApiError via `instanceof ApiError`.
 */
export class ApiError extends Error {
	readonly status: number;
	constructor(status: number, message: string) {
		super(message);
		this.name = 'ApiError';
		this.status = status;
	}
}

/** Thrown when a request is aborted by the caller (user cancel), distinct
 *  from a timeout or network failure so callers can skip the error toast. */
export class RequestCancelledError extends Error {
	constructor() {
		super('request cancelled');
		this.name = 'RequestCancelledError';
	}
}

/**
 * Shared 401 handling: logs the user out, redirects to /login, and returns a
 * SessionExpiredError for the caller to throw (request/download) or reject
 * with (upload's XHR callback can't throw across the async boundary).
 *
 * This was previously copy-pasted in request(), download(), and upload() —
 * three identical logout+goto+throw/reject triplets. Centralizing it keeps the
 * session-expiry contract (logout BEFORE redirect, typed error after) in one
 * place.
 */
function handleUnauthorized(): SessionExpiredError {
	auth.logout();
	goto('/login');
	return new SessionExpiredError();
}

// Retry config for transient failures. Only idempotent GET requests retry —
// POST/PUT/PATCH/DELETE are never retried (a retried write could double-apply).
// A retry happens on: HTTP 5xx (server-side, likely transient) or a network-
// level failure (fetch rejected — DNS/connection drop). 4xx, 401, and
// AbortError (explicit cancel / timeout) are NOT retried.
const MAX_RETRIES = 2;
const RETRY_BASE_DELAY_MS = 150;

function isRetryableMethod(method?: string): boolean {
	// GET (and HEAD/OPTIONS) are safe/idempotent. Default (no method) is GET.
	return !method || method === 'GET' || method === 'HEAD' || method === 'OPTIONS';
}

function sleep(ms: number): Promise<void> {
	return new Promise((r) => setTimeout(r, ms));
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	const csrfToken = getCSRFToken();
	if (csrfToken && options?.method && options.method !== 'GET') {
		headers['X-CSRF-Token'] = csrfToken;
	}

	const method = options?.method;
	const canRetry = isRetryableMethod(method);
	let lastError: unknown;

	for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
		// Combine the caller's abort signal (user cancel) with a 30s timeout into
		// a single controller. Manual combiner instead of AbortSignal.any() — the
		// build target is es2020 and the repo has no prior usage of .any(), so a
		// listener-based merge is the safe, dependency-free path (#153).
		const ctrl = new AbortController();
		const timer = setTimeout(
			() => ctrl.abort(new DOMException('request timeout', 'TimeoutError')),
			30000
		);
		const callerSignal = options?.signal;
		const onCallerAbort = () => ctrl.abort(callerSignal?.reason);
		if (callerSignal) {
			if (callerSignal.aborted) {
				ctrl.abort(callerSignal.reason);
			} else {
				callerSignal.addEventListener('abort', onCallerAbort, { once: true });
			}
		}
		try {
			const res = await fetch(`${API_BASE}${path}`, {
				...options,
				signal: ctrl.signal,
				credentials: 'include',
				headers: { ...headers, ...(options?.headers as Record<string, string>) }
			});
			// A cancel that races with the response arriving: the server may have
			// already written a (likely 500, context-cancelled) status, but the user
			// cancelled — treat it as a cancel, not an error (#153).
			if (callerSignal?.aborted) throw new RequestCancelledError();
			if (res.status === 401) {
				throw handleUnauthorized();
			}
			if (!res.ok) {
				const err = await res.json().catch(() => ({ error: m['api.Request Failed']() }));
				const apiErr = new ApiError(res.status, err.error || m['api.HTTP Error']({ status: String(res.status) }));
				// 5xx on a GET is worth one more shot; anything else (4xx) is final.
				if (canRetry && res.status >= 500 && attempt < MAX_RETRIES) {
					lastError = apiErr;
					await sleep(RETRY_BASE_DELAY_MS * Math.pow(2, attempt));
					continue;
				}
				throw apiErr;
			}
			if (res.status === 204) return undefined as T;
			return res.json();
		} catch (err: unknown) {
			// A user-triggered cancel (caller's signal aborted with AbortError)
			// must propagate as a distinct, non-retryable error so callers can
			// skip the error toast (#153). Timeout / network errors wrap as before.
			if (callerSignal?.aborted) {
				throw new RequestCancelledError();
			}
			// Typed errors we created (SessionExpiredError / ApiError) propagate
			// as-is. A retryable ApiError (5xx GET) was already handled above
			// via `continue`; if it reaches here the retry budget is exhausted.
			if (err instanceof SessionExpiredError) throw err;
			if (err instanceof ApiError) throw err;
			// Anything else is a network/abort/parse failure. Distinguish:
			//  - AbortError (timeout): never retry, surface now.
			//  - network TypeError on a GET: retry, then surface if exhausted.
			const isTimeout = err instanceof DOMException && err.name === 'TimeoutError';
			const isAbort = err instanceof DOMException && err.name === 'AbortError';
			if (canRetry && !isAbort && !isTimeout && attempt < MAX_RETRIES) {
				lastError = err;
				await sleep(RETRY_BASE_DELAY_MS * Math.pow(2, attempt));
				continue;
			}
			// Wrap the genuine network/abort/parse error (no HTTP status) into a
			// plain Error. Callers distinguish it from ApiError via instanceof.
			throw new Error(getErrorMessage(err));
		} finally {
			clearTimeout(timer);
			callerSignal?.removeEventListener('abort', onCallerAbort);
		}
	}
	// Retry budget exhausted — surface the last error.
	throw lastError instanceof Error
		? lastError
		: new Error(getErrorMessage(lastError));
}

export const api = {
	get: <T>(path: string) => request<T>(path),
	post: <T>(path: string, body: unknown, signal?: AbortSignal) =>
		request<T>(path, { method: 'POST', body: JSON.stringify(body), signal }),
	put: <T>(path: string, body: unknown) =>
		request<T>(path, { method: 'PUT', body: JSON.stringify(body) }),
	patch: <T>(path: string, body: unknown) =>
		request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }),
	delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
	// download fetches a binary (CSV/JSON export, file download) and returns it
	// as a Blob. Goes through the same auth/CSRF/401 handling as request(), so
	// exports no longer bypass the client via raw fetch (which dropped CSRF).
	download: async (path: string): Promise<Blob> => {
		const csrfToken = getCSRFToken();
		const headers: Record<string, string> = {};
		if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
		// 60s timeout — more generous than request()'s 30s since downloads
		// (CSV/JSON exports, file downloads) can be larger. Without this a hung
		// or very slow response would leave the fetch pending forever (#71).
		const res = await fetch(`${API_BASE}${path}`, {
			credentials: 'include',
			headers,
			signal: AbortSignal.timeout(60000)
		});
		if (res.status === 401) {
			throw handleUnauthorized();
		}
		if (!res.ok) {
			const err = await res.json().catch(() => ({ error: m['api.Download Failed']() }));
			throw new ApiError(res.status, err.error || m['api.HTTP Error']({ status: String(res.status) }));
		}
		return res.blob();
	},
	upload: <T>(path: string, formData: FormData, onProgress?: (percent: number) => void): Promise<T> => {
		return new Promise((resolve, reject) => {
			const xhr = new XMLHttpRequest();
			xhr.open('POST', `${API_BASE}${path}`);
			xhr.withCredentials = true;
			const csrfToken = getCSRFToken();
			if (csrfToken) {
				xhr.setRequestHeader('X-CSRF-Token', csrfToken);
			}
			xhr.upload.addEventListener('progress', (e) => {
				if (e.lengthComputable && onProgress) {
					onProgress(Math.round((e.loaded / e.total) * 100));
				}
			});
			xhr.timeout = 30000;
			xhr.onload = () => {
				if (xhr.status === 401) {
					reject(handleUnauthorized());
					return;
				}
				if (xhr.status >= 400) {
					try {
						const err = JSON.parse(xhr.responseText);
						reject(new ApiError(xhr.status, err.error || m['api.HTTP Error']({ status: String(xhr.status) })));
					} catch {
						reject(new ApiError(xhr.status, m['api.HTTP Error']({ status: String(xhr.status) })));
					}
					return;
				}
				try {
					resolve(JSON.parse(xhr.responseText) as T);
				} catch {
					resolve(undefined as T);
				}
			};
			xhr.onerror = () => reject(new Error(m['api.Upload Failed']()));
			xhr.ontimeout = () => reject(new Error(m['api.Upload Timed Out']()));
			xhr.send(formData);
		});
	}
};
