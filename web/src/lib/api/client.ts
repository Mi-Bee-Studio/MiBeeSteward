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

const API_BASE = '/api/v1';

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

async function request<T>(path: string, options?: RequestInit): Promise<T> {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	const csrfToken = getCSRFToken();
	if (csrfToken && options?.method && options.method !== 'GET') {
		headers['X-CSRF-Token'] = csrfToken;
	}
	try {
		const res = await fetch(`${API_BASE}${path}`, {
			...options,
			signal: AbortSignal.timeout(30000),
			credentials: 'include',
			headers: { ...headers, ...(options?.headers as Record<string, string>) }
		});
		if (res.status === 401) {
			auth.logout();
			goto('/login');
			throw new SessionExpiredError();
		}
		if (!res.ok) {
			const err = await res.json().catch(() => ({ error: m['api.Request Failed']() }));
			throw new ApiError(res.status, err.error || m['api.HTTP Error']({ status: String(res.status) }));
		}
		if (res.status === 204) return undefined as T;
		return res.json();
	} catch (err: unknown) {
		// Preserve typed errors (SessionExpiredError / ApiError) so callers can
		// branch on `instanceof` / `.status`. Only wrap genuine network/abort/
		// parse errors (which have no HTTP status) into a plain Error.
		if (err instanceof SessionExpiredError || err instanceof ApiError) throw err;
		throw new Error(getErrorMessage(err));
	}
}

export const api = {
	get: <T>(path: string) => request<T>(path),
	post: <T>(path: string, body: unknown) =>
		request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
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
			auth.logout();
			goto('/login');
			throw new SessionExpiredError();
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
					auth.logout();
					goto('/login');
					reject(new SessionExpiredError());
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
