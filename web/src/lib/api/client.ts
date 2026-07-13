function getCSRFToken(): string {
	const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
	return match ? decodeURIComponent(match[1]) : '';
}

import { goto } from '$app/navigation';
import { auth } from '$lib/stores/auth';
import { getErrorMessage } from '$lib/utils/error';

const API_BASE = '/api/v1';

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
			throw new Error('Session expired');
		}
		if (!res.ok) {
			const err = await res.json().catch(() => ({ error: 'Request failed' }));
			throw new Error(err.error || `HTTP ${res.status}`);
		}
		if (res.status === 204) return undefined as T;
		return res.json();
	} catch (err: unknown) {
		throw new Error(getErrorMessage(err));
	}
}

export const api = {
	get: <T>(path: string) => request<T>(path),
	post: <T>(path: string, body: unknown) =>
		request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
	put: <T>(path: string, body: unknown) =>
		request<T>(path, { method: 'PUT', body: JSON.stringify(body) }),
	delete: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
	// download fetches a binary (CSV/JSON export, file download) and returns it
	// as a Blob. Goes through the same auth/CSRF/401 handling as request(), so
	// exports no longer bypass the client via raw fetch (which dropped CSRF).
	download: async (path: string): Promise<Blob> => {
		const csrfToken = getCSRFToken();
		const headers: Record<string, string> = {};
		if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
		const res = await fetch(`${API_BASE}${path}`, {
			credentials: 'include',
			headers
		});
		if (res.status === 401) {
			auth.logout();
			goto('/login');
			throw new Error('Session expired');
		}
		if (!res.ok) {
			const err = await res.json().catch(() => ({ error: 'Download failed' }));
			throw new Error(err.error || `HTTP ${res.status}`);
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
					reject(new Error('Session expired'));
					return;
				}
				if (xhr.status >= 400) {
					try {
						const err = JSON.parse(xhr.responseText);
						reject(new Error(err.error || `HTTP ${xhr.status}`));
					} catch {
						reject(new Error(`HTTP ${xhr.status}`));
					}
					return;
				}
				try {
					resolve(JSON.parse(xhr.responseText) as T);
				} catch {
					resolve(undefined as T);
				}
			};
			xhr.onerror = () => reject(new Error('Upload failed'));
			xhr.ontimeout = () => reject(new Error('Upload timed out'));
			xhr.send(formData);
		});
	}
};
