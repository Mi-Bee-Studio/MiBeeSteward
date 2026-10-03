/**
 * Regression: the upstream-check API serializes empty slices as JSON null
 * (Go nil slice). `null.length` in the panel template crashed Svelte 5's
 * render effect, silently killing the whole {#if upstream} subtree — the
 * button looked like it did nothing. The component now normalizes null → []
 * before assigning state; this test feeds the REAL wire shape (nulls) and
 * demands the panel render.
 */
import { describe, it, expect, vi, beforeAll } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';

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
		user: { id: 1, username: 'admin', email: 'a@b.c', role: 'admin' },
		token: 't'
	},
	upstreamResult: {
		upstream_version: 'rig-20261004.2',
		upstream_rev: '00a4b4a8d99caccd71b73bf69ea493de0505d226dce2fb08ad5239b612d84082',
		rule_count: 2638,
		current_rev: 'f54d02aa7077d565',
		up_to_date: false,
		// Wire shape when a category is empty: JSON null, not [].
		changed_files: null,
		added_rules: null,
		removed_rules: null
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
vi.mock('$lib/stores/toast', () => ({ addToast: vi.fn() }));
vi.mock('$lib/api/client', () => ({
	api: {
		get: vi.fn((url: string) => {
			if (url === '/auth/profile')
				return Promise.resolve({ id: 1, username: 'admin', email: 'a@b.c', role: 'admin' });
			if (url === '/auth/2fa/status') return Promise.resolve({ enabled: false });
			if (url === '/fingerprints')
				return Promise.resolve({
					source: 'managed',
					rev: 'f54d02aa7077d565',
					rule_count: 2637,
					files: [{ name: 'banner.yaml', size: 7091 }],
					bytes: 7091,
					prev_available: true,
					uploads_enabled: true
				});
			if (url === '/fingerprints/agents') return Promise.resolve({ agents: [] });
			if (url === '/fingerprints/upstream') return Promise.resolve(mocks.upstreamResult);
			return Promise.resolve({});
		}),
		post: vi.fn(() => Promise.resolve({})),
		put: vi.fn(() => Promise.resolve({})),
		del: vi.fn(() => Promise.resolve({})),
		upload: vi.fn(() => Promise.resolve({}))
	},
	ApiError: class ApiError extends Error {
		status = 0;
	}
}));

import Settings from '../routes/settings/+page.svelte';

describe('Fingerprint upstream check panel (null-safe)', () => {
	it('renders the panel even when the API sends null diff arrays', async () => {
		const { container } = render(Settings);
		await waitFor(() => expect(document.getElementById('settings-fingerprints')).toBeTruthy());

		await fireEvent.click(container.querySelector('#settings-fingerprints button')!);
		await waitFor(() => {
			const panel = document.getElementById('settings-panel-fingerprints');
			expect(panel && !panel.classList.contains('hidden')).toBe(true);
		});

		const fpPanel = document.getElementById('settings-panel-fingerprints')!;
		const checkBtn = [...fpPanel.querySelectorAll('button')].find((b) =>
			(b.textContent || '').includes('Check Upstream')
		);
		expect(checkBtn, 'check button exists').toBeTruthy();

		await fireEvent.click(checkBtn!);
		await waitFor(
			() => {
				const anyH2 = [...fpPanel.querySelectorAll('h2')].map((h) => h.textContent);
				expect(anyH2.some((t) => (t || '').includes('Upstream check'))).toBe(true);
			},
			{ timeout: 4000 }
		);
	});
});
