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

import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';

// We need to re-import for each test to reset the store state.
// Since the module uses a singleton, we test the exported store directly.
import { toasts, addToast, removeToast, pauseToast, resumeToast } from '$lib/stores/toast';

describe('toast store', () => {
	beforeEach(() => {
		// Clear all toasts before each test by removing them
		const current = get(toasts);
		for (const t of current) {
			removeToast(t.id);
		}
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('addToast adds a toast to the store', () => {
		addToast('success', 'Operation succeeded');
		const current = get(toasts);
		expect(current.length).toBe(1);
		expect(current[0].type).toBe('success');
		expect(current[0].message).toBe('Operation succeeded');
	});

	it('addToast auto-removes after 5 seconds', () => {
		addToast('info', 'Auto-remove test');
		expect(get(toasts).length).toBe(1);

		vi.advanceTimersByTime(5000);
		expect(get(toasts).length).toBe(0);
	});

	it('removeToast removes a specific toast', () => {
		addToast('error', 'First');
		addToast('warning', 'Second');

		const current = get(toasts);
		expect(current.length).toBe(2);

		removeToast(current[0].id);
		expect(get(toasts).length).toBe(1);
		expect(get(toasts)[0].message).toBe('Second');
	});

	it('limits toasts to max 5', () => {
		for (let i = 0; i < 7; i++) {
			addToast('info', `Toast ${i}`);
		}

		const current = get(toasts);
		expect(current.length).toBe(5);
		// Should keep the last 5: Toast 2..6
		expect(current[0].message).toBe('Toast 2');
		expect(current[4].message).toBe('Toast 6');
	});

	it('assigns incrementing IDs', () => {
		addToast('success', 'A');
		addToast('error', 'B');

		const current = get(toasts);
		expect(current[1].id).toBeGreaterThan(current[0].id);
	});

	it('merges repeated identical toasts into one row with a counter (#573)', () => {
		addToast('error', 'request timeout');
		addToast('error', 'request timeout');
		addToast('error', 'request timeout');
		addToast('error', 'a different message');

		const current = get(toasts);
		expect(current.length).toBe(2);
		const merged = current.find((t) => t.message === 'request timeout')!;
		expect(merged.count).toBe(3);
		expect(current.find((t) => t.message === 'a different message')!.count).toBeUndefined();
	});

	it('restarts the dismiss window when a toast merges', () => {
		addToast('info', 'blip');
		// 4.9s of the 5s window elapses, then the repeat arrives and restarts it.
		vi.advanceTimersByTime(4900);
		addToast('info', 'blip');
		vi.advanceTimersByTime(4900);
		expect(get(toasts).length).toBe(1, 'restarted window must not have fired yet');

		vi.advanceTimersByTime(200);
		expect(get(toasts).length).toBe(0, 'restarted window fires after the full 5s');
	});

	it('pauseToast freezes dismissal and resumeToast continues the remainder (#573)', () => {
		addToast('info', 'hold me');
		const id = get(toasts)[0].id;

		// Fake-timer worlds advance Date with the timers, so Date.now() inside
		// the store tracks the elapsed 2000ms of the window.
		vi.advanceTimersByTime(2000);
		pauseToast(id);
		vi.advanceTimersByTime(60000);
		expect(get(toasts).length).toBe(1, 'paused toast must not dismiss');

		resumeToast(id);
		vi.advanceTimersByTime(2900);
		expect(get(toasts).length).toBe(1, 'resume must continue the remainder, not a full window');

		vi.advanceTimersByTime(200);
		expect(get(toasts).length).toBe(0);
	});

	it('supports all toast types', () => {
		const types = ['success', 'error', 'warning', 'info'] as const;
		for (const type of types) {
			addToast(type, `${type} message`);
		}

		const current = get(toasts);
		expect(current.map((t) => t.type)).toEqual(types);
	});
});
