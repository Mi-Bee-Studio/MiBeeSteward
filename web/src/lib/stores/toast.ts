/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import { writable } from 'svelte/store';
import { m } from '$lib/i18n-paraglide';

export type ToastType = 'success' | 'error' | 'warning' | 'info';

export interface ToastUndo {
	callback: () => void;
	label: string;
	timeout: number;
}

export interface Toast {
	id: number;
	type: ToastType;
	message: string;
	/** How many times this same (type, message) fired while still visible;
	 *  repeats merge into one row with a counter instead of stacking (#573). */
	count?: number;
	undo?: ToastUndo;
}

interface ToastTimer {
	timeout: ReturnType<typeof setTimeout>;
	/** ms left before dismissal; maintained across pause/resume so hovering
	 *  really freezes the auto-dismiss (previously the progress bar paused
	 *  via CSS while the timer kept running — a lie the comment told). */
	remaining: number;
	startedAt: number;
}

function createToastStore() {
	const { subscribe, update } = writable<Toast[]>([]);
	let nextId = 1;
	const timers = new Map<number, ToastTimer>();

	function arm(id: number, ms: number) {
		timers.set(id, {
			timeout: setTimeout(() => removeToast(id), ms),
			remaining: ms,
			startedAt: Date.now()
		});
	}

	function disarm(id: number) {
		const t = timers.get(id);
		if (t) {
			clearTimeout(t.timeout);
			timers.delete(id);
		}
	}

	function addToast(type: ToastType, message: string, undo?: { callback: () => void; label?: string; timeout?: number }) {
		const undoConfig = undo ? {
			callback: undo.callback,
			label: undo.label || m['common.Undo'](),
			timeout: undo.timeout || 10000
		} : undefined;
		const dismissMs = undoConfig ? undoConfig.timeout : 5000;
		const id = nextId++;
		let mergedInto: number | undefined;

		update((current) => {
			// Merge repeats (#573): an identical (type, message, undo-ness) toast
			// still on screen bumps its counter and restarts its window instead
			// of stacking a duplicate row.
			const existing = current.find(
				(t) => t.type === type && t.message === message && !!t.undo === !!undoConfig
			);
			if (existing) {
				mergedInto = existing.id;
				return current.map((t) =>
					t.id === existing.id ? { ...t, count: (t.count ?? 1) + 1 } : t
				);
			}
			const updated = [...current, { id, type, message, undo: undoConfig }];
			// Keep max 5 toasts. A toast evicted here may still have a pending
			// timer; its eventual removeToast is a harmless no-op filter.
			return updated.slice(-5);
		});

		if (mergedInto !== undefined) {
			disarm(mergedInto);
			arm(mergedInto, dismissMs);
		} else {
			arm(id, dismissMs);
		}
	}

	function removeToast(id: number) {
		disarm(id);
		update((current) => current.filter((t) => t.id !== id));
	}

	function pauseToast(id: number) {
		const t = timers.get(id);
		if (!t) return;
		clearTimeout(t.timeout);
		t.remaining = Math.max(0, t.remaining - (Date.now() - t.startedAt));
	}

	function resumeToast(id: number) {
		const t = timers.get(id);
		if (!t) return;
		t.timeout = setTimeout(() => removeToast(id), t.remaining);
		t.startedAt = Date.now();
	}

	function invokeUndo(id: number) {
		let undoCallback: (() => void) | undefined;
		update((current) => {
			const toast = current.find((t) => t.id === id);
			undoCallback = toast?.undo?.callback;
			return current.filter((t) => t.id !== id);
		});
		disarm(id);
		undoCallback?.();
	}

	return { subscribe, addToast, removeToast, pauseToast, resumeToast, invokeUndo };
}

export const toasts = createToastStore();
export const { removeToast, addToast, pauseToast, resumeToast, invokeUndo } = toasts;
