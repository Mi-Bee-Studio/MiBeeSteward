import { writable } from 'svelte/store';

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
	undo?: ToastUndo;
}

function createToastStore() {
	const { subscribe, update } = writable<Toast[]>([]);
	let nextId = 1;

	function addToast(type: ToastType, message: string, undo?: { callback: () => void; label?: string; timeout?: number }) {
		const id = nextId++;
		const undoConfig = undo ? {
			callback: undo.callback,
			label: undo.label || 'Undo',
			timeout: undo.timeout || 10000
		} : undefined;
		update((current) => {
			const updated = [...current, { id, type, message, undo: undoConfig }];
			// Keep max 5 toasts
			return updated.slice(-5);
		});
		const dismissMs = undoConfig ? undoConfig.timeout : 5000;
		setTimeout(() => removeToast(id), dismissMs);
	}

	function removeToast(id: number) {
		update((current) => current.filter((t) => t.id !== id));
	}

	function invokeUndo(id: number) {
		let undoCallback: (() => void) | undefined;
		update((current) => {
			const toast = current.find((t) => t.id === id);
			undoCallback = toast?.undo?.callback;
			return current.filter((t) => t.id !== id);
		});
		undoCallback?.();
	}

	return { subscribe, addToast, removeToast, invokeUndo };
}

export const toasts = createToastStore();
export const { removeToast, addToast, invokeUndo } = toasts;
