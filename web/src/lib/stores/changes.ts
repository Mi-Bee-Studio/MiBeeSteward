// Shared SSE client for the change stream (GET /api/v1/changes/watch), #272.
//
// Design notes:
// - EventSource cannot send an Authorization header; the endpoint authenticates
//   via the JWT cookie (same-origin requests carry it automatically). A pure
//   Bearer-token client (no cookie) will get a 401 and land in the backoff
//   path — harmless, it retries quietly.
// - Native EventSource auto-reconnects, but a non-retryable failure (401, or
//   the server answering 200 then closing) can flip it to CLOSED silently. We
//   manage reconnection ourselves: close on error, reopen with exponential
//   backoff (1s→2s→…→30s cap), reset on a successful open.
// - Tab visibility (#272 goal 3): hidden tabs close the stream (暂停消费);
//   re-visible tabs reopen it. Missed events are tolerated because consumers
//   refresh their data on (re)connect.
// - The store is lazy: the connection opens with the first subscriber and
//   closes with the last, so pages that never subscribe cost nothing.

import { derived, get, writable } from 'svelte/store';
import type { ChangeLogEntry } from '$lib/types';

export interface ChangeStoreState {
	connected: boolean;
	lastEvent: ChangeLogEntry | null;
}

// Fan-out state: one writable, N readers. The SSE connection is owned by a
// single manager started on first subscribe.
const state = writable<ChangeStoreState>({ connected: false, lastEvent: null });

let source: EventSource | null = null;
let backoffMs = 1000;
let reopenTimer: ReturnType<typeof setTimeout> | null = null;
let subscriberCount = 0;

function openStream() {
	if (source || typeof EventSource === 'undefined') return;
	const es = new EventSource('/api/v1/changes/watch', { withCredentials: true });
	source = es;

	es.onopen = () => {
		backoffMs = 1000;
		state.update((s) => ({ ...s, connected: true }));
	};
	es.addEventListener('change', (ev) => {
		try {
			const evt = JSON.parse((ev as MessageEvent).data) as ChangeLogEntry;
			state.update((s) => ({ ...s, lastEvent: evt }));
		} catch {
			// malformed frame — ignore
		}
	});
	es.onerror = () => {
		// Close and reopen on our own backoff loop (see note above).
		es.close();
		source = null;
		state.update((s) => ({ ...s, connected: false }));
		if (subscriberCount > 0 && !document.hidden) {
			reopenTimer = setTimeout(openStream, backoffMs);
			backoffMs = Math.min(backoffMs * 2, 30_000);
		}
	};
}

function closeStream() {
	if (reopenTimer) {
		clearTimeout(reopenTimer);
		reopenTimer = null;
	}
	source?.close();
	source = null;
	state.update((s) => ({ ...s, connected: false }));
}

function onVisibility() {
	if (document.hidden) {
		closeStream();
	} else if (subscriberCount > 0) {
		backoffMs = 1000;
		openStream();
	}
}

/** Subscribe to the live change stream. Returns the store; call .subscribe(). */
export function changeStream() {
	return derived(state, ($s) => $s);
}

/** Acquire the stream (pair with releaseStream). Idempotent per caller bookkeeping. */
export function acquireStream() {
	subscriberCount++;
	if (subscriberCount === 1) {
		document.addEventListener('visibilitychange', onVisibility);
		if (!document.hidden) openStream();
	}
}

/** Release the stream; the connection closes with the last subscriber. */
export function releaseStream() {
	subscriberCount = Math.max(0, subscriberCount - 1);
	if (subscriberCount === 0) {
		document.removeEventListener('visibilitychange', onVisibility);
		closeStream();
	}
}

// Convenience for tests / one-shot reads.
export function currentStreamState(): ChangeStoreState {
	return get(state);
}
