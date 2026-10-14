<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { scale } from 'svelte/transition';

	// Open-modal registry (#582): the close() handler of every OPEN Modal,
	// in open order. The last entry is the topmost modal; while any modal is
	// open, the Escape key belongs to that topmost one alone.
	const openModalStack: Array<() => void> = [];
	import { m } from '$lib/i18n-paraglide';
	import { X } from '@lucide/svelte';

	let {
		open = $bindable(false),
		title,
		maxWidth = '32rem',
		onClose,
		closable = true,
		confirmDiscard,
		discardTitle,
		discardMessage,
		children
	}: {
		open?: boolean;
		title: string;
		maxWidth?: string;
		onClose?: () => void;
		/** When false, Escape / backdrop / X are ignored (e.g. while an async
		 *  confirm is in flight: see ConfirmDialog). Defaults to true. */
		closable?: boolean;
		/**
		 * Return `true` to block the close and instead show the "unsaved
		 * changes" discard confirmation. The previous name `onBeforeClose`
		 * read as "return true to allow close": the opposite of the actual
		 * contract: so it was renamed for clarity.
		 */
		confirmDiscard?: () => boolean;
		/** Override the discard-confirm title (defaults to "Unsaved Changes"). */
		discardTitle?: string;
		/** Override the discard-confirm message. */
		discardMessage?: string;
		children: import('svelte').Snippet;
	} = $props();

	const resolvedDiscardTitle = $derived(discardTitle ?? m['common.unsaved_changes']());
	const resolvedDiscardMessage = $derived(discardMessage ?? m['common.unsaved_changes_desc']());

	let dialogRef: HTMLDivElement | undefined = $state();
	let previouslyFocused: HTMLElement | undefined = $state();
	let showConfirm = $state(false);

	// Unique id for this instance's title element so aria-labelledby resolves
	// correctly even when multiple Modals (or a Modal + ConfirmDialog) are open
	// at once. Hardcoded "modal-title" collided across concurrent instances.
	const titleId = typeof crypto !== 'undefined' && 'randomUUID' in crypto
		? `modal-title-${crypto.randomUUID()}`
		: `modal-title-${Math.random().toString(36).slice(2)}`;

	const FOCUSABLE =
		'a[href], button:not([disabled]), textarea, input, select, [tabindex]:not([tabindex="-1"])';

	function getFocusable(): HTMLElement[] {
		if (!dialogRef) return [];
		return Array.from(dialogRef.querySelectorAll(FOCUSABLE));
	}

	function trapFocus(e: KeyboardEvent) {
		if (e.key !== 'Tab') return;

		const focusable = getFocusable();
		if (focusable.length === 0) {
			e.preventDefault();
			return;
		}

		const first = focusable[0];
		const last = focusable[focusable.length - 1];

		if (e.shiftKey) {
			if (document.activeElement === first) {
				e.preventDefault();
				last.focus();
			}
		} else {
			if (document.activeElement === last) {
				e.preventDefault();
				first.focus();
			}
		}
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') {
			close();
		} else {
			trapFocus(e);
		}
	}

	// Escape ownership (#582): answer Escape from a DOCUMENT-CAPTURE
	// listener instead of relying on the keydown bubbling up to the
	// backdrop. Bubbling was never guaranteed: synthetic KeyboardEvents
	// default to bubbles:false (automation, key injection — the #582
	// reproduction), and focus sitting outside the modal meant the event
	// never traversed the backdrop at all (the app layout carried a
	// querySelector workaround for exactly that half). A capture listener
	// sees every keydown regardless of where — or whether — it bubbles.
	function handleDocumentKeydown(e: KeyboardEvent) {
		if (e.key !== 'Escape') return;
		// Stacked modals: only the topmost one answers.
		if (openModalStack[openModalStack.length - 1] !== close) return;
		// Own the key entirely: the same event must not also run the
		// backdrop's delegated handler (double close / double onClose) or
		// app-level Escape logic beneath this modal.
		e.stopImmediatePropagation();
		close();
	}

	function close() {
		// Locked by the caller (e.g. ConfirmDialog during an in-flight async
		// confirm): ignore Escape / backdrop / X so the request is not orphaned.
		if (!closable) return;
		// If the discard-confirm overlay is already up, a backdrop click just
		// dismisses the overlay (back to the open modal) instead of re-running
		// confirmDiscard and re-showing it: that flickery loop was the old bug.
		if (showConfirm) {
			showConfirm = false;
			return;
		}
		if (confirmDiscard?.()) {
			showConfirm = true;
			return;
		}
		doClose();
	}

	function doClose() {
		showConfirm = false;
		open = false;
		onClose?.();
	}

	function handleBackdropClick(e: MouseEvent) {
		if (e.target === e.currentTarget) {
			close();
		}
	}

	$effect(() => {
		if (open) {
			previouslyFocused = document.activeElement as HTMLElement;
			document.body.style.overflow = 'hidden';
			openModalStack.push(close);
			document.addEventListener('keydown', handleDocumentKeydown, true);

			// Focus first focusable element after the dialog's scale transition
			// paints. requestAnimationFrame (chained once to land on the post-paint
			// frame) is more reliable than a fixed setTimeout(50), which raced the
			// transition and occasionally focused before the dialog was interactive.
			let raf2 = 0;
			const raf1 = requestAnimationFrame(() => {
				raf2 = requestAnimationFrame(() => {
					if (!dialogRef) return;
					const focusable = getFocusable();
					if (focusable.length > 0) {
						focusable[0].focus();
					} else {
						dialogRef!.focus();
					}
				});
			});

			return () => {
				const idx = openModalStack.indexOf(close);
				if (idx !== -1) openModalStack.splice(idx, 1);
				document.removeEventListener('keydown', handleDocumentKeydown, true);
				cancelAnimationFrame(raf1);
				cancelAnimationFrame(raf2);
			};
		} else {
			document.body.style.overflow = '';
			if (previouslyFocused && previouslyFocused.focus) {
				previouslyFocused.focus();
			}
		}
	});
</script>

{#if open}
	<!-- Closing must never depend on an animation finishing (#567): Svelte
	     outro transitions wait for the Web Animations clock, and embedded
	     webviews (old tablets, kiosks, some Electron/WebView hosts) can have
	     a document timeline that never advances - the outro's onfinish never
	     fired, open flipped false but the backdrop+dialog DOM lingered
	     forever, intercepting every pointer event under it. So: no outro at
	     all (close removes the DOM on the spot), and the intro is
	     transform-only (in:scale) - a frozen clock then leaves the dialog at
	     0.95 scale, still fully visible and usable, instead of an
	     opacity-keyed fade that would pin the scrim invisible. -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="modal-backdrop"
		onclick={handleBackdropClick}
		onkeydown={handleKeydown}
	>
		<div
			bind:this={dialogRef}
			class="modal-dialog"
			style="max-width: {maxWidth}"
			in:scale={{ duration: 200, start: 0.95 }}
			role="dialog"
			aria-modal="true"
			aria-labelledby={titleId}
			tabindex="-1"
		>
			<header class="modal-header">
				<h2 id={titleId} class="modal-title">{title}</h2>
				<button
					class="modal-close"
					onclick={close}
					aria-label={m['common.Close Dialog']()}
				>
					<X class="w-5 h-5" />
				</button>
			</header>

			<div class="modal-body">
				{@render children()}
			</div>

			{#if showConfirm}
				<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
				<div class="modal-confirm-overlay" onclick={() => (showConfirm = false)}>
					<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
					<div class="modal-confirm-card" onclick={(e) => e.stopPropagation()}>
						<h3 class="modal-confirm-title">{resolvedDiscardTitle}</h3>
						<p class="modal-confirm-desc">{resolvedDiscardMessage}</p>
						<div class="modal-confirm-actions">
							<button class="confirm-btn confirm-cancel" onclick={() => (showConfirm = false)}>{m['common.Cancel']()}</button>
							<button class="confirm-btn confirm-discard" onclick={doClose}>{m['common.discard']()}</button>
						</div>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}

<style>
	.modal-backdrop {
		position: fixed;
		inset: 0;
		z-index: 50;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: 1rem;
		background: var(--overlay-scrim);
		backdrop-filter: blur(2px);
	}

	.modal-dialog {
		position: relative;
		width: 100%;
		max-height: min(90vh, 800px);
		overflow-y: auto;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-lg);
		box-shadow: var(--shadow-lg);
		outline: none;
	}

	@media (max-width: 480px) {
		.modal-dialog {
			border-radius: var(--radius-md);
			margin: 0;
		}

		.modal-header {
			padding: 0.75rem 1rem;
		}

		.modal-body {
			padding: 1rem;
		}
	}

	.modal-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 1rem 1.5rem;
		border-bottom: 1px solid var(--color-border);
	}

	.modal-title {
		font-size: 1.125rem;
		font-weight: 600;
		color: var(--color-primary);
		margin: 0;
		line-height: 1.4;
	}

	.modal-close {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 2rem;
		height: 2rem;
		border-radius: var(--radius-sm);
		border: none;
		background: transparent;
		color: var(--color-text-muted);
		cursor: pointer;
		transition: color 0.15s ease, background 0.15s ease;
		flex-shrink: 0;
	}

	.modal-close:hover {
		color: var(--color-text);
		background: var(--color-surface-2);
	}

	.modal-body {
		padding: 1.5rem;
	}

	.modal-confirm-overlay {
		position: absolute;
		inset: 0;
		z-index: 10;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--overlay-scrim);
		border-radius: var(--radius-lg);
	}

	.modal-confirm-card {
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-radius: var(--radius-md);
		padding: 1.25rem 1.5rem;
		max-width: 22rem;
		width: 90%;
		box-shadow: var(--shadow-md);
	}

	.modal-confirm-title {
		font-size: 0.9375rem;
		font-weight: 600;
		color: var(--color-text);
		margin: 0 0 0.5rem;
	}

	.modal-confirm-desc {
		font-size: 0.8125rem;
		color: var(--color-text-muted);
		line-height: 1.5;
		margin: 0 0 1rem;
	}

	.modal-confirm-actions {
		display: flex;
		gap: 0.625rem;
		justify-content: flex-end;
	}

	.confirm-btn {
		padding: 0.375rem 1rem;
		font-size: 0.8125rem;
		font-weight: 600;
		border-radius: var(--radius-sm);
		cursor: pointer;
		border: none;
		line-height: 1.4;
		transition: all 0.15s ease;
	}

	.confirm-cancel {
		background: transparent;
		color: var(--color-text-muted);
		border: 1px solid var(--color-border);
	}

	.confirm-cancel:hover {
		border-color: var(--color-primary);
		color: var(--color-text);
	}

	.confirm-discard {
		background: var(--color-error);
		color: var(--color-text-inverse);
	}

	.confirm-discard:hover {
		opacity: 0.9;
	}
</style>
