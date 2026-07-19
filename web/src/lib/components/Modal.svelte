<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { fade, scale } from 'svelte/transition';
	import { m } from '$lib/i18n-paraglide';
	import { X } from '@lucide/svelte';

	let {
		open = $bindable(false),
		title,
		maxWidth = '32rem',
		onClose,
		confirmDiscard,
		discardTitle,
		discardMessage,
		children
	}: {
		open?: boolean;
		title: string;
		maxWidth?: string;
		onClose?: () => void;
		/**
		 * Return `true` to block the close and instead show the "unsaved
		 * changes" discard confirmation. The previous name `onBeforeClose`
		 * read as "return true to allow close" — the opposite of the actual
		 * contract — so it was renamed for clarity.
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

	function close() {
		// If the discard-confirm overlay is already up, a backdrop click just
		// dismisses the overlay (back to the open modal) instead of re-running
		// confirmDiscard and re-showing it — that flickery loop was the old bug.
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

			// Focus first focusable element after render
			const timeout = setTimeout(() => {
				if (!dialogRef) return;
				const focusable = getFocusable();
				if (focusable.length > 0) {
					focusable[0].focus();
				} else {
					dialogRef!.focus();
				}
			}, 50);

			return () => {
				clearTimeout(timeout);
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
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div
		class="modal-backdrop"
		transition:fade={{ duration: 150 }}
		onclick={handleBackdropClick}
		onkeydown={handleKeydown}
	>
		<div
			bind:this={dialogRef}
			class="modal-dialog"
			style="max-width: {maxWidth}"
			transition:scale={{ duration: 200, start: 0.95 }}
			role="dialog"
			aria-modal="true"
			aria-labelledby="modal-title"
			tabindex="-1"
		>
			<header class="modal-header">
				<h2 id="modal-title" class="modal-title">{title}</h2>
				<button
					class="modal-close"
					onclick={close}
					aria-label="Close dialog"
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
