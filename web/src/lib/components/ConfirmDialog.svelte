<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import Modal from './Modal.svelte';
	import { m } from '$lib/i18n-paraglide';
	import { LoaderCircle } from '@lucide/svelte';

	let {
		open = $bindable(false),
		title,
		message,
		confirmLabel,
		cancelLabel,
		confirmVariant = 'primary',
		loading = false,
		onConfirm,
		onCancel
	}: {
		open?: boolean;
		title: string;
		message: string;
		/** Defaults to the localized "Confirm". */
		confirmLabel?: string;
		/** Defaults to the localized "Cancel" (was hardcoded "Cancel"). */
		cancelLabel?: string;
		confirmVariant?: 'primary' | 'danger';
		/** When true, the confirm button shows a spinner and is disabled. */
		loading?: boolean;
		/** May be async — the dialog stays open (with a spinner) until it resolves,
		 *  closes on success, stays open on rejection so the user can retry. */
		onConfirm: () => unknown;
		onCancel?: () => void;
	} = $props();

	const resolvedConfirmLabel = $derived(confirmLabel ?? m['common.Confirm']());
	const resolvedCancelLabel = $derived(cancelLabel ?? m['common.Cancel']());

	// Internal in-flight flag driven while `onConfirm` is awaiting. OR-ed with
	// the caller-supplied `loading` prop so both light up the spinner / disable
	// the buttons / block Modal close paths.
	let busy = $state(false);
	const pending = $derived(busy || loading);

	// Per-instance ids so two concurrent ConfirmDialogs (or a ConfirmDialog
	// alongside a Modal) don't collide on aria-labelledby/describedby targets.
	const idBase = typeof crypto !== 'undefined' && 'randomUUID' in crypto
		? crypto.randomUUID()
		: Math.random().toString(36).slice(2);
	const confirmTitleId = `confirm-title-${idBase}`;
	const confirmMessageId = `confirm-message-${idBase}`;

	async function handleConfirm() {
		if (pending) return;
		busy = true;
		try {
			await onConfirm();
			// On success, close. If the caller's onConfirm rejects AND the
			// caller does NOT swallow it internally, the catch below keeps
			// the dialog open so the user can retry. (Most callers do their
			// own try/catch + toast, in which case the promise resolves and
			// we close here — they can re-open the dialog to retry.)
			open = false;
		} catch {
			// Caller let the error bubble (did not try/catch inside onConfirm).
			// Keep the dialog open + busy=false so the user can fix input and
			// retry. The caller is expected to surface its own error toast.
		} finally {
			busy = false;
		}
	}

	function handleCancel() {
		if (pending) return;
		onCancel?.();
		open = false;
	}
</script>

	<Modal bind:open {title} maxWidth="24rem" onClose={handleCancel} closable={!pending}>
		<div
			class="confirm-content"
			role="alertdialog"
			aria-modal="true"
			aria-labelledby={confirmTitleId}
			aria-describedby={confirmMessageId}
		>
			<h3 id={confirmTitleId} class="sr-only">{title}</h3>
			<p id={confirmMessageId} class="confirm-message">{message}</p>
			<div class="confirm-actions">
				<button
					class="cd-btn cd-cancel"
					onclick={handleCancel}
					disabled={pending}
				>
					{resolvedCancelLabel}
				</button>
				<button
					class="cd-btn cd-confirm"
					class:cd-confirm-danger={confirmVariant === 'danger'}
					onclick={handleConfirm}
					disabled={pending}
					aria-busy={pending ? 'true' : undefined}
				>
					{#if pending}
						<LoaderCircle class="w-4 h-4 animate-spin" aria-hidden="true" />
					{/if}
					<span>{resolvedConfirmLabel}</span>
				</button>
			</div>
		</div>
	</Modal>

	<style>
		.confirm-content {
			display: flex;
			flex-direction: column;
			gap: 1.25rem;
		}

		.confirm-message {
			font-size: 0.875rem;
			color: var(--color-text-muted);
			line-height: 1.5;
			margin: 0;
		}

		.confirm-actions {
			display: flex;
			gap: 0.75rem;
			justify-content: flex-end;
		}

	.cd-btn {
		display: inline-flex;
		align-items: center;
		justify-content: center;
		gap: 0.5rem;
		padding: 0.5rem 1.25rem;
		font-size: 0.875rem;
		font-weight: 600;
		border-radius: var(--radius-md);
		cursor: pointer;
		transition: all 0.15s ease;
		border: none;
		line-height: 1.4;
	}

		.cd-cancel {
			border: 1px solid var(--color-border);
			background: transparent;
			color: var(--color-text-muted);
		}

		.cd-cancel:hover {
			border-color: var(--color-primary);
			color: var(--color-text);
		}

		.cd-confirm {
			background: var(--color-primary);
			color: var(--color-text-inverse);
		}

		.cd-confirm:hover {
			background: var(--color-primary-hover);
		}

		.cd-confirm-danger {
			background: var(--color-error);
			color: var(--color-text-inverse);
		}

		.cd-confirm-danger:hover {
			opacity: 0.9;
		}
	</style>
