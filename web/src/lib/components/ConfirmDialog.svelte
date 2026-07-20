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
		onConfirm: () => void;
		onCancel?: () => void;
	} = $props();

	const resolvedConfirmLabel = $derived(confirmLabel ?? m['common.Confirm']());
	const resolvedCancelLabel = $derived(cancelLabel ?? m['common.Cancel']());

	function handleConfirm() {
		if (loading) return;
		onConfirm();
		open = false;
	}

	function handleCancel() {
		onCancel?.();
		open = false;
	}
</script>

	<Modal bind:open {title} maxWidth="24rem" onClose={handleCancel}>
		<div
			class="confirm-content"
			role="alertdialog"
			aria-modal="true"
			aria-labelledby="confirm-title"
			aria-describedby="confirm-message"
		>
			<h3 id="confirm-title" class="sr-only">{title}</h3>
			<p id="confirm-message" class="confirm-message">{message}</p>
			<div class="confirm-actions">
				<button
					class="cd-btn cd-cancel"
					onclick={handleCancel}
					disabled={loading}
				>
					{resolvedCancelLabel}
				</button>
				<button
					class="cd-btn cd-confirm"
					class:cd-confirm-danger={confirmVariant === 'danger'}
					onclick={handleConfirm}
					disabled={loading}
					aria-busy={loading ? 'true' : undefined}
				>
					{#if loading}
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
