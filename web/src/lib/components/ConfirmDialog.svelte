<script lang="ts">
	import Modal from './Modal.svelte';

	let {
		open = $bindable(false),
		title,
		message,
		confirmLabel = 'Confirm',
		confirmVariant = 'primary',
		onConfirm,
		onCancel
	}: {
		open?: boolean;
		title: string;
		message: string;
		confirmLabel?: string;
		confirmVariant?: 'primary' | 'danger';
		onConfirm: () => void;
		onCancel?: () => void;
	} = $props();

	function handleConfirm() {
		onConfirm();
		open = false;
	}

	function handleCancel() {
		onCancel?.();
		open = false;
	}
</script>

	<Modal bind:open {title} maxWidth="24rem" onClose={handleCancel}>
		<div class="confirm-content">
			<p class="confirm-message">{message}</p>
			<div class="confirm-actions">
				<button class="cd-btn cd-cancel" onclick={handleCancel}>
					Cancel
				</button>
				<button
					class="cd-btn cd-confirm"
					class:cd-confirm-danger={confirmVariant === 'danger'}
					onclick={handleConfirm}
				>
					{confirmLabel}
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
