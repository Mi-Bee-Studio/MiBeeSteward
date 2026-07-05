<script lang="ts">
	import { toasts, removeToast, invokeUndo, type ToastType } from '$lib/stores/toast';
	import { fly } from 'svelte/transition';
	import { CheckCircle2, XCircle, AlertTriangle, Info, X } from '@lucide/svelte';
	import type { Component } from 'svelte';

	const typeConfig: Record<ToastType, { icon: Component; color: string }> = {
		success: { icon: CheckCircle2, color: 'var(--color-success)' },
		error: { icon: XCircle, color: 'var(--color-error)' },
		warning: { icon: AlertTriangle, color: 'var(--color-warning)' },
		info: { icon: Info, color: 'var(--color-info)' }
	};
</script>

<div class="toast-container" aria-live="polite">
	{#each $toasts as toast (toast.id)}
		{@const cfg = typeConfig[toast.type]}
		<div
			class="toast-item"
			style="border-left-color: {cfg.color}"
			transition:fly={{ y: 20, duration: 300 }}
		>
			<div class="toast-body">
				<span class="toast-icon" style="color: {cfg.color}">
					<cfg.icon class="w-[18px] h-[18px]" />
				</span>
				<span class="toast-message">{toast.message}</span>
				{#if toast.undo}
					<button
						class="toast-undo"
						onclick={() => invokeUndo(toast.id)}
					>
						{toast.undo.label}
					</button>
				{/if}
				<button
					class="toast-dismiss"
					onclick={() => removeToast(toast.id)}
					aria-label="Dismiss notification"
				>
					<X class="w-4 h-4" />
				</button>
			</div>
			{#if toast.undo}
				<div
					class="toast-progress"
					style="background: {cfg.color}; animation-duration: {toast.undo.timeout}ms"
				></div>
			{:else}
				<div
					class="toast-progress"
					style="background: {cfg.color}"
				></div>
			{/if}
		</div>
	{/each}
</div>

<style>
	.toast-container {
		position: fixed;
		bottom: 1rem;
		right: 1rem;
		z-index: 60;
		display: flex;
		flex-direction: column-reverse;
		gap: 0.5rem;
		max-width: 24rem;
		pointer-events: none;
	}

	.toast-item {
		pointer-events: auto;
		background: var(--color-surface);
		border: 1px solid var(--color-border);
		border-left: 4px solid;
		border-radius: var(--radius-md);
		overflow: hidden;
		box-shadow: var(--shadow-md);
		backdrop-filter: blur(8px);
	}

	.toast-body {
		display: flex;
		align-items: center;
		gap: 0.75rem;
		padding: 0.75rem 1rem;
	}

	.toast-icon {
		display: flex;
		align-items: center;
		flex-shrink: 0;
		line-height: 1;
	}

	.toast-message {
		flex: 1;
		font-size: 0.875rem;
		color: var(--color-text);
		line-height: 1.4;
	}

	.toast-undo {
		flex-shrink: 0;
		background: var(--color-surface-2);
		border: none;
		color: var(--color-text);
		cursor: pointer;
		padding: 0.2rem 0.5rem;
		border-radius: var(--radius-sm);
		font-size: 0.75rem;
		font-weight: 600;
		white-space: nowrap;
		transition: background 0.15s ease;
	}

	.toast-undo:hover {
		background: var(--color-primary);
		color: var(--color-text-inverse);
	}

	.toast-dismiss {
		flex-shrink: 0;
		background: transparent;
		border: none;
		color: var(--color-text-muted);
		cursor: pointer;
		padding: 0.25rem;
		border-radius: var(--radius-sm);
		display: flex;
		align-items: center;
		justify-content: center;
		transition: color 0.15s ease, background 0.15s ease;
	}

	.toast-dismiss:hover {
		color: var(--color-text);
		background: var(--color-surface-2);
	}

	.toast-progress {
		height: 3px;
		animation: toast-progress 5s linear forwards;
	}

	@keyframes toast-progress {
		from { width: 100%; }
		to { width: 0%; }
	}
</style>
