<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { toasts, removeToast, invokeUndo, type ToastType, type Toast } from '$lib/stores/toast';
	import { fly } from 'svelte/transition';
	import { CheckCircle2, XCircle, AlertTriangle, Info, X } from '@lucide/svelte';
	import { m } from '$lib/i18n-paraglide';
	import type { Component } from 'svelte';

	const typeConfig: Record<ToastType, { icon: Component; color: string }> = {
		success: { icon: CheckCircle2, color: 'var(--color-success)' },
		error: { icon: XCircle, color: 'var(--color-error)' },
		warning: { icon: AlertTriangle, color: 'var(--color-warning)' },
		info: { icon: Info, color: 'var(--color-info)' }
	};

	// Hover-to-pause: stop the dismiss timer while the user is interacting
	// with a toast (reading it, about to click undo). Per-toast state tracks
	// whether the auto-dismiss should fire.
	let hoveredId: number | null = $state(null);
	const dismissLabel = $derived(m['common.Dismiss']());

	function onEnter(toast: Toast) {
		hoveredId = toast.id;
	}
	function onLeave() {
		hoveredId = null;
	}
</script>

<!--
  Two live regions: errors are assertive (interrupt), the rest polite (announce
  when idle). Splitting by severity avoids every success toast interrupting SR
  users. Both share the same visual stack via the grid below.
-->
<div class="sr-only" aria-live="assertive" aria-atomic="true">
	{#each $toasts as toast (toast.id)}
		{#if toast.type === 'error'}{toast.message}{/if}
	{/each}
</div>

<div class="toast-stack" aria-live="polite">
	{#each $toasts as toast (toast.id)}
		{@const cfg = typeConfig[toast.type]}
		<div
			class="toast-item"
			class:hovered={hoveredId === toast.id}
			style="border-left-color: {cfg.color}"
			role={toast.type === 'error' ? 'alert' : 'status'}
			transition:fly={{ y: 20, duration: 300 }}
			onmouseenter={() => onEnter(toast)}
			onmouseleave={onLeave}
		>
			<div class="toast-body">
				<span class="toast-icon" style="color: {cfg.color}">
					<cfg.icon class="w-[18px] h-[18px]" aria-hidden="true" />
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
					aria-label={dismissLabel}
				>
					<X class="w-4 h-4" aria-hidden="true" />
				</button>
			</div>
			{#if toast.undo}
				<div
					class="toast-progress"
					style="background: {cfg.color}; animation-duration: {toast.undo.timeout}ms"
				></div>
			{:else}
				<!--
					Explicit 5000ms matches the store's default dismiss timeout —
					without this the CSS fell back to its own 5s, which happened to
					match, but the coupling was implicit. Hovering freezes the bar.
				-->
				<div
					class="toast-progress"
					style="background: {cfg.color}; animation-duration: 5000ms"
				></div>
			{/if}
		</div>
	{/each}
</div>

<style>
	.toast-stack {
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

	.toast-undo:focus-visible,
	.toast-dismiss:focus-visible {
		outline: 2px solid var(--color-primary);
		outline-offset: 2px;
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
		/* Default duration; callers override via inline style. Hovering the
		 * toast pauses the bar so the user can finish reading / clicking undo
		 * before it dismisses itself. */
		animation: toast-progress 5s linear forwards;
	}

	.toast-item.hovered .toast-progress {
		animation-play-state: paused;
	}

	@keyframes toast-progress {
		from { width: 100%; }
		to { width: 0%; }
	}

	@media (prefers-reduced-motion: reduce) {
		.toast-progress {
			animation: none;
			opacity: 0.4;
		}
	}
</style>
