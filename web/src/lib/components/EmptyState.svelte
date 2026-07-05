<script lang="ts">
	import type { Component } from 'svelte';

	let {
		icon,
		title,
		description,
		actionLabel,
		onAction
	}: {
		/** Accepts a lucide icon Component (preferred) or an emoji string (legacy). */
		icon?: Component | string;
		title: string;
		description?: string;
		actionLabel?: string;
		onAction?: () => void;
	} = $props();

	function handleAction() {
		onAction?.();
	}
</script>

<div class="empty-state">
	{#if icon}
		<div class="empty-icon">
			{#if typeof icon === 'string'}
				{icon}
			{:else}
				<svelte:component this={icon} class="w-10 h-10" strokeWidth={1.5} />
			{/if}
		</div>
	{/if}
	<h3 class="empty-title">{title}</h3>
	{#if description}
		<p class="empty-description">{description}</p>
	{/if}
	{#if actionLabel}
		<button class="btn btn-primary" onclick={handleAction}>{actionLabel}</button>
	{/if}
</div>

<style>
	.empty-state {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		padding: 3rem 1.5rem;
		text-align: center;
	}

	.empty-icon {
		font-size: 2.5rem;
		line-height: 1;
		margin-bottom: 1rem;
		color: var(--color-text-muted);
		display: flex;
		align-items: center;
		justify-content: center;
	}

	.empty-title {
		font-size: 1.125rem;
		font-weight: 600;
		color: var(--color-text);
		margin: 0 0 0.375rem;
		line-height: 1.4;
	}

	.empty-description {
		font-size: 0.875rem;
		color: var(--color-text-muted);
		margin: 0 0 1.25rem;
		line-height: 1.5;
		max-width: 24rem;
	}
</style>
