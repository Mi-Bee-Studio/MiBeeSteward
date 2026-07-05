<script lang="ts">
	let { variant = 'text', width, height, count = 1 }: {
		variant?: 'text' | 'rect' | 'circle';
		width?: string;
		height?: string;
		count?: number;
	} = $props();

	const items = $derived(Array.from({ length: count }));
</script>

{#each items as _item, i (i)}
	{#if variant === 'circle'}
		<div
			class="skeleton skeleton-circle"
			style="width: {width ?? '2.5rem'}; height: {width ?? '2.5rem'}"
		></div>
	{:else if variant === 'rect'}
		<div
			class="skeleton skeleton-rect"
			style="width: {width ?? '100%'}; height: {height ?? '6rem'}"
		></div>
	{:else}
		<div
			class="skeleton skeleton-text"
			style="width: {width ?? '100%'}; height: {height ?? '1rem'}"
		></div>
	{/if}
{/each}

<style>
	.skeleton {
		background: var(--color-border);
		border-radius: var(--radius-sm);
		animation: sk-pulse 1.5s ease-in-out infinite;
		flex-shrink: 0;
	}

	.skeleton-text {
		border-radius: var(--radius-sm);
	}

	.skeleton-circle {
		border-radius: 9999px;
	}

	@keyframes sk-pulse {
		0%, 100% { opacity: 0.3; }
		50% { opacity: 0.6; }
	}
</style>
