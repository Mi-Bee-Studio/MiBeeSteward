<script lang="ts">
	import Skeleton from './Skeleton.svelte';

	let { type }: { type: 'dashboard' | 'table' | 'form' } = $props();
</script>

{#if type === 'dashboard'}
	<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
		<Skeleton variant="rect" width="100%" height="200px" />
		<Skeleton variant="rect" width="100%" height="200px" />
		<Skeleton variant="rect" width="100%" height="200px" />
		<Skeleton variant="rect" width="100%" height="200px" />
	</div>
{:else if type === 'table'}
	<div class="space-y-4">
		<!-- Header row -->
		<div class="flex gap-4 pb-3 border-b border-border">
			<Skeleton variant="text" width="30%" height="0.875rem" />
			<Skeleton variant="text" width="25%" height="0.875rem" />
			<Skeleton variant="text" width="20%" height="0.875rem" />
			<Skeleton variant="text" width="15%" height="0.875rem" />
		</div>
		<!-- Data rows -->
		{#each Array(5) as _, i (i)}
			<div class="flex gap-4 py-3 {i < 4 ? 'border-b border-border' : ''}">
				<Skeleton variant="text" width="30%" height="0.875rem" />
				<Skeleton variant="text" width="25%" height="0.875rem" />
				<Skeleton variant="text" width="20%" height="0.875rem" />
				<Skeleton variant="text" width="15%" height="0.875rem" />
			</div>
		{/each}
	</div>
{:else if type === 'form'}
	<div class="space-y-6 max-w-lg">
		<!-- 3 form fields with label + input -->
		{#each Array(3) as _, i (i)}
			<div class="space-y-1.5">
				<Skeleton variant="text" width="6rem" height="0.75rem" />
				<Skeleton variant="rect" width="100%" height="2.5rem" />
			</div>
		{/each}
		<!-- Button skeleton -->
		<div class="pt-2">
			<Skeleton variant="rect" width="8rem" height="2.5rem" />
		</div>
	</div>
{/if}
