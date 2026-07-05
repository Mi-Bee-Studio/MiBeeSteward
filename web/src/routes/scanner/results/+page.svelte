<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	onMount(() => {
		goto('/devices/scan-results', { replaceState: true });
	});
</script>
