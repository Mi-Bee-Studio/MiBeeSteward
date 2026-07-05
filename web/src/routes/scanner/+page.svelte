<script lang="ts">
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	onMount(() => {
		goto('/devices/scan-tasks', { replaceState: true });
	});
</script>
