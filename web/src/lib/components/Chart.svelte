<script lang="ts">
	import { echarts, type EChartsOption } from '$lib/charts/echarts';
	import { onMount } from 'svelte';

	let {
		option = $bindable(),
		width = '100%',
		height = '300px'
	}: {
		option: EChartsOption;
		width?: string;
		height?: string;
	} = $props();

	let container: HTMLDivElement | undefined = $state();
	let instance: ReturnType<typeof echarts.init> | undefined = $state();
let chartError = $state(false);
function initChart() {
		if (!container) return;
		if (instance) {
			instance.dispose();
		}
		try {
			instance = echarts.init(container);
			chartError = false;
		} catch {
			chartError = true;
		}
	}

	onMount(() => {
		initChart();

		const handleResize = () => instance?.resize();
		window.addEventListener('resize', handleResize);

		// Watch for theme changes (data-theme attribute on <html>)
		const observer = new MutationObserver(() => {
			initChart();
		});
		observer.observe(document.documentElement, {
			attributes: true,
			attributeFilter: ['data-theme']
		});

		return () => {
			window.removeEventListener('resize', handleResize);
			observer.disconnect();
			instance?.dispose();
			instance = undefined;
		};
	});

	$effect(() => {
		if (instance && option && !chartError) {
			instance.setOption(option);
		}
	});
</script>

{#if chartError}
	<div class="flex items-center justify-center rounded-lg border border-error/30 bg-error/10 text-error text-sm" style="width: {width}; height: {height};">
		<span>Chart unavailable</span>
	</div>
{:else}
	<div bind:this={container} class="echarts-container" style="width: {width}; height: {height};"></div>
{/if}
