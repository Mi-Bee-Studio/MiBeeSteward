<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { echarts, type EChartsOption } from '$lib/charts/echarts';
	import { onMount } from 'svelte';
	import { m } from '$lib/i18n-paraglide';

	let {
		option = $bindable(),
		width = '100%',
		height = '300px',
		onclick,
		ondblclick
	}: {
		option: EChartsOption;
		width?: string;
		height?: string;
		// onclick fires for ECharts series clicks (node/edge). The payload is the
		// raw ECharts event object; inspect dataType ('node'|'edge') + data.value.
		onclick?: (params: Record<string, unknown>) => void;
		// ondblclick fires for ECharts series double-clicks (node/edge).
		ondblclick?: (params: Record<string, unknown>) => void;
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

	// Bind the click handler whenever it or the instance changes. ECharts
	// 'click' events carry the series payload (node/edge data) — distinct from
	// DOM clicks, which is why we forward via the instance API.
	$effect(() => {
		if (!instance) return;
		const handler = onclick;
		if (!handler) return;
		const fn = (params: Record<string, unknown>) => handler(params);
		instance.on('click', fn);
		return () => {
			instance.off('click', fn);
		};
	});

	// Bind the double-click handler whenever it or the instance changes.
	$effect(() => {
		if (!instance) return;
		const handler = ondblclick;
		if (!handler) return;
		const fn = (params: Record<string, unknown>) => handler(params);
		instance.on('dblclick', fn);
		return () => {
			instance.off('dblclick', fn);
		};
	});
</script>

{#if chartError}
	<div class="flex items-center justify-center rounded-lg border border-error/30 bg-error/10 text-error text-sm" style="width: {width}; height: {height};">
		<span>{m['common.Chart Unavailable']()}</span>
	</div>
{:else}
	<div bind:this={container} class="echarts-container" style="width: {width}; height: {height};"></div>
{/if}