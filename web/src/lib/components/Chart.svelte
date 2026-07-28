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
	import { LoaderCircle } from '@lucide/svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';

	let {
		option = $bindable(),
		width = '100%',
		height = '300px',
		loading = false,
		onclick,
		ondblclick
	}: {
		option: EChartsOption;
		width?: string;
		height?: string;
		// When true, the chart shows a spinner overlay on top of the canvas.
		// Parent components toggle this during refetches so the chart doesn't
		// visually freeze on stale data while waiting for the next payload.
		loading?: boolean;
		// onclick fires for ECharts series clicks (node/edge). The payload is the
		// raw ECharts event object; inspect dataType ('node'|'edge') + data.value.
		onclick?: (params: Record<string, unknown>) => void;
		// ondblclick fires for ECharts series double-clicks (node/edge).
		ondblclick?: (params: Record<string, unknown>) => void;
	} = $props();

	let container: HTMLDivElement | undefined = $state();
	let instance: ReturnType<typeof echarts.init> | undefined = $state();
	let chartError = $state(false);

	// Detect an empty dataset so we can show an EmptyState instead of a blank
	// canvas. An option is "empty" when it has no series, or every series has an
	// empty/nonexistent data array. A blank canvas with no explanation was
	// confusing when a query returned no rows (#71).
	let isEmpty = $derived.by(() => {
		const series = option?.series;
		if (!series) return true;
		const arr = Array.isArray(series) ? series : [series];
		if (arr.length === 0) return true;
		return arr.every(
			(s) => !s || (s as { data?: unknown }).data == null || ((s as { data?: unknown[] }).data?.length ?? 0) === 0
		);
	});

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

		// Watch the container's size directly. A window 'resize' listener alone
		// misses cases where the container changes size without the window
		// resizing — e.g. an accordion expanding, a modal opening, or a sidebar
		// collapsing — which left the chart squeezed into its old (often 0-width)
		// box. ResizeObserver fires on those layout transitions.
		const resizeObserver = new ResizeObserver(() => {
			instance?.resize();
		});
		if (container) resizeObserver.observe(container);

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
			resizeObserver.disconnect();
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

	// Loading overlay: parent sets `loading` while refetching. We render a CSS
	// overlay rather than ECharts' built-in showLoading() to avoid pulling in the
	// (unregistered here) LoadingComponent and to keep the spinner consistent
	// with the rest of the app's LoaderCircle icon.

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
{:else if isEmpty}
	<div class="flex items-center justify-center" style="width: {width}; height: {height};">
		<EmptyState title={m['common.No Data']()} />
	</div>
{:else}
	<div class="relative" style="width: {width}; height: {height};">
		<div bind:this={container} class="echarts-container" style="width: 100%; height: 100%;"></div>
		{#if loading}
			<div class="absolute inset-0 flex items-center justify-center bg-surface/60 backdrop-blur-sm rounded-lg">
				<LoaderCircle class="w-6 h-6 animate-spin text-primary" aria-hidden="true" />
				<span class="sr-only">{m['common.Loading']()}</span>
			</div>
		{/if}
	</div>
{/if}