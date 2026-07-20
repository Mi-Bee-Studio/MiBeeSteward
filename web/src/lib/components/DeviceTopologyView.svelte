<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  DeviceTopologyView — the radial L2-topology graph, extracted from the old
  standalone /topology page so it can render as a view inside /devices.

  Only the radial tree view is kept. The old page also had list-by-type and
  subnet-grouping views, but those are just alternate groupings of the device
  table (which /devices already provides) — only the radial graph (which needs
  the /topology API's LLDP/CDP/Bridge-MIB edges) is unique, so only it earns a
  place here.

  Props:
    networkId — the currently-selected network filter from the devices page
                (empty/null = all networks). Passed through to /topology?network_id=.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { goto } from '$app/navigation';
	import { escapeHtml } from '$lib/utils';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import Chart from '$lib/components/Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import type { TopologyGraph, Device } from '$lib/types';
	import { buildTree, type TreeNode } from '$lib/utils/topologyTree';
	import { Share2 } from '@lucide/svelte';

	let {
		networkId = ''
	}: {
		networkId?: string;
	} = $props();

	let graph = $state<TopologyGraph | null>(null);
	let loading = $state(true);
	let error = $state('');
	let searchQuery = $state('');
	let pollTimer: ReturnType<typeof setInterval> | null = null;
	let fetchSeq = 0;
	let prevSignature = '';

	onMount(() => {
		fetchTopology();
		pollTimer = setInterval(() => fetchTopology(true), 60000);
	});
	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});

	// Refetch when the network filter changes (prop reactivity).
	$effect(() => {
		void networkId; // track
		fetchTopology();
	});

	async function fetchTopology(silent = false) {
		const seq = ++fetchSeq;
		try {
			const qs = networkId ? `?network_id=${networkId}` : '';
			const fresh = await api.get<TopologyGraph>(`/topology${qs}`);
			if (seq !== fetchSeq) return;
			const sig = graphSignature(fresh);
			if (silent && sig === prevSignature) return;
			prevSignature = sig;
			graph = fresh;
			error = '';
		} catch (err: unknown) {
			if (seq !== fetchSeq) return;
			error = getErrorMessage(err);
		} finally {
			if (seq === fetchSeq) loading = false;
		}
	}

	function graphSignature(g: TopologyGraph): string {
		const nodeIds = g.nodes.map((n) => n.id).sort((a, b) => a - b).join(',');
		const edgeKeys = g.edges
			.map((e) => `${e.from_device_id}>${e.to_device_id ?? e.to_mac}:${e.protocol}`)
			.sort()
			.join(',');
		return `${g.nodes.length}|${g.edges.length}|${nodeIds}|${edgeKeys}`;
	}

	// Read a computed CSS variable so ECharts (canvas-rendered, can't resolve
	// var(...)) follows the theme.
	function cssVar(name: string, fallback: string): string {
		const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
		return v || fallback;
	}

	function typeColor(type: string): string {
		const tokenByType: Record<string, [string, string]> = {
			switch: ['--color-info', '#3b82f6'],
			router: ['--color-accent-purple', '#8b5cf6'],
			firewall: ['--color-error', '#ef4444'],
			server: ['--color-success', '#10b981'],
			nas: ['--color-warning', '#f59e0b'],
			camera: ['--color-accent-cyan', '#ec4899'],
			pc: ['--color-accent-cyan', '#06b6d4'],
			embedded: ['--color-muted', '#64748b'],
			iot: ['--color-success', '#84cc16'],
			other: ['--color-muted', '#94a3b8']
		};
		const [token, fallback] = tokenByType[type] ?? ['--color-muted', '#94a3b8'];
		return cssVar(token, fallback);
	}

	function nodeCategory(n: Device): string {
		const sa = n.scan_attributes as { inferred_type?: string } | undefined;
		return (sa?.inferred_type || n.type || 'other').toLowerCase();
	}

	function typeLabel(type: string): string {
		const labels: Record<string, string> = {
			pc: m['devices.PC'](),
			embedded: m['devices.Embedded'](),
			iot: m['devices.IoT'](),
			server: m['devices.Server'](),
			switch: m['devices.Switch'](),
			router: m['devices.Router'](),
			firewall: m['devices.Firewall'](),
			nas: m['devices.NAS'](),
			camera: m['devices.Camera'](),
			other: m['devices.Other']()
		};
		return labels[type] ?? type;
	}

	let treeOption = $derived<EChartsOption | null>(buildTreeOption(graph, searchQuery));

	function buildTreeOption(g: TopologyGraph | null, search: string): EChartsOption | null {
		if (!g || g.nodes.length === 0) return null;
		const { roots } = buildTree(g);
		if (roots.length === 0) return null;

		function mapNode(node: TreeNode): any {
			const n = node.value;
			const cat = nodeCategory(n);
			const isMatch = search && (
				(n.name || '').toLowerCase().includes(search) ||
				(n.ip_address || '').toLowerCase().includes(search) ||
				(n.mac_address || '').toLowerCase().includes(search)
			);
			const dimmed = search && !isMatch;
			const size = node.isRoot ? 44 : Math.max(12, Math.min(34, 10 + node.childCount * 3));
			return {
				name: node.name,
				value: node,
				children: node.children.map(mapNode),
				symbolSize: size,
				itemStyle: {
					color: typeColor(cat),
					opacity: dimmed ? 0.2 : 1
				},
				label: {
					show: true,
					position: 'radial' as const,
					fontSize: 10,
					color: dimmed ? cssVar('--color-muted', '#475569') : cssVar('--color-text', '#e2e8f0'),
					formatter: () => n.name || n.ip_address || `#${n.id}`
				}
			};
		}

		let data: any[];
		if (roots.length === 1) {
			data = [mapNode(roots[0])];
		} else {
			data = [{
				name: '', value: null, children: roots.map(mapNode),
				symbolSize: 0, label: { show: false }, itemStyle: { opacity: 0 }
			}];
		}

		const activeCategories = [...new Set(g.nodes.map(n => nodeCategory(n)))];

		return {
			tooltip: {
				formatter: (p: any) => {
					if (p.dataType === 'node') {
						const v = p.data.value as TreeNode | undefined;
						if (!v || !v.value) return '';
						const n = v.value;
						const gw = v.isRoot ? ` ⭐ ${escapeHtml(m['topology.Gateway']())}` : '';
						const portInfo = v.parentPort
							? `<br/>Via: ${escapeHtml(v.edgeProtocol ?? '')}${v.parentPort ? ' · port ' + escapeHtml(v.parentPort) : ''}`
							: '';
						return `<b>${escapeHtml(n.name)}</b>${gw}<br/>IP: ${escapeHtml(n.ip_address || '-')}<br/>MAC: ${escapeHtml(n.mac_address || '-')}<br/>Type: ${escapeHtml(typeLabel(nodeCategory(n)))}<br/>Status: ${escapeHtml(n.status || '-')}${portInfo}<br/>Downstream: ${v.childCount} devices`;
					}
					return '';
				}
			},
			legend: { data: activeCategories, textStyle: { color: cssVar('--color-text-muted', '#cbd5e1') }, top: 10 },
			animationDuration: 600,
			series: [{
				type: 'tree',
				data: data,
				layout: 'radial',
				symbol: 'circle',
				roam: true,
				label: { show: false, position: 'radial', fontSize: 10, color: cssVar('--color-text', '#e2e8f0') },
				leaves: { label: { position: 'radial', fontSize: 10, color: cssVar('--color-text', '#e2e8f0') } },
				emphasis: { focus: 'descendant', lineStyle: { width: 2 } },
				expandAndCollapse: true,
				initialTreeDepth: -1,
				lineStyle: { curveness: 0.5, color: cssVar('--color-border-strong', '#64748b'), width: 1 },
			}]
		};
	}

	function onNodeDblClick(ev: { dataType: string; data: { value?: TreeNode } }) {
		if (ev.dataType === 'node' && ev.data.value?.value?.id) goto('/devices/detail/' + ev.data.value.value.id);
	}
</script>

<div class="flex flex-col gap-3 h-full">
	<!-- Search (client-side filter over graph nodes) + refresh -->
	<div class="flex items-center gap-2">
		<input
			type="text"
			bind:value={searchQuery}
			placeholder={m['common.Search']() + '…'}
			class="input max-w-xs"
		/>
		<div class="flex-1"></div>
		<button
			onclick={() => fetchTopology()}
			class="btn btn-secondary text-sm"
		>{m['dashboard.Refresh']()}</button>
	</div>

	{#if loading}
		<PageSkeleton type="table" />
	{:else if error}
		<div class="px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite">
			{error}
		</div>
	{:else if !graph || graph.nodes.length === 0}
		<EmptyState
			icon={Share2}
			title={m['topology.Empty']()}
			description={m['topology.Empty Desc']()}
		/>
	{:else if !treeOption}
		<!-- Nodes exist but no edges → can't build a tree. -->
		<EmptyState
			icon={Share2}
			title={m['topology.No Edges Title']()}
			description={m['topology.No Edges Desc']()}
		/>
	{:else}
		<div class="bg-surface border border-border rounded-lg p-2 flex-1 min-h-[500px]">
			<Chart option={treeOption} height="600px" ondblclick={onNodeDblClick} />
		</div>
		<p class="text-xs text-muted">
			{m['topology.Click Hint']()}
		</p>
	{/if}
</div>
