<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import { goto } from '$app/navigation';
	import { escapeHtml } from '$lib/utils';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { Share2 as TopologyIcon, List as ListIcon, Network as GraphIcon, GitBranch as SubnetIcon } from '@lucide/svelte';
	import Chart from '$lib/components/Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import type { TopologyGraph, TopoNode } from '$lib/types';
	import { buildTree, type TreeNode } from '$lib/utils/topologyTree';

	interface Network {
		id: number;
		name: string;
		cidr?: string | null;
		site?: string | null;
	}

	let graph = $state<TopologyGraph | null>(null);
	let prevSignature = '';
	let networks = $state<Network[]>([]);
	let selectedNetwork = $state<number | null>(null);
	let loading = $state(true);
	let error = $state('');
	let viewMode = $state<'list' | 'subnet' | 'tree'>('tree');
	let searchQuery = $state('');
	let pollTimer: ReturnType<typeof setInterval> | null = null;
	let fetchSeq = 0;

	onMount(() => {
		fetchNetworks();
		fetchTopology();
		pollTimer = setInterval(() => fetchTopology(true), 60000);
	});
	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});

	async function fetchNetworks() {
		try {
			const res = await api.get<{ networks: Network[] }>('/networks');
			networks = res.networks ?? [];
		} catch {
			// Non-fatal.
		}
	}

	async function fetchTopology(silent = false) {
		const seq = ++fetchSeq;
		try {
			const qs = selectedNetwork != null ? `?network_id=${selectedNetwork}` : '';
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

	function onNetworkChange() {
		loading = true;
		fetchTopology();
	}

	// --- type → color + label mapping ---
	const typeCategories = [
		'switch', 'router', 'firewall', 'server', 'nas', 'camera',
		'pc', 'embedded', 'iot', 'other'
	];
	const typeColors: Record<string, string> = {
		switch: '#3b82f6', router: '#8b5cf6', firewall: '#ef4444',
		server: '#10b981', nas: '#f59e0b', camera: '#ec4899',
		pc: '#06b6d4', embedded: '#64748b', iot: '#84cc16', other: '#94a3b8'
	};
	const typeDotClass: Record<string, string> = {
		switch: 'bg-blue-500', router: 'bg-violet-500', firewall: 'bg-red-500',
		server: 'bg-emerald-500', nas: 'bg-amber-500', camera: 'bg-pink-500',
		pc: 'bg-cyan-500', embedded: 'bg-slate-500', iot: 'bg-lime-500', other: 'bg-slate-400'
	};

	function nodeCategory(node: TopoNode): string {
		const inferred = (node.inferred_type || '').toLowerCase();
		if (typeCategories.includes(inferred)) return inferred;
		const t = (node.type || 'other').toLowerCase();
		return typeCategories.includes(t) ? t : 'other';
	}

	function typeLabel(t: string): string {
		const labels: Record<string, string> = {
			switch: m['devices.Switch']?.() ?? 'Switch',
			router: m['devices.Router']?.() ?? 'Router',
			firewall: m['devices.Firewall']?.() ?? 'Firewall',
			server: m['devices.Server']?.() ?? 'Server',
			nas: m['devices.NAS']?.() ?? 'NAS',
			camera: m['devices.Camera']?.() ?? 'Camera',
			pc: m['devices.PC']?.() ?? 'PC',
			embedded: m['devices.Embedded']?.() ?? 'Embedded',
			iot: m['devices.IoT']?.() ?? 'IoT',
			other: m['devices.Other']?.() ?? 'Other'
		};
		return labels[t] ?? t;
	}

	let hasNodes = $derived((graph?.nodes.length ?? 0) > 0);

	function statusDotClass(status: string): string {
		if (status === 'online') return 'bg-success';
		if (status === 'offline') return 'bg-error';
		return 'bg-text-muted';
	}

	// --- search filter (shared across all views) ---
	let q = $derived(searchQuery.trim().toLowerCase());
	let filteredNodes = $derived(
		(graph?.nodes ?? []).filter((n) => {
			if (!q) return true;
			return (
				(n.name || '').toLowerCase().includes(q) ||
				(n.ip_address || '').toLowerCase().includes(q) ||
				(n.mac_address || '').toLowerCase().includes(q)
			);
		})
	);

	// --- View 1: list grouped by type ---
	let groupedNodes = $derived.by(() => {
		const groups: Record<string, TopoNode[]> = {};
		for (const n of filteredNodes) {
			const cat = nodeCategory(n);
			(groups[cat] ??= []).push(n);
		}
		return typeCategories
			.filter((c) => groups[c]?.length)
			.map((c) => ({ type: c, label: typeLabel(c), devices: groups[c] }));
	});

	// --- View 2: subnet grouping ---
	// Extract /24 prefix from IP (first 3 octets). Group devices by subnet.
	function subnetKey(ip: string): string {
		const parts = ip.split('.');
		if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
		return m['topology.No Subnet']?.() ?? 'Unknown subnet';
	}

	let groupedBySubnet = $derived.by(() => {
		const subnets = new Map<string, TopoNode[]>();
		for (const n of filteredNodes) {
			const key = n.ip_address ? subnetKey(n.ip_address) : (m['topology.No Subnet']?.() ?? 'Unknown subnet');
			const arr = subnets.get(key) ?? [];
			arr.push(n);
			subnets.set(key, arr);
		}
		return [...subnets.entries()]
			.map(([subnet, devices]) => ({
				subnet,
				devices: devices.sort((a, b) => (a.ip_address || '').localeCompare(b.ip_address || '')),
				online: devices.filter((d) => d.status === 'online').length
			}))
			.sort((a, b) => a.subnet.localeCompare(b.subnet));
	});

	// --- View 3: topology tree (radial) ECharts option ---
	let treeOption = $derived<EChartsOption | null>(buildTreeOption(graph, q));

	function buildTreeOption(g: TopologyGraph | null, search: string): EChartsOption | null {
		if (!g || g.nodes.length === 0) return null;
		const { roots } = buildTree(g);
		if (roots.length === 0) return null;

		// Map TreeNode → ECharts tree node format
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
					color: typeColors[cat] ?? typeColors.other,
					opacity: dimmed ? 0.2 : 1
				},
				label: {
					show: true,
					position: 'radial' as const,
					fontSize: 10,
					color: dimmed ? '#475569' : '#e2e8f0',
					formatter: () => n.name || n.ip_address || `#${n.id}`
				}
			};
		}

		// If multiple roots (disconnected clusters), wrap in invisible synthetic root
		let data: any[];
		if (roots.length === 1) {
			data = [mapNode(roots[0])];
		} else {
			data = [{
				name: '', value: null, children: roots.map(mapNode),
				symbolSize: 0, label: { show: false }, itemStyle: { opacity: 0 }
			}];
		}

		// Legend: show only categories that exist in the graph
		const activeCategories = [...new Set(g.nodes.map(n => nodeCategory(n)))];

		return {
			tooltip: {
				formatter: (p: any) => {
					if (p.dataType === 'node') {
						const v = p.data.value as TreeNode | undefined;
						if (!v || !v.value) return '';
						const n = v.value;
						const gw = v.isRoot ? ` ⭐ ${escapeHtml(m['topology.Gateway']?.() ?? 'Gateway')}` : '';
						const portInfo = v.parentPort
							? `<br/>Via: ${escapeHtml(v.edgeProtocol ?? '')}${v.parentPort ? ' · port ' + escapeHtml(v.parentPort) : ''}`
							: '';
						return `<b>${escapeHtml(n.name)}</b>${gw}<br/>IP: ${escapeHtml(n.ip_address || '-')}<br/>MAC: ${escapeHtml(n.mac_address || '-')}<br/>Type: ${escapeHtml(typeLabel(nodeCategory(n)))}<br/>Status: ${escapeHtml(n.status || '-')}${portInfo}<br/>Downstream: ${v.childCount} devices`;
					}
					return '';
				}
			},
			legend: { data: activeCategories, textStyle: { color: '#cbd5e1' }, top: 10 },
			animationDuration: 600,
			series: [{
				type: 'tree',
				data: data,
				layout: 'radial',
				symbol: 'circle',
				roam: true,
				label: { show: false, position: 'radial', fontSize: 10, color: '#e2e8f0' },
				leaves: { label: { position: 'radial', fontSize: 10, color: '#e2e8f0' } },
				emphasis: { focus: 'descendant', lineStyle: { width: 2 } },
				expandAndCollapse: true,
				initialTreeDepth: -1,
				lineStyle: { curveness: 0.5, color: '#64748b', width: 1 },
			}]
		};
	}

	function onNodeDblClick(ev: { dataType: string; data: { value?: TreeNode } }) {
		if (ev.dataType === 'node' && ev.data.value?.value?.id) goto('/devices/detail/' + ev.data.value.value.id);
	}

	const viewButtons = $derived([
		{ mode: 'list' as const, icon: ListIcon, label: m['topology.List View']?.() ?? 'List' },
		{ mode: 'subnet' as const, icon: SubnetIcon, label: m['topology.Subnet View']?.() ?? 'Subnets' },
		{ mode: 'tree' as const, icon: GraphIcon, label: m['topology.Graph View']?.() ?? 'Topology Tree' }
	]);
</script>

{#if !$auth.token}
	<div class="p-6 text-center text-text-muted">
		<p>{m['errors.Unauthorized Desc']?.() ?? 'Please log in.'}</p>
		<a href="/login" class="text-primary hover:underline text-sm mt-2 inline-block">{m['navigation.Login']()}</a>
	</div>
{:else}
<div class="p-4 sm:p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6 flex-wrap gap-3">
		<h2 class="text-2xl font-bold text-primary">{m['topology.Title']?.() ?? 'Network Topology'}</h2>
		<div class="flex items-center gap-3 flex-wrap">
			<select bind:value={selectedNetwork} onchange={onNetworkChange}
				class="px-3 py-2 bg-surface border border-border rounded-lg text-sm text-text">
				<option value={null}>{m['topology.All Networks']?.() ?? 'All networks'}</option>
				{#each networks as net}
					<option value={net.id}>{net.name}{net.site ? ` · ${net.site}` : ''}</option>
				{/each}
			</select>
			<!-- View toggle: 3 modes -->
			<div class="flex border border-border rounded-lg overflow-hidden">
				{#each viewButtons as btn}
					<button
						onclick={() => (viewMode = btn.mode)}
						class="px-3 py-2 text-sm flex items-center gap-1.5 transition-colors whitespace-nowrap
							{viewMode === btn.mode ? 'bg-primary text-white' : 'text-text-muted hover:text-text'}"
					>
						<btn.icon class="w-4 h-4" />
						<span class="hidden sm:inline">{btn.label}</span>
					</button>
				{/each}
			</div>
			<input type="text" bind:value={searchQuery}
				placeholder={m['topology.Search Placeholder']?.() ?? 'Find device...'}
				class="px-3 py-2 bg-surface border border-border rounded-lg text-sm text-text w-44" />
			<button onclick={() => fetchTopology()}
				class="px-4 py-2 border border-border text-text-muted rounded-lg hover:border-primary hover:text-primary transition-colors text-sm">
				{m['dashboard.Refresh']()}
			</button>
		</div>
	</div>

	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">{error}</div>
	{/if}

	{#if loading}
		<PageSkeleton type="table" />
	{:else if !hasNodes}
		<EmptyState icon={TopologyIcon}
			title={m['topology.Empty']?.() ?? 'No topology data yet'}
			description={m['topology.Empty Desc']?.() ?? 'L2 neighbor edges (Bridge-MIB / LLDP) are populated when switches are scanned. Run a scan that includes managed switches.'} />
	{:else if viewMode === 'list'}
		<!-- VIEW 1: List grouped by type -->
		<div class="flex flex-wrap items-center gap-4 mb-4 text-xs text-text-muted">
			<span>{filteredNodes.length} / {(graph?.nodes.length ?? 0)} {m['topology.Nodes']?.() ?? 'devices'}</span>
			<span>{(graph?.edges.length ?? 0)} {m['topology.Edges']?.() ?? 'adjacencies'}</span>
		</div>
		<div class="space-y-4">
			{#each groupedNodes as group}
				<div class="bg-surface border border-border rounded-lg overflow-hidden">
					<div class="flex items-center gap-2 px-4 py-2.5 bg-bg/50 border-b border-border">
						<span class="inline-block w-3 h-3 rounded-full {typeDotClass[group.type]}"></span>
						<span class="text-sm font-semibold text-text">{group.label}</span>
						<span class="text-xs text-text-muted">{group.devices.length}</span>
					</div>
					<div class="divide-y divide-border/50">
						{#each group.devices as dev}
							<a href={`/devices/detail/${dev.id}`} class="flex items-center gap-3 px-4 py-2 hover:bg-bg/30 transition-colors">
								<span class="inline-block w-2 h-2 rounded-full {statusDotClass(dev.status)} shrink-0"></span>
								<span class="text-sm text-text font-medium truncate flex-1 min-w-0">{dev.name || dev.ip_address || `#${dev.id}`}</span>
								{#if dev.ip_address}<span class="text-xs font-mono text-text-muted hidden sm:inline">{dev.ip_address}</span>{/if}
								{#if dev.brand}<span class="text-xs text-text-muted hidden md:inline truncate max-w-[120px]">{dev.brand}</span>{/if}
							</a>
						{/each}
					</div>
				</div>
			{:else}
				<div class="bg-surface border border-border rounded-lg p-6 text-center text-sm text-text-muted">
					{m['topology.No Search Results']?.() ?? 'No devices match your search.'}
				</div>
			{/each}
		</div>
	{:else if viewMode === 'subnet'}
		<!-- VIEW 2: Subnet grouping -->
		<div class="flex flex-wrap items-center gap-4 mb-4 text-xs text-text-muted">
			<span>{filteredNodes.length} / {(graph?.nodes.length ?? 0)} {m['topology.Nodes']?.() ?? 'devices'}</span>
			<span>{groupedBySubnet.length} {m['topology.Subnets']?.() ?? 'subnets'}</span>
		</div>
		<div class="space-y-4">
			{#each groupedBySubnet as group}
				<div class="bg-surface border border-border rounded-lg overflow-hidden">
					<div class="flex items-center gap-2 px-4 py-2.5 bg-bg/50 border-b border-border">
						<SubnetIcon class="w-4 h-4 text-primary" />
						<span class="text-sm font-semibold font-mono text-text">{group.subnet}</span>
						<span class="text-xs text-text-muted">{group.devices.length} {m['topology.Nodes']?.() ?? 'devices'}</span>
						<span class="text-xs text-success">{group.online} {m['topology.Online']?.() ?? 'online'}</span>
					</div>
					<div class="divide-y divide-border/50">
						{#each group.devices as dev}
							<a href={`/devices/detail/${dev.id}`} class="flex items-center gap-3 px-4 py-2 hover:bg-bg/30 transition-colors">
								<span class="inline-block w-2 h-2 rounded-full {statusDotClass(dev.status)} shrink-0"></span>
								<span class="text-sm text-text font-medium truncate flex-1 min-w-0">{dev.name || dev.ip_address || `#${dev.id}`}</span>
								{#if dev.ip_address}<span class="text-xs font-mono text-text-muted">{dev.ip_address}</span>{/if}
								{#if dev.brand}<span class="text-xs text-text-muted hidden md:inline truncate max-w-[100px]">{dev.brand}</span>{/if}
							</a>
						{/each}
					</div>
				</div>
			{/each}
		</div>
	{:else if viewMode === 'tree'}
		<!-- VIEW: Radial topology tree -->
		<div class="flex flex-wrap items-center gap-4 mb-3 text-xs text-text-muted">
			<span>{(graph?.nodes.length ?? 0)} {m['topology.Nodes']?.() ?? 'devices'}</span>
			<span>{(graph?.edges.length ?? 0)} {m['topology.Edges']?.() ?? 'adjacencies'}</span>
		</div>
		<div class="bg-surface border border-border rounded-lg p-2">
			{#if treeOption}
				<Chart option={treeOption} height="70vh" ondblclick={(p: any) => onNodeDblClick(p as { dataType: string; data: { value?: TreeNode } })} />
			{:else}
				<EmptyState icon={TopologyIcon}
					title={m['topology.No Edges Title']?.() ?? 'No L2 adjacency discovered yet'}
					description={m['topology.No Edges Desc']?.() ?? 'Run a scan to discover device adjacencies.'} />
			{/if}
		</div>
		<p class="text-xs text-text-muted mt-2">{m['topology.Click Hint']?.() ?? 'Click to collapse/expand subtree; double-click to open device detail.'}</p>
	{/if}
</div>
{/if}