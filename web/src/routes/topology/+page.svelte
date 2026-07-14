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
	import { Share2 as TopologyIcon, List as ListIcon, Network as GraphIcon } from '@lucide/svelte';
	import Chart from '$lib/components/Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import type { TopologyGraph, TopoNode } from '$lib/types';

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
	let viewMode = $state<'list' | 'graph'>('list'); // list = human-readable default
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

	let hasEdges = $derived((graph?.edges.length ?? 0) > 0);
	let hasNodes = $derived((graph?.nodes.length ?? 0) > 0);

	// --- List view: devices grouped by type, searchable, scannable ---
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
	// Group filtered nodes by type category for the list view.
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

	function statusDotClass(status: string): string {
		if (status === 'online') return 'bg-success';
		if (status === 'offline') return 'bg-error';
		return 'bg-text-muted';
	}

	// --- Graph view (only when there are edges) ---
	let topologyOption = $derived<EChartsOption | null>(hasEdges ? buildOption(graph, q) : null);

	function buildOption(g: TopologyGraph | null, search: string): EChartsOption | null {
		if (!g || g.nodes.length === 0 || g.edges.length === 0) return null;
		const nodeCount = g.nodes.length;
		const showLabels = nodeCount <= 50;
		const matched = new Set<string>();
		if (search) {
			for (const n of g.nodes) {
				if (
					(n.name || '').toLowerCase().includes(search) ||
					(n.ip_address || '').toLowerCase().includes(search) ||
					(n.mac_address || '').toLowerCase().includes(search)
				) {
					matched.add(String(n.id));
				}
			}
		}

		const knownMACs = new Set(g.nodes.map((n) => n.mac_address).filter(Boolean));
		const syntheticNodes = new Map<string, { mac: string; protocol: string }>();
		for (const e of g.edges) {
			if (e.to_mac && !knownMACs.has(e.to_mac) && !syntheticNodes.has(e.to_mac)) {
				syntheticNodes.set(e.to_mac, { mac: e.to_mac, protocol: e.protocol });
			}
		}

		const echartsNodes = [
			...g.nodes.map((n) => {
				const cat = nodeCategory(n);
				const isMatch = search && matched.has(String(n.id));
				const dimmed = search && !isMatch;
				return {
					id: String(n.id),
					name: n.name || n.ip_address || `#${n.id}`,
					category: cat,
					symbolSize: nodeCount > 100 ? 20 : nodeCount > 50 ? 28 : 38,
					value: n,
					label: { show: showLabels || isMatch, position: 'right', fontSize: 10, color: dimmed ? '#475569' : '#e2e8f0' },
					itemStyle: { opacity: dimmed ? 0.2 : 1 }
				};
			}),
			...[...syntheticNodes.values()].map((s) => ({
				id: `mac:${s.mac}`,
				name: s.mac,
				category: 'other',
				symbolSize: 22,
				itemStyle: { color: typeColors.other, opacity: 0.5 },
				label: { show: showLabels, fontSize: 9, color: '#94a3b8' }
			}))
		];

		const echartsEdges = g.edges.map((e, i) => {
			const target = e.to_device_id ? String(e.to_device_id) : `mac:${e.to_mac}`;
			return {
				id: `e${i}`,
				source: String(e.from_device_id),
				target,
				lineStyle: {
					color: e.protocol === 'LLDP' ? '#3b82f6' : '#10b981',
					width: e.protocol === 'LLDP' ? 2 : 1,
					type: e.to_device_id ? 'solid' : 'dashed',
					opacity: 0.6
				},
				value: e
			};
		});

		const repulsion = Math.max(120, nodeCount * 6);

		return {
			tooltip: {
				formatter: (p: any) => {
					if (p.dataType === 'node') {
						const v = p.data.value as TopoNode | undefined;
						if (!v) return escapeHtml(p.data.name);
						return `<b>${escapeHtml(v.name)}</b><br/>IP: ${escapeHtml(v.ip_address || '-')}` +
							`<br/>MAC: ${escapeHtml(v.mac_address || '-')}` +
							`<br/>Type: ${escapeHtml(v.type || '-')}` +
							`<br/>Status: ${escapeHtml(v.status || '-')}`;
					}
					const e = p.data.value as { protocol: string; local_port?: string | null } | undefined;
					return e ? `${escapeHtml(e.protocol)}${e.local_port ? ' · port ' + escapeHtml(e.local_port) : ''}` : '';
				}
			},
			legend: {
				data: typeCategories.filter((c) => g.nodes.some((n) => nodeCategory(n) === c)),
				textStyle: { color: '#cbd5e1' },
				top: 10
			},
			animationDuration: 800,
			animationEasingUpdate: 'cubicOut',
			series: [
				{
					type: 'graph',
					layout: 'force',
					roam: true,
					draggable: true,
					label: { show: showLabels, position: 'right', fontSize: 10, color: '#e2e8f0' },
					force: { repulsion, edgeLength: [80, 200], gravity: 0.01, layoutAnimation: true },
					categories: typeCategories.map((c) => ({ name: c, itemStyle: { color: typeColors[c] } })),
					data: echartsNodes,
					links: echartsEdges,
					edgeSymbol: ['none', 'arrow'],
					edgeSymbolSize: 6,
					emphasis: { focus: 'adjacency', lineStyle: { width: 3 }, label: { show: true } }
				}
			]
		};
	}

	function onChartClick(ev: { dataType: string; data: { value?: TopoNode } }) {
		if (ev.dataType === 'node' && ev.data.value?.id) {
			goto(`/devices/detail/${ev.data.value.id}`);
		}
	}
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
			<select
				bind:value={selectedNetwork}
				onchange={onNetworkChange}
				class="px-3 py-2 bg-surface border border-border rounded-lg text-sm text-text"
			>
				<option value={null}>{m['topology.All Networks']?.() ?? 'All networks'}</option>
				{#each networks as net}
					<option value={net.id}>{net.name}{net.site ? ` · ${net.site}` : ''}</option>
				{/each}
			</select>
			<!-- View toggle: list (default, human-readable) vs graph (needs edges) -->
			<div class="flex border border-border rounded-lg overflow-hidden">
				<button
					onclick={() => (viewMode = 'list')}
					class="px-3 py-2 text-sm flex items-center gap-1.5 transition-colors {viewMode === 'list' ? 'bg-primary text-white' : 'text-text-muted hover:text-text'}"
				>
					<ListIcon class="w-4 h-4" />
					{m['topology.List View']?.() ?? 'List'}
				</button>
				<button
					onclick={() => (viewMode = 'graph')}
					class="px-3 py-2 text-sm flex items-center gap-1.5 transition-colors {viewMode === 'graph' ? 'bg-primary text-white' : 'text-text-muted hover:text-text'}"
					disabled={!hasEdges}
					title={hasEdges ? '' : (m['topology.Graph Disabled']?.() ?? 'No L2 edges — graph needs adjacency data')}
				>
					<GraphIcon class="w-4 h-4" />
					{m['topology.Graph View']?.() ?? 'Graph'}
				</button>
			</div>
			<input
				type="text"
				bind:value={searchQuery}
				placeholder={m['topology.Search Placeholder']?.() ?? 'Find device...'}
				class="px-3 py-2 bg-surface border border-border rounded-lg text-sm text-text w-44"
			/>
			<button
				onclick={() => fetchTopology()}
				class="px-4 py-2 border border-border text-text-muted rounded-lg hover:border-primary hover:text-primary transition-colors text-sm"
			>
				{m['dashboard.Refresh']()}
			</button>
		</div>
	</div>

	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{error}
		</div>
	{/if}

	{#if loading}
		<PageSkeleton type="table" />
	{:else if !hasNodes}
		<EmptyState
			icon={TopologyIcon}
			title={m['topology.Empty']?.() ?? 'No topology data yet'}
			description={m['topology.Empty Desc']?.() ?? 'L2 neighbor edges (Bridge-MIB / LLDP) are populated when switches are scanned. Run a scan that includes managed switches.'}
		/>
	{:else if viewMode === 'list'}
		<!-- LIST VIEW (default): devices grouped by type. This is what a human
		     actually scans — no overlapping nodes, just a scannable inventory. -->
		<div class="flex flex-wrap items-center gap-4 mb-4 text-xs text-text-muted">
			<span>{filteredNodes.length} / {(graph?.nodes.length ?? 0)} {m['topology.Nodes']?.() ?? 'devices'}</span>
			<span>{(graph?.edges.length ?? 0)} {m['topology.Edges']?.() ?? 'adjacencies'}</span>
			{#if !hasEdges}
				<span class="px-2 py-0.5 rounded-full bg-amber-500/10 text-amber-400">
					{m['topology.No Edges Hint']?.() ?? 'No L2 edges yet — scan managed switches to populate adjacency'}
				</span>
			{/if}
		</div>
		<div class="space-y-4">
			{#each groupedNodes as group}
				<div class="bg-surface border border-border rounded-lg overflow-hidden">
					<!-- Group header: type dot + label + count -->
					<div class="flex items-center gap-2 px-4 py-2.5 bg-bg/50 border-b border-border">
						<span class="inline-block w-3 h-3 rounded-full {typeDotClass[group.type]}"></span>
						<span class="text-sm font-semibold text-text">{group.label}</span>
						<span class="text-xs text-text-muted">{group.devices.length}</span>
					</div>
					<!-- Device rows -->
					<div class="divide-y divide-border/50">
						{#each group.devices as dev}
							<a
								href={`/devices/detail/${dev.id}`}
								class="flex items-center gap-3 px-4 py-2 hover:bg-bg/30 transition-colors"
							>
								<span class="inline-block w-2 h-2 rounded-full {statusDotClass(dev.status)} shrink-0"></span>
								<span class="text-sm text-text font-medium truncate flex-1 min-w-0">{dev.name || dev.ip_address || `#${dev.id}`}</span>
								{#if dev.ip_address}
									<span class="text-xs font-mono text-text-muted hidden sm:inline">{dev.ip_address}</span>
								{/if}
								{#if dev.brand}
									<span class="text-xs text-text-muted hidden md:inline truncate max-w-[120px]">{dev.brand}</span>
								{/if}
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
	{:else if !hasEdges}
		<!-- Graph mode selected but no edges → explanatory empty state -->
		<div class="bg-surface border border-border rounded-lg p-8 text-center">
			<TopologyIcon class="w-12 h-12 mx-auto text-text-muted mb-4" />
			<h3 class="text-lg font-semibold text-text mb-2">
				{m['topology.No Edges Title']?.() ?? 'No L2 adjacency discovered yet'}
			</h3>
			<p class="text-sm text-text-muted max-w-md mx-auto">
				{m['topology.No Edges Desc']?.() ??
					'There are devices in this network, but no L2 neighbor edges (Bridge-MIB / LLDP). Run a scan that includes managed switches to populate the topology graph.'}
			</p>
		</div>
	{:else}
		<!-- GRAPH VIEW: force-directed, only shown when edges exist -->
		<div class="flex flex-wrap items-center gap-4 mb-3 text-xs text-text-muted">
			<span>{(graph?.nodes.length ?? 0)} {m['topology.Nodes']?.() ?? 'devices'}</span>
			<span>{(graph?.edges.length ?? 0)} {m['topology.Edges']?.() ?? 'adjacencies'}</span>
			<span class="flex items-center gap-1.5">
				<span class="inline-block w-6 h-0.5" style="background:#3b82f6"></span>LLDP
			</span>
			<span class="flex items-center gap-1.5">
				<span class="inline-block w-6 h-0.5" style="background:#10b981"></span>Bridge-MIB
			</span>
			<span class="flex items-center gap-1.5">
				<span class="inline-block w-6 h-0 border-t border-dashed border-text-muted"></span>
				{m['topology.Unidentified']?.() ?? 'unidentified neighbor'}
			</span>
		</div>
		<div class="bg-surface border border-border rounded-lg p-2">
			<Chart option={topologyOption} height="70vh" onclick={(p) => onChartClick(p as unknown as { dataType: string; data: { value?: TopoNode } })} />
		</div>
		<p class="text-xs text-text-muted mt-2">{m['topology.Click Hint']?.() ?? 'Click a device node to open its detail page. Drag to rearrange; scroll to zoom.'}</p>
	{/if}
</div>
{/if}
