<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  DeviceTopologyView: the L2-topology view shell (issue #136; renderer split
  #635 PR1).

  Renders as a view inside /devices: fetches /topology, owns the toolbar
  (search, layer pills, edge-type legend, orphan toggle) and the drill-down
  panels, and mounts TopologyCanvas2D as the renderer. Rendering lives
  behind the canvas contract (see TopologyCanvas2D.svelte) so a 3D renderer
  can slot in beside the 2D one (#635 PR2).

  Interactions (canvas-side, dispatched up):
    - Click node   → highlight neighbors + show node detail (IP/MAC/type/degree)
    - Click edge   → show port drill-down (local ↔ remote port, protocol)
    - Double-click node → open device detail page
    - Search box   → dim non-matching nodes + their edges

  Root detection prefers the collected STP fact when a bridge reported itself
  as the dot1dStp root (#525); otherwise it is heuristic (detectRoot +
  device-type classification). See topologyGraph.ts.

  Props:
    networkId: the currently-selected network filter from the devices page
                (empty/null = all networks). Passed through to /topology?network_id=.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { goto } from '$app/navigation';
	import { resolveToken } from '$lib/utils/cssVar';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import TopologyCanvas2D from '$lib/components/TopologyCanvas2D.svelte';
	import type { TopologyGraph } from '$lib/types';
	import {
		buildGraph,
		LAYER_ORDER,
		LAYER_COLORS,
		protocolStyle,
		isSegmentBridge,
		formatPresence,
		edgeTypeCounts,
		WEAK_PROTOCOLS,
		isStaleEdge,
		edgeAgeMs,
		splitOrphans,
		missingEnrichmentFamilies,
		topologyFingerprint,
		typeBucketCounts,
		TYPE_BUCKET_COLORS,
		type GraphNode,
		type GraphLink,
		type TopoLayer
	} from '$lib/utils/topologyGraph';
	import { layerLabel, bucketLabel, typeLabel, deviceType, formatAge } from '$lib/utils/topologyLabels';
	import { Share2, X, Settings2 } from '@lucide/svelte';

	let {
		networkId = ''
	}: {
		networkId?: string;
	} = $props();

	let graph = $state<TopologyGraph | null>(null);
	let loading = $state(true);
	let error = $state('');
	let searchQuery = $state('');
	// Selected node/edge for the drill-down panels (mutually exclusive: clicking
	// one clears the other so only one panel shows at a time).
	let selectedNode = $state<GraphNode | null>(null);
	let selectedEdge = $state<GraphLink | null>(null);
	// Per-protocol edge visibility (#583): the edge-type legend doubles as a
	// filter, mirroring the layer pills above. Absent protocol = visible (the
	// map only stores explicit hides, so new protocols default to shown).
	let hiddenProtocols = $state<Record<string, boolean>>({});

	function toggleProtocol(protocol: string) {
		hiddenProtocols = { ...hiddenProtocols, [protocol]: !hiddenProtocols[protocol] };
	}

	// Orphan grouping (#584): devices with zero observed relations default to
	// a collapsed group node so the canvas carries relationship information
	// instead of a floating island ocean; one pill expands them back.
	let showOrphans = $state(false);
	let orphanPanelOpen = $state(false);

	// Node color mode + label density (user request 2026-11-03): color by
	// hierarchy layer (default) or by device-type bucket; labels auto (by
	// node count), forced all (identify every point) or none.
	let colorMode = $state<'layer' | 'type'>('layer');
	let labelMode = $state<'auto' | 'all' | 'none'>('auto');
	// Type-bucket chips: click to filter (user request 2026-11-03). All on by
	// default; combines with the layer pills (a node renders only when BOTH
	// its layer and its bucket are enabled).
	let bucketVisible = $state<Record<string, boolean>>({
		network: true,
		camera: true,
		computer: true,
		mobile: true,
		other: true
	});

	function toggleBucket(bucket: string) {
		bucketVisible = { ...bucketVisible, [bucket]: !bucketVisible[bucket] };
	}

	// 2D/3D renderer dimension (#635 PR2). The three.js chunk loads lazily on
	// the first 2D→3D toggle; the preference rides the URL (&dim=3d) like the
	// view= param. WebGL-less environments stay on 2D with a hint.
	type TopoDim = '2d' | '3d';
	let dim = $state<TopoDim>('2d');
	let Canvas3D = $state<typeof import('./TopologyCanvas3D.svelte').default | null>(null);
	let webglBlocked = $state(false);

	function webglSupported(): boolean {
		try {
			const c = document.createElement('canvas');
			return !!(c.getContext('webgl2') || c.getContext('webgl'));
		} catch {
			return false;
		}
	}

	async function setDim(next: TopoDim) {
		if (next === '3d') {
			if (!webglSupported()) {
				webglBlocked = true;
				return;
			}
			webglBlocked = false;
			if (!Canvas3D) Canvas3D = (await import('./TopologyCanvas3D.svelte')).default;
		}
		dim = next;
		const url = new URL(window.location.href);
		if (next === '3d') url.searchParams.set('dim', '3d');
		else url.searchParams.delete('dim');
		window.history.replaceState({}, '', url);
	}

	// Per-layer visibility (the legend doubles as a filter toggle). All on by default.
	let layerVisible = $state<Record<TopoLayer, boolean>>({
		root: true,
		core: true,
		access: true,
		edge: true
	});
	let pollTimer: ReturnType<typeof setInterval> | null = null;
	let panelTickTimer: ReturnType<typeof setInterval> | null = null;
	let themeObs: MutationObserver | null = null;
	// Bumped by the data-theme observer so toolbar token colors re-resolve (#639).
	let themeTick = $state(0);
	let fetchSeq = 0;
	let prevSignature = '';

	onMount(() => {
		// The first fetch belongs to the networkId $effect below (it tracks the
		// prop and fires on mount) — fetching here too doubled the request and
		// the first response was discarded by fetchSeq (#638).
		pollTimer = setInterval(() => fetchTopology(true), 60000);
		panelTickTimer = setInterval(() => (panelTick += 1), 30_000);
		// Theme flips must re-resolve the toolbar's token colors (#639): the
		// pills/legend read CSS variables at render time and a data-theme
		// change alone re-renders nothing.
		themeObs = new MutationObserver(() => (themeTick += 1));
		themeObs.observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });
		// Deep link ?dim=3d (#635): honor the persisted preference on mount.
		if (new URLSearchParams(window.location.search).get('dim') === '3d') void setDim('3d');
	});
	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
		if (panelTickTimer) clearInterval(panelTickTimer);
		themeObs?.disconnect();
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
			// #637: the fingerprint covers last_seen + status too, so silent
			// polls deliver freshness updates instead of short-circuiting on
			// an unchanged skeleton.
			const sig = topologyFingerprint(fresh);
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

	// Panel freshness (#637): "最后可见" ages and the stale verdict in the
	// edge panel are computed at render time — a shared 30s tick keeps them
	// moving on an otherwise static page (same cadence as the canvas tick).
	let panelTick = $state(0);

	// The selected edge's age/staleness verdict, recomputed on the tick.
	let selectedEdgeAge = $derived.by(() => {
		void panelTick; // track: time-driven verdicts
		if (!selectedEdge) return null;
		return { ageMs: edgeAgeMs(selectedEdge) ?? 0, stale: isStaleEdge(selectedEdge) };
	});

	// Build once per graph, feed every derived below (#584).
	let builtGraph = $derived(graph ? buildGraph(graph) : null);

	// Type-bucket census for the color-by-type legend.
	let typeStats = $derived(builtGraph ? typeBucketCounts(builtGraph.nodes) : []);

	// Edge types actually present in the graph (#583) — the legend lists only
	// these, with per-type counts.
	let edgeStats = $derived(builtGraph ? edgeTypeCounts(builtGraph.links) : []);

	// Theme-reactive resolved colors (#639): the toolbar pills/legend resolve
	// CSS-variable tokens at render time — re-resolve whenever data-theme
	// flips (themeTick) or the present protocol set changes.
	let toolbarColors = $derived.by(() => {
		void themeTick;
		return {
			layer: Object.fromEntries(LAYER_ORDER.map((l) => [l, resolveToken(LAYER_COLORS[l])])) as Record<TopoLayer, string>,
			protocol: Object.fromEntries(edgeStats.map((s) => [s.protocol, resolveToken(protocolStyle(s.protocol).color)])) as Record<string, string>,
			bucket: Object.fromEntries(
				Object.entries(TYPE_BUCKET_COLORS).map(([b, tc]) => [b, resolveToken(tc)])
			) as Record<string, string>
		};
	});

	// Orphan census (#584): degree-0 nodes (the root always stays drawn).
	let orphanNodes = $derived(builtGraph ? splitOrphans(builtGraph.nodes).orphans : []);

	// Enrichment gaps (#584): edge families with zero presence — the hints
	// link each family's source to the settings page where it's enabled.
	let enrichHints = $derived(builtGraph ? missingEnrichmentFamilies(builtGraph.links) : []);

	// Cross-segment bridge count (#556): nodes present in more than one
	// segment — the link points joining the LAN clusters. Zero on a
	// single-network view, so the pill adds no noise there.
	let bridgeCount = $derived.by(() => {
		if (!graph) return 0;
		return graph.nodes.filter((n) => isSegmentBridge(n)).length;
	});

	// Canvas contract handlers: the shell owns the mutually exclusive panel
	// state (node panel / edge panel / orphan member list).
	function handleSelectNode(gn: GraphNode | null) {
		selectedNode = gn;
		selectedEdge = null;
		orphanPanelOpen = false;
	}

	function handleSelectEdge(gl: GraphLink | null) {
		selectedEdge = gl;
		selectedNode = null;
	}

	function openOrphanPanel() {
		orphanPanelOpen = true;
		selectedNode = null;
		selectedEdge = null;
	}

	function openDevice(id: number) {
		goto('/devices/detail/' + id);
	}

	// Canvas-swap fade-in (#635 PR3): a short setTimeout-driven tween.
	// Deliberately NOT CSS/WAAPI (frozen document.timeline environments
	// leave those stuck at their start state) and NOT requestAnimationFrame
	// — the same frozen-clock hosts never fire rAF either, which left the
	// canvas stuck at the tween's start opacity (blanked the whole view).
	// setTimeout fires everywhere.
	function fadeSwap(node: HTMLElement) {
		const t0 = Date.now();
		const step = () => {
			const k = Math.min(1, (Date.now() - t0) / 180);
			node.style.opacity = String(0.25 + 0.75 * k);
			if (k < 1) setTimeout(step, 30);
		};
		node.style.opacity = '0.25';
		setTimeout(step, 30);
		// Belt and braces: never leave the canvas dimmed, whatever stalls.
		setTimeout(() => (node.style.opacity = '1'), 400);
	}

	// Offline endpoint check for the link panel (#585).
	function endpointOffline(l: GraphLink): boolean {
		if (!graph) return false;
		const src = graph.nodes.find((n) => n.id === l.source);
		if (src?.status === 'offline') return true;
		if (l.isUnidentified) return false;
		const dst = graph.nodes.find((n) => n.id === l.target);
		return dst?.status === 'offline';
	}

	// Why a port is missing (#583): protocol-aware explanation shown in the
	// link panel whenever an end shows a bare dash.
	function portHint(l: GraphLink): string {
		if (l.protocol === 'ARP') return m['topology.Port Hint ARP']();
		if (l.protocol === 'speaks-with') return m['topology.Port Hint Traffic']();
		if (l.protocol === 'LLDP' || l.protocol === 'CDP') return m['topology.Port Hint Lldp']();
		return m['topology.Port Hint Snmp']();
	}

	// Resolve a link's endpoint device names for the detail panel (nicer than
	// showing bare ids).
	function nodeNameById(id: number): string {
		if (!graph) return `#${id}`;
		const n = graph.nodes.find((x) => x.id === id);
		return n ? n.name || n.ip_address || `#${id}` : `#${id}`;
	}
</script>

<div class="flex flex-col gap-3 h-full">
	<!-- Toolbar: search + layer-filter toggles + refresh -->
	<div class="flex flex-wrap items-center gap-2">
		<input
			type="text"
			bind:value={searchQuery}
			placeholder={m['common.Search']() + '…'}
			class="input max-w-xs"
		/>
		<!-- Cross-segment bridges (#556): how many nodes join multiple segments -->
		{#if bridgeCount > 0}
			<span
				class="px-2 py-1 rounded-full border border-primary/60 text-primary text-xs inline-flex items-center gap-1"
				title={m['topology.Bridge Count Desc']()}
			>
				⇄ {m['topology.Bridge Count']({ n: bridgeCount })}
			</span>
		{/if}
		<!-- Orphan grouping toggle (#584): collapsed by default — the canvas
		     carries relationships, not an island ocean. -->
		{#if orphanNodes.length > 0}
			<button
				onclick={() => (showOrphans = !showOrphans)}
				aria-pressed={showOrphans}
				class="px-2 py-1 rounded-full border border-border bg-surface text-xs transition-colors hover:border-border-strong"
				title={m['topology.Orphan Panel Desc']()}
			>
				{showOrphans ? m['topology.Orphan Hide']() : m['topology.Orphan Show']()}
				<span class="text-muted font-mono ml-1">×{orphanNodes.length}</span>
			</button>
		{/if}
		<!-- Layer filter pills (also reflected in the legend) -->
		<div class="flex items-center gap-1 text-xs">
			{#each LAYER_ORDER as layer}
				<button
					onclick={() => (layerVisible = { ...layerVisible, [layer]: !layerVisible[layer] })}
					aria-pressed={layerVisible[layer]}
					class="px-2 py-1 rounded-full border transition-colors {layerVisible[layer]
						? 'border-border-strong bg-surface-strong'
						: 'border-border bg-surface opacity-50'}"
					style={layerVisible[layer] ? `border-color: ${toolbarColors.layer[layer]}` : ''}
				>
					<span
						class="inline-block w-2 h-2 rounded-full mr-1 align-middle"
						style="background: {toolbarColors.layer[layer]}"
					></span>
					{layerLabel(layer)}
				</button>
			{/each}
		</div>
		<div class="flex-1"></div>
		<!-- Node color mode (user request 2026-11-03): by hierarchy layer
		     (default) or by device-type bucket — paired with the type legend
		     below when active. -->
		<div class="flex items-center rounded-full border border-border overflow-hidden text-xs" role="group" aria-label="node color mode">
			<button
				onclick={() => (colorMode = 'layer')}
				aria-pressed={colorMode === 'layer'}
				class="px-2.5 py-1 {colorMode === 'layer' ? 'bg-surface-strong' : 'bg-surface text-muted'}"
			>{m['topology.Color By Layer']()}</button>
			<button
				onclick={() => (colorMode = 'type')}
				aria-pressed={colorMode === 'type'}
				class="px-2.5 py-1 {colorMode === 'type' ? 'bg-surface-strong' : 'bg-surface text-muted'}"
			>{m['topology.Color By Type']()}</button>
		</div>
		<!-- Label density: auto (node-count-derived) / all (identify every
		     point) / none. -->
		<div class="flex items-center rounded-full border border-border overflow-hidden text-xs" role="group" aria-label="label density">
			<button
				onclick={() => (labelMode = 'auto')}
				aria-pressed={labelMode === 'auto'}
				class="px-2.5 py-1 {labelMode === 'auto' ? 'bg-surface-strong' : 'bg-surface text-muted'}"
			>{m['topology.Labels Auto']()}</button>
			<button
				onclick={() => (labelMode = 'all')}
				aria-pressed={labelMode === 'all'}
				class="px-2.5 py-1 {labelMode === 'all' ? 'bg-surface-strong' : 'bg-surface text-muted'}"
			>{m['topology.Labels All']()}</button>
			<button
				onclick={() => (labelMode = 'none')}
				aria-pressed={labelMode === 'none'}
				class="px-2.5 py-1 {labelMode === 'none' ? 'bg-surface-strong' : 'bg-surface text-muted'}"
			>{m['topology.Labels None']()}</button>
		</div>
		<!-- 2D/3D dimension toggle (#635): 3D lazily loads its chunk; WebGL-less
		     environments stay on 2D with a hint. -->
		<div class="flex items-center rounded-full border border-border overflow-hidden text-xs" role="group" aria-label="renderer dimension">
			<button
				onclick={() => setDim('2d')}
				aria-pressed={dim === '2d'}
				class="px-2.5 py-1 {dim === '2d' ? 'bg-surface-strong' : 'bg-surface text-muted'}"
			>2D</button>
			<button
				onclick={() => setDim('3d')}
				aria-pressed={dim === '3d'}
				class="px-2.5 py-1 {dim === '3d' ? 'bg-surface-strong' : 'bg-surface text-muted'}"
			>3D</button>
		</div>
		{#if webglBlocked}
			<span class="text-xs text-warning">{m['topology.Webgl Unavailable']()}</span>
		{/if}
		<button
			onclick={() => fetchTopology()}
			class="btn btn-secondary text-sm"
		>{m['dashboard.Refresh']()}</button>

		<!-- Type-bucket legend (user request 2026-11-03): dot + name + count
		     per present bucket, shown in BOTH color modes — the chips are
		     click-to-filter (same interaction as the layer pills and the
		     edge-type legend; multiple chips combine). -->
		{#if typeStats.length > 0}
			<div class="flex items-center gap-1 text-xs flex-wrap w-full" aria-label={m['topology.Color By Type']()}>
				{#each typeStats as stat (stat.bucket)}
					<button
						onclick={() => toggleBucket(stat.bucket)}
						aria-pressed={bucketVisible[stat.bucket]}
						class="px-2 py-1 rounded-full border transition-colors inline-flex items-center gap-1.5 {bucketVisible[stat.bucket]
							? 'border-border-strong bg-surface-strong'
							: 'border-border bg-surface opacity-40'}"
					>
						<span
							class="inline-block w-2.5 h-2.5 rounded-full"
							style="background: {toolbarColors.bucket[stat.bucket]}"
						></span>
						{bucketLabel(stat.bucket)}
						<span class="text-muted font-mono">×{stat.count}</span>
					</button>
				{/each}
			</div>
		{/if}

		<!-- Edge-type legend (#583): style + name + count for every protocol
		     actually present on the canvas; click toggles the whole type
		     (same interaction as the layer pills). Weak-evidence types
		     (ARP / speaks-with) carry the fainter line + a tooltip flag. -->
		{#if edgeStats.length > 0}
			<div class="flex items-center gap-1 text-xs flex-wrap w-full" aria-label={m['topology.Edge Types']()}>
				{#each edgeStats as stat (stat.protocol)}
					{@const style = protocolStyle(stat.protocol)}
					{@const weak = WEAK_PROTOCOLS.has(stat.protocol)}
					<button
						onclick={() => toggleProtocol(stat.protocol)}
						aria-pressed={!hiddenProtocols[stat.protocol]}
						class="px-2 py-1 rounded-full border transition-colors inline-flex items-center gap-1.5 {hiddenProtocols[stat.protocol]
							? 'border-border bg-surface opacity-40'
							: 'border-border-strong bg-surface-strong'}"
						title={weak ? m['topology.Weak Evidence Desc']() : stat.protocol}
					>
						<span
							class="inline-block w-4 border-t-2 mr-0.5 align-middle"
							style="border-color: {toolbarColors.protocol[stat.protocol]}; border-top-style: {style.dash}"
						></span>
						{stat.protocol}
						{#if weak}
							<span class="text-[10px] text-muted">({m['topology.Weak Evidence']()})</span>
						{/if}
						<span class="text-muted font-mono">×{stat.count}</span>
					</button>
				{/each}
			</div>
		{/if}
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
	{:else}
		<!-- Enrichment guidance (#584): the default deployment shape renders an
		     ARP star at best; these hints name the unlit data sources and link
		     straight to the settings page where each is enabled. -->
		{#if enrichHints.length > 0}
			<div class="flex flex-wrap items-center gap-2 text-xs">
				<span class="text-muted font-medium">{m['topology.Enrich Hints Title']()}:</span>
				{#each enrichHints as family (family)}
					<a
						href="/settings"
						class="px-2 py-1 rounded-full border border-primary/40 text-primary hover:bg-primary/10 transition-colors inline-flex items-center gap-1"
					>
						<Settings2 class="w-3 h-3" aria-hidden="true" />
						{family === 'wifi'
							? m['topology.Hint Wifi']()
							: family === 'traffic'
								? m['topology.Hint Traffic']()
								: m['topology.Hint Snmp']()}
					</a>
				{/each}
			</div>
		{/if}
		<div class="flex gap-3 flex-1 min-h-[500px]">
			<!-- Graph canvas (fills available space; detail panel overlays on the right).
			     The renderer swaps by dimension (#635) — both implement the same
			     contract, and the 3D component itself lazy-loads its chunk. The
			     {#key dim} block remounts the wrapper so the fade-in action runs
			     on every swap (#635 PR3). -->
			{#key dim}
				<div class="bg-surface border border-border rounded-lg p-2 flex-1 min-w-0" use:fadeSwap>
					{#if dim === '3d' && Canvas3D}
						<Canvas3D
							graph={graph}
							search={searchQuery}
							layerVisible={layerVisible}
							hiddenProtocols={hiddenProtocols}
							expandOrphans={showOrphans}
							bucketVisible={bucketVisible}
							colorMode={colorMode}
							labelDensity={labelMode === "auto" ? undefined : labelMode === "all" ? "all" : "none"}
							height="640px"
							onselectnode={handleSelectNode}
							onselectedge={handleSelectEdge}
							onopenorphans={openOrphanPanel}
							onopendevice={openDevice}
						/>
					{:else}
						<TopologyCanvas2D
							graph={graph}
							search={searchQuery}
							layerVisible={layerVisible}
							hiddenProtocols={hiddenProtocols}
							expandOrphans={showOrphans}
							bucketVisible={bucketVisible}
							colorMode={colorMode}
							labelDensity={labelMode === "auto" ? undefined : labelMode === "all" ? "all" : "none"}
							height="640px"
							onselectnode={handleSelectNode}
							onselectedge={handleSelectEdge}
							onopenorphans={openOrphanPanel}
							onopendevice={openDevice}
						/>
					{/if}
				</div>
			{/key}

			<!-- Drill-down panel: shows when a node or edge is selected -->
			{#if selectedNode}
				<aside class="w-72 shrink-0 bg-surface border border-border rounded-lg p-4 text-sm overflow-y-auto">
					<div class="flex items-start justify-between mb-2">
						<h3 class="font-semibold text-base">{m['topology.Node Detail Title']()}</h3>
						<button onclick={() => (selectedNode = null)} class="text-muted hover:text-text" aria-label={m['common.Close']()}>
							<X class="w-4 h-4" />
						</button>
					</div>
					<dl class="space-y-1.5">
						<div><dt class="text-muted inline">{m['topology.Tooltip IP']()}: </dt><dd class="inline font-mono">{selectedNode.value.ip_address || '—'}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Tooltip MAC']()}: </dt><dd class="inline font-mono">{selectedNode.value.mac_address || '—'}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Tooltip Type']()}: </dt><dd class="inline">{typeLabel(deviceType(selectedNode.value))}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Tooltip Status']()}: </dt><dd class="inline">{selectedNode.value.status || '—'}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Degree']()}: </dt><dd class="inline">{selectedNode.degree}</dd></div>
						<div><dt class="text-muted inline">{m['topology.Brand']()}: </dt><dd class="inline">{selectedNode.value.brand || '—'}</dd></div>
						{#if selectedNode.value.network_id}
							<div><dt class="text-muted inline">{m['topology.Network']()}: </dt><dd class="inline">{selectedNode.value.network_id}</dd></div>
						{/if}
					</dl>
					{#if selectedNode.isRoot}
						<p class="mt-3 text-xs text-warning">⭐ {m['topology.Gateway']()}</p>
					{/if}
					{#if (selectedNode.value.networks?.length ?? 0) > 1}
						<!-- Multi-homed (#526): the node bridges several networks -
						     the collected interconnect fact, not a graph guess. -->
						<div class="mt-3 pt-3 border-t border-border">
							<p class="text-xs font-medium text-primary mb-1">{m['topology.Multi Homed']()}</p>
							<p class="text-xs text-muted mb-2">{m['topology.Multi Homed Desc']()}</p>
							<ul class="space-y-1">
								{#each selectedNode.value.networks as pn}
									<li class="text-xs flex items-center gap-2">
										<!-- #556: the chip names the segment (name · CIDR · the
										     address the asset answers at in it), never a bare #id. -->
										<span class="px-1.5 py-0.5 rounded bg-bg-hover text-text-muted font-mono">{formatPresence(pn)}</span>
										{#if pn.vantage}
											<span class="text-muted font-mono">@{pn.vantage}</span>
										{/if}
									</li>
								{/each}
							</ul>
						</div>
					{/if}
					<a
						href="/devices/detail/{selectedNode.value.id}"
						class="btn btn-secondary text-xs mt-4 inline-block"
					>{m['topology.Open Device']()}</a>
				</aside>
			{:else if selectedEdge}
				<aside class="w-72 shrink-0 bg-surface border border-border rounded-lg p-4 text-sm overflow-y-auto">
					<div class="flex items-start justify-between mb-2">
						<h3 class="font-semibold text-base">{m['topology.Edge Detail Title']()}</h3>
						<button onclick={() => (selectedEdge = null)} class="text-muted hover:text-text" aria-label={m['common.Close']()}>
							<X class="w-4 h-4" />
						</button>
					</div>
					<dl class="space-y-1.5">
						<div>
							<dt class="text-muted">{m['topology.Protocol']()}</dt>
							<dd class="font-mono">{selectedEdge.protocol}</dd>
						</div>
						<div>
							<dt class="text-muted">{m['topology.From Device']()}</dt>
							<dd>{nodeNameById(selectedEdge.source)}</dd>
						</div>
						<div>
							<dt class="text-muted">{m['topology.Local Port']()}</dt>
							<dd class="font-mono">{selectedEdge.localPort || '—'}</dd>
						</div>
						<div>
							<dt class="text-muted">{m['topology.To Device']()}</dt>
							<dd>{selectedEdge.isUnidentified ? m['topology.Unidentified Neighbor']() : nodeNameById(selectedEdge.target)}</dd>
						</div>
						<div>
							<dt class="text-muted">{m['topology.Remote Port']()}</dt>
							<dd class="font-mono">{selectedEdge.remotePort || '—'}</dd>
						</div>
						{#if !selectedEdge.localPort || !selectedEdge.remotePort}
							<!-- #583: a bare dash where the graph's most valuable
							     troubleshooting fact should be needs a way out, not a
							     dead end. Explain WHY the port is missing and what
							     would fill it. -->
							<p class="text-xs text-muted mt-2 border-t border-border pt-2">
								{portHint(selectedEdge)}
							</p>
						{/if}
						{#if selectedEdge.lastSeen}
							<div>
								<dt class="text-muted">{m['topology.Last Seen']()}</dt>
								<dd>{formatAge(selectedEdgeAge?.ageMs ?? 0)}{#if selectedEdgeAge?.stale} <span class="text-warning">({m['topology.Edge Stale']()})</span>{/if}</dd>
							</div>
						{/if}
						{#if endpointOffline(selectedEdge)}
							<p class="text-xs text-warning mt-2">{m['topology.Edge Offline Endpoint']()}</p>
						{/if}
						{#if selectedEdge.isCrossLink}
							<p class="text-xs text-accent-purple mt-2">↻ {m['topology.Cross Link']()}</p>
						{/if}
					</dl>
				</aside>
			{:else if orphanPanelOpen}
				<!-- Orphan member list (#584): what the collapsed group node holds. -->
				<aside class="w-72 shrink-0 bg-surface border border-border rounded-lg p-4 text-sm overflow-y-auto">
					<div class="flex items-start justify-between mb-2">
						<h3 class="font-semibold text-base">{m['topology.Orphan Panel Title']()}</h3>
						<button onclick={() => (orphanPanelOpen = false)} class="text-muted hover:text-text" aria-label={m['common.Close']()}>
							<X class="w-4 h-4" />
						</button>
					</div>
					<p class="text-xs text-muted mb-3">{m['topology.Orphan Panel Desc']()}</p>
					<ul class="space-y-1">
						{#each orphanNodes as on (on.id)}
							<li>
								<a
									href="/devices/detail/{on.value.id}"
									class="flex items-center justify-between px-2 py-1.5 rounded hover:bg-bg-hover transition-colors"
								>
									<span class="truncate">{on.name}</span>
									<span class="text-muted font-mono text-xs shrink-0 ml-2">{on.value.ip_address}</span>
								</a>
							</li>
						{/each}
					</ul>
				</aside>
			{/if}
		</div>
		<p class="text-xs text-muted">
			{m['topology.Click Hint']()}
		</p>
	{/if}
</div>
