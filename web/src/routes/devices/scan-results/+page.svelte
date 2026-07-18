<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import { goto } from '$app/navigation';

	import Pagination from '$lib/components/Pagination.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';

	// --- Types ---
	interface ScanTask {
		id: number;
		name: string;
		targets: string;
		enabled: boolean;
	}

	interface ScanResult {
		id: number;
		task_id: number;
		run_id: number;
		ip: string;
		alive: boolean;
		rtt_ms: number;
		ports: string;
		services: string;
		snmp_data: string;
		prometheus_detected: boolean;
		prometheus_url: string;
		node_exporter_detected: boolean;
		node_exporter_url: string;
		node_exporter_data: string;
		scanned_at: string;
	}

	interface ScanRun {
		id: number;
		task_id: number;
		status: string;
		total_hosts: number;
		alive_hosts: number;
		new_hosts: number;
		updated_hosts: number;
		duration_ms: number;
		error_message: string;
		started_at: string | null;
		finished_at: string | null;
		created_at: string;
	}

	// --- Core state ---
	let results = $state<ScanResult[]>([]);
	let tasks = $state<ScanTask[]>([]);
	let runs = $state<ScanRun[]>([]);
	let resultsTotal = $state(0);
	let runsTotal = $state(0);
	let loading = $state(true);
	let error = $state('');

	// --- Filters ---
	let taskIdFilter = $state<number | ''>('');
	let aliveFilter = $state<'' | 'alive' | 'dead'>('');
	let ipSearch = $state('');
	let debouncedIp = $state('');
	let debounceTimer: ReturnType<typeof setTimeout> | null = null;

	// --- Pagination ---
	let resultsOffset = $state(0);
	let runsOffset = $state(0);
	const limit = 20;

	// --- Expandable rows ---
	let expandedResultId = $state<number | null>(null);
	// --- Sorting ---
	let sortColumn = $state<'ip' | 'status' | 'rtt' | null>(null);
	let sortDirection = $state<'asc' | 'desc'>('asc');

	function toggleSort(column: 'ip' | 'status' | 'rtt') {
		if (sortColumn === column) {
			sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
		} else {
			sortColumn = column;
			sortDirection = 'asc';
		}
	}

	let sortedResults = $derived.by<ScanResult[]>(() => {
		if (!sortColumn) return results;
		const sorted = [...results].sort((a, b) => {
			let cmp = 0;
			if (sortColumn === 'ip') {
				cmp = a.ip.localeCompare(b.ip);
			} else if (sortColumn === 'status') {
				cmp = Number(a.alive) - Number(b.alive);
			} else if (sortColumn === 'rtt') {
				cmp = a.rtt_ms - b.rtt_ms;
			}
			return sortDirection === 'asc' ? cmp : -cmp;
		});
		return sorted;
	});

	// --- Tab ---
	let activeTab = $state<'results' | 'runs'>('results');
	// --- Export ---
	let exporting = $state(false);

	// --- Debounced IP search ---
	$effect(() => {
		if (debounceTimer) clearTimeout(debounceTimer);
		debounceTimer = setTimeout(() => {
			debouncedIp = ipSearch;
		}, 400);
		return () => {
			if (debounceTimer) clearTimeout(debounceTimer);
		};
	});

	// --- Lifecycle ---
	onMount(() => {
		fetchTasks();
		fetchData();
	});

	// Re-fetch when debounced IP changes (skip first mount)
	let ipSearchInitialized = $state(false);
	$effect(() => {
		debouncedIp;
		if (!ipSearchInitialized) {
			ipSearchInitialized = true;
			return;
		}
		if (activeTab === 'results') {
			resultsOffset = 0;
			expandedResultId = null;
			fetchData();
		}
	});
	// --- Data fetching ---
	async function fetchTasks() {
		try {
			const res = await api.get<{ tasks: ScanTask[]; total: number }>('/scanner/tasks?limit=200');
			tasks = res.tasks || [];
		} catch (err: unknown) {
			console.error('Failed to load scan tasks', err);
		}
	}

	async function fetchData() {
		loading = true;
		error = '';
		try {
			if (activeTab === 'results') {
				await fetchResults();
			} else {
				await fetchRuns();
			}
		} catch (err: unknown) {
			error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	async function fetchResults() {
		const params = new URLSearchParams();
		if (taskIdFilter) params.set('task_id', String(taskIdFilter));
		if (debouncedIp) {
			params.set('ip', `%${debouncedIp}%`);
		}
		// alive filter is now applied server-side (the backend CountScanResults
		// mirrors it too), so resultsTotal stays correct and pagination doesn't
		// desync. Previously this was a client-side filter over one page slice,
		// which made the "Showing X–Y of N" line and page counts wrong.
		if (aliveFilter === 'alive') params.set('alive', '1');
		else if (aliveFilter === 'dead') params.set('alive', '0');
		params.set('limit', String(limit));
		params.set('offset', String(resultsOffset));

		const res = await api.get<{ results: ScanResult[]; total: number }>(`/scanner/results?${params}`);
		results = res.results || [];
		resultsTotal = res.total || 0;
	}

	async function fetchRuns() {
		const params = new URLSearchParams();
		if (taskIdFilter) params.set('task_id', String(taskIdFilter));
		params.set('limit', String(limit));
		params.set('offset', String(runsOffset));

		const res = await api.get<{ runs: ScanRun[]; total: number }>(`/scanner/runs?${params}`);
		runs = res.runs || [];
		runsTotal = res.total || 0;
	}

	function applyFilters() {
		resultsOffset = 0;
		runsOffset = 0;
		expandedResultId = null;
		fetchData();
	}

	function switchTab(tab: 'results' | 'runs') {
		if (activeTab === tab) return;
		activeTab = tab;
		resultsOffset = 0;
		runsOffset = 0;
		expandedResultId = null;
		fetchData();
	}

	// --- CSV Export ---
	async function exportCSV() {
		if (!taskIdFilter) return;
		exporting = true;
		try {
			const res = await fetch(`/api/v1/scanner/results/export?task_id=${taskIdFilter}`, {
				credentials: 'include'
			});
			if (!res.ok) {
				const err = await res.json().catch(() => ({ error: 'Export failed' }));
				throw new Error(err.error || `HTTP ${res.status}`);
			}
			const blob = await res.blob();
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `scan-results-${taskIdFilter}-${new Date().toISOString().slice(0, 10)}.csv`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			exporting = false;
		}
	}

	// --- JSON parsing helpers ---
	function parseJSON<T>(raw: string | null | undefined): T | null {
		if (!raw) return null;
		try {
			return JSON.parse(raw) as T;
		} catch {
			return null;
		}
	}

	interface PortEntry {
		port: number;
		service?: string;
	}

	interface ServiceEntry {
		port: number;
		service: string;
		version?: string;
	}

	interface SNMPEntry {
		sys_name?: string;
		sys_descr?: string;
		[key: string]: unknown;
	}

	interface NodeExporterEntry {
		os?: string;
		cpu_model?: string;
		memory_total_bytes?: number;
		[key: string]: unknown;
	}

	// --- Formatting ---
	function formatDuration(ms: number): string {
		if (ms < 1000) return `${ms}ms`;
		return `${(ms / 1000).toFixed(1)}s`;
	}

	function formatTime(iso: string | null | undefined): string {
		if (!iso) return '-';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	function formatBytes(bytes: number): string {
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / 1048576).toFixed(1)} MB`;
	}

	function runStatusClass(status: string): string {
		switch (status) {
			case 'completed':
				return 'text-success bg-success/10';
			case 'running':
				return 'text-warning bg-warning/10';
			case 'failed':
				return 'text-error bg-error/10';
			default:
				return 'text-text-muted bg-border';
		}
	}
</script>

<div class="p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<div>
			<h2 class="text-2xl font-bold text-text">{m['scanner.Results Title']()}</h2>
			<p class="text-sm text-text-muted mt-1">{m['scanner.Results Subtitle']()}</p>
		</div>
		{#if taskIdFilter}
			<button
				onclick={exportCSV}
				disabled={exporting}
				class="flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-lg border border-border text-text bg-surface hover:bg-primary/10 hover:text-primary transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
				>
				{#if exporting}
					<svg class="animate-spin w-4 h-4" fill="none" viewBox="0 0 24 24">
						<circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
						<path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
					</svg>
				{/if}
					<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
						<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
					</svg>
					{m['scanner.Export CSV']()}
				</button>
		{/if}
	</div>

	<!-- Filter bar -->
	<div class="flex flex-wrap gap-3 mb-4 items-center">
		<!-- Task selector -->
		<select
			bind:value={taskIdFilter}
			onchange={applyFilters}
			class="px-3 py-2 bg-surface border border-border rounded-lg text-sm text-text
				focus:border-primary focus:outline-none min-w-[180px]"
		>
			<option value="">{m['scanner.Filter All Tasks']()}</option>
			{#each tasks as task}
				<option value={task.id}>{task.name}</option>
			{/each}
		</select>

		<!-- Alive/Dead filter -->
		<div class="flex rounded-lg border border-border overflow-hidden">
			<button
				onclick={() => { aliveFilter = ''; applyFilters(); }}
				class="px-3 py-2 text-xs font-medium transition-colors
					{aliveFilter === '' ? 'bg-primary text-text-inverse' : 'bg-surface text-text-muted hover:text-text'}"
			>{m['scanner.Filter All']()}</button>
			<button
				onclick={() => { aliveFilter = 'alive'; applyFilters(); }}
				class="px-3 py-2 text-xs font-medium transition-colors border-l border-border
					{aliveFilter === 'alive' ? 'bg-success text-text-inverse' : 'bg-surface text-text-muted hover:text-text'}"
			>{m['scanner.Filter Alive']()}</button>
			<button
				onclick={() => { aliveFilter = 'dead'; applyFilters(); }}
				class="px-3 py-2 text-xs font-medium transition-colors border-l border-border
					{aliveFilter === 'dead' ? 'bg-error text-text-inverse' : 'bg-surface text-text-muted hover:text-text'}"
			>{m['scanner.Filter Dead']()}</button>
		</div>

		<!-- IP search -->
		<div class="relative">
			<svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted pointer-events-none"
				fill="none" stroke="currentColor" viewBox="0 0 24 24">
				<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
					d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
			</svg>
			<input
				type="text"
				bind:value={ipSearch}
				oninput={() => { resultsOffset = 0; }}
				placeholder={m['scanner.Search IP']()}
				class="pl-10 pr-4 py-2 bg-surface border border-border rounded-lg text-sm text-text
					placeholder:text-text-muted/40 focus:border-primary focus:outline-none w-48"
			/>
		</div>

		<div class="flex-1"></div>

		<!-- Tab switcher -->
		<div class="flex rounded-lg border border-border overflow-hidden">
			<button
				onclick={() => switchTab('results')}
				class="px-4 py-2 text-xs font-medium transition-colors
					{activeTab === 'results' ? 'bg-primary text-text-inverse' : 'bg-surface text-text-muted hover:text-text'}"
			>{m['scanner.Scan Results']()}</button>
			<button
				onclick={() => switchTab('runs')}
				class="px-4 py-2 text-xs font-medium transition-colors border-l border-border
					{activeTab === 'runs' ? 'bg-primary text-text-inverse' : 'bg-surface text-text-muted hover:text-text'}"
			>{m['scanner.Run History']()}</button>
		</div>
	</div>

	<!-- Error -->
	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite">
			{error}
		</div>
	{/if}

	<!-- Loading -->
	{#if loading}
		<PageSkeleton type="table" />
	{:else if activeTab === 'results'}
		<!-- Results table -->
		{#if results.length === 0}
			<div class="flex flex-col items-center justify-center py-16 text-center">
				<svg class="w-12 h-12 mb-3 text-text-muted opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
						d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
				</svg>
				<h3 class="text-sm font-medium text-text mb-1">{m['scanner.No Results']()}</h3>
				<p class="text-xs text-text-muted">{m['scanner.No Results Desc']()}</p>
			</div>
		{:else}
			<div class="overflow-x-auto rounded-lg border border-border">
				<table class="w-full">
					<thead>
						<tr class="border-b border-border text-left text-xs text-text-muted bg-surface">
							<th class="px-3 py-3 w-8"></th>
							<th class="px-3 py-3 cursor-pointer select-none hover:text-text transition-colors" onclick={() => toggleSort('ip')}>
								<span class="inline-flex items-center gap-1">
									{m['scanner.IP Address']()}
									{#if sortColumn === 'ip'}
										<span class="text-primary">{sortDirection === 'asc' ? '↑' : '↓'}</span>
									{:else}
										<span class="opacity-30">↕</span>
									{/if}
								</span>
							</th>
							<th class="px-3 py-3 cursor-pointer select-none hover:text-text transition-colors" onclick={() => toggleSort('status')}>
								<span class="inline-flex items-center gap-1">
									{m['scanner.Status']()}
									{#if sortColumn === 'status'}
										<span class="text-primary">{sortDirection === 'asc' ? '↑' : '↓'}</span>
									{:else}
										<span class="opacity-30">↕</span>
									{/if}
								</span>
							</th>
							<th class="px-3 py-3 cursor-pointer select-none hover:text-text transition-colors" onclick={() => toggleSort('rtt')}>
								<span class="inline-flex items-center gap-1">
									{m['scanner.Ports Count']()}
									{#if sortColumn === 'rtt'}
										<span class="text-primary">{sortDirection === 'asc' ? '↑' : '↓'}</span>
									{:else}
										<span class="opacity-30">↕</span>
									{/if}
								</span>
							</th>
							<th class="px-3 py-3">{m['scanner.Services Label']()}</th>
							<th class="px-3 py-3">{m['scanner.Prometheus Label']()}</th>
							<th class="px-3 py-3">{m['scanner.Node Exporter Label']()}</th>
							<th class="px-3 py-3">{m['scanner.Scanned At']()}</th>
							<th class="px-3 py-3"></th>
						</tr>
					</thead>
					<tbody>
						{#each sortedResults as result}
							{@const ports = parseJSON<PortEntry[]>(result.ports)}
							{@const services = parseJSON<ServiceEntry[]>(result.services)}
							{@const snmp = parseJSON<SNMPEntry>(result.snmp_data)}
							{@const nodeData = parseJSON<NodeExporterEntry>(result.node_exporter_data)}
							{@const isExpanded = expandedResultId === result.id}
							<tr
								class="border-b border-border last:border-b-0 hover:bg-border/30 transition-colors cursor-pointer"
								onclick={() => { expandedResultId = isExpanded ? null : result.id; }}
							>
								<td class="px-3 py-3">
									<svg class="w-3.5 h-3.5 text-text-muted transition-transform duration-200 {isExpanded ? 'rotate-90' : ''}"
										fill="none" stroke="currentColor" viewBox="0 0 24 24">
										<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
									</svg>
								</td>
								<td class="px-3 py-3 text-sm font-mono text-text">{result.ip}</td>
								<td class="px-3 py-3">
									{#if result.alive}
										<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium
											text-success bg-success/10">
											<span class="w-1.5 h-1.5 rounded-full bg-success"></span>
											{m['scanner.Alive']()}
										</span>
									{:else}
										<span class="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium
											text-error bg-error/10">
											<span class="w-1.5 h-1.5 rounded-full bg-error"></span>
											{m['scanner.Unreachable']()}
										</span>
									{/if}
								</td>
								<td class="px-3 py-3 text-sm text-text">
									{ports ? ports.length : 0}
									{#if result.rtt_ms > 0}
										<span class="text-text-muted ml-1">({result.rtt_ms}{m['scanner.ms']()})</span>
									{/if}
								</td>
								<td class="px-3 py-3 text-sm text-text-muted max-w-[200px] truncate">
									{Array.isArray(services) ? services.map((s) => s.service).join(', ') || '-' : '-'}
								</td>
								<td class="px-3 py-3">
									{#if result.prometheus_detected}
										<span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium
											text-accent bg-accent/10">
											{m['scanner.Detected']()}
										</span>
									{:else}
										<span class="text-xs text-text-muted">-</span>
									{/if}
								</td>
								<td class="px-3 py-3">
									{#if result.node_exporter_detected}
										<span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium
											text-accent-purple bg-accent-purple/10">
											{m['scanner.Detected']()}
										</span>
									{:else}
										<span class="text-xs text-text-muted">-</span>
									{/if}
								</td>
								<td class="px-3 py-3 text-xs text-text-muted whitespace-nowrap">{formatTime(result.scanned_at)}</td>
								<td class="px-3 py-3">
									<button
									onclick={(e) => { e.stopPropagation(); goto(`/devices?search=${result.ip}`); }}
										class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
									>{m['scanner.View Device']()}</button>
								</td>
							</tr>
							{#if isExpanded}
								<tr>
									<td colspan="9" class="p-0">
										<div class="bg-surface/50 border-t border-border">
											<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 p-4">
												<!-- Ports -->
												<div>
													<h4 class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
														{m['scanner.Detail Ports']()}
													</h4>
													{#if ports && ports.length > 0}
														<div class="space-y-1">
															{#each ports as p}
																<div class="flex items-center gap-2 text-sm">
																	<span class="font-mono text-text">{p.port}</span>
																	{#if p.service}
																		<span class="text-text-muted">({p.service})</span>
																	{/if}
																</div>
															{/each}
														</div>
													{:else}
														<p class="text-xs text-text-muted">{m['scanner.Not Detected']()}</p>
													{/if}
												</div>

												<!-- Services -->
												<div>
													<h4 class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
														{m['scanner.Detail Services']()}
													</h4>
													{#if services && services.length > 0}
														<div class="space-y-1">
															{#each services as s}
																<div class="text-sm">
																	<span class="font-mono text-text">{s.port}</span>
																	<span class="text-accent ml-1">{s.service}</span>
																	{#if s.version}
																		<span class="text-text-muted ml-1">({s.version})</span>
																	{/if}
																</div>
															{/each}
														</div>
													{:else}
														<p class="text-xs text-text-muted">{m['scanner.Not Detected']()}</p>
													{/if}
												</div>

												<!-- SNMP Data -->
												<div>
													<h4 class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
														{m['scanner.Detail SNMP']()}
													</h4>
													{#if snmp}
														<div class="space-y-1">
															{#if snmp.sys_name}
																<div class="text-sm">
																	<span class="text-text-muted">{m['scanner.Detail SNMP Name']()}:</span>
																	<span class="text-text ml-1">{snmp.sys_name}</span>
																</div>
															{/if}
															{#if snmp.sys_descr}
																<div class="text-sm">
																	<span class="text-text-muted">{m['scanner.Detail SNMP Descr']()}:</span>
																	<span class="text-text ml-1">{snmp.sys_descr}</span>
																</div>
															{/if}
														</div>
													{:else}
														<p class="text-xs text-text-muted">{m['scanner.Not Detected']()}</p>
													{/if}
												</div>

												<!-- Prometheus -->
												<div>
													<h4 class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
														{m['scanner.Detail Prometheus']()}
													</h4>
													{#if result.prometheus_detected && result.prometheus_url}
														<a href={result.prometheus_url} target="_blank" rel="noopener noreferrer"
															class="text-sm text-accent hover:underline font-mono break-all">
															{result.prometheus_url}
														</a>
													{:else}
														<p class="text-xs text-text-muted">{m['scanner.Not Detected']()}</p>
													{/if}
												</div>

												<!-- Node Exporter -->
												<div>
													<h4 class="text-xs font-semibold text-text-muted uppercase tracking-wider mb-2">
														{m['scanner.Detail NodeExporter']()}
													</h4>
													{#if result.node_exporter_detected}
														<div class="space-y-1">
															{#if nodeData?.os}
																<div class="text-sm">
																	<span class="text-text-muted">{m['scanner.Detail NodeExporter OS']()}:</span>
																	<span class="text-text ml-1">{nodeData.os}</span>
																</div>
															{/if}
															{#if nodeData?.cpu_model}
																<div class="text-sm">
																	<span class="text-text-muted">{m['scanner.Detail NodeExporter CPU']()}:</span>
																	<span class="text-text ml-1">{nodeData.cpu_model}</span>
																</div>
															{/if}
															{#if nodeData?.memory_total_bytes}
																<div class="text-sm">
																	<span class="text-text-muted">{m['scanner.Detail NodeExporter Memory']()}:</span>
																	<span class="text-text ml-1">{formatBytes(nodeData.memory_total_bytes)}</span>
																</div>
															{/if}
															{#if result.node_exporter_url}
																<a href={result.node_exporter_url} target="_blank" rel="noopener noreferrer"
																	class="text-xs text-accent hover:underline font-mono break-all block mt-1">
																	{result.node_exporter_url}
																</a>
															{/if}
														</div>
													{:else}
														<p class="text-xs text-text-muted">{m['scanner.Not Detected']()}</p>
													{/if}
												</div>
											</div>
										</div>
									</td>
								</tr>
							{/if}
						{/each}
					</tbody>
				</table>
			</div>

			<Pagination total={resultsTotal} {limit} offset={resultsOffset} onPageChange={(o) => { resultsOffset = o; expandedResultId = null; fetchData(); }} />
		{/if}
	{:else}
		<!-- Runs table -->
		{#if runs.length === 0}
			<div class="flex flex-col items-center justify-center py-16 text-center">
				<svg class="w-12 h-12 mb-3 text-text-muted opacity-40" fill="none" stroke="currentColor" viewBox="0 0 24 24">
					<path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5"
						d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
				</svg>
				<h3 class="text-sm font-medium text-text mb-1">{m['scanner.No Results']()}</h3>
				<p class="text-xs text-text-muted">{m['scanner.No Results Desc']()}</p>
			</div>
		{:else}
			<div class="overflow-x-auto rounded-lg border border-border">
				<table class="w-full">
					<thead>
						<tr class="border-b border-border text-left text-xs text-text-muted bg-surface">
							<th class="px-4 py-3">ID</th>
							<th class="px-4 py-3">{m['scanner.Run Status']()}</th>
							<th class="px-4 py-3">{m['scanner.Run Duration']()}</th>
							<th class="px-4 py-3">{m['scanner.Run Hosts']()}</th>
							<th class="px-4 py-3">{m['scanner.Run New']()}</th>
							<th class="px-4 py-3">{m['scanner.Run Updated']()}</th>
							<th class="px-4 py-3">{m['scanner.Run Started']()}</th>
							<th class="px-4 py-3">{m['scanner.Run Finished']()}</th>
							<th class="px-4 py-3">{m['scanner.Run Error']()}</th>
						</tr>
					</thead>
					<tbody>
						{#each runs as run}
							<tr class="border-b border-border last:border-b-0 hover:bg-border/30 transition-colors">
								<td class="px-4 py-3 text-sm font-mono text-text-muted">#{run.id}</td>
								<td class="px-4 py-3">
									<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium capitalize {runStatusClass(run.status)}">
										{run.status}
									</span>
								</td>
								<td class="px-4 py-3 text-sm text-text">{formatDuration(run.duration_ms)}</td>
								<td class="px-4 py-3 text-sm text-text">
									<span class="text-success">{run.alive_hosts}</span>
									<span class="text-text-muted">/</span>
									<span>{run.total_hosts}</span>
								</td>
								<td class="px-4 py-3 text-sm text-accent">{run.new_hosts}</td>
								<td class="px-4 py-3 text-sm text-text-muted">{run.updated_hosts}</td>
								<td class="px-4 py-3 text-xs text-text-muted whitespace-nowrap">{formatTime(run.started_at)}</td>
								<td class="px-4 py-3 text-xs text-text-muted whitespace-nowrap">{formatTime(run.finished_at)}</td>
								<td class="px-4 py-3 text-xs text-error max-w-[200px] truncate">
									{run.error_message || '-'}
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>

			<Pagination total={runsTotal} {limit} offset={runsOffset} onPageChange={(o) => { runsOffset = o; fetchData(); }} />
		{/if}
	{/if}
</div>
