<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!-- Passive Discovery — moved here from the standalone /discovery route so all
     "find devices" entry points live under the Devices → scan tab group. The
     standalone /discovery route now redirects here. Content is unchanged. -->
<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { discoveryOutcomeBadge, onOffBadge } from '$lib/utils/badges';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { Radar as RadarIcon } from '@lucide/svelte';
	import type { DiscoveryStatus } from '$lib/types';

	let status = $state<DiscoveryStatus | null>(null);
	let loading = $state(true);
	let refreshing = $state(false);
	let error = $state('');
	// Poll loop uses setTimeout recursion (not setInterval) so the next delay
	// can adapt: on repeated failure the interval backs off (up to 2min) so a
	// dead backend isn't hammered every 30s; on success it resets to 30s.
	let pollTimer: ReturnType<typeof setTimeout> | null = null;
	let consecutiveErrors = 0;
	const BASE_POLL_MS = 30_000;
	const MAX_POLL_MS = 120_000;

	onMount(() => {
		fetchStatus();
	});

	onDestroy(() => {
		if (pollTimer) clearTimeout(pollTimer);
	});

	async function fetchStatus() {
		// First load shows the PageSkeleton via `loading`; subsequent refreshes
		// (manual button or poll) toggle `refreshing` so the user gets feedback
		// without the skeleton flashing on every tick.
		if (status) refreshing = true;
		try {
			status = await api.get<DiscoveryStatus>('/discovery/status');
			error = '';
			consecutiveErrors = 0;
		} catch (err: unknown) {
			error = getErrorMessage(err);
			consecutiveErrors++;
		} finally {
			loading = false;
			refreshing = false;
			schedulePoll();
		}
	}

	function schedulePoll() {
		if (pollTimer) clearTimeout(pollTimer);
		// Backoff: double the base per consecutive error, capped at MAX_POLL_MS.
		// 0 errors → 30s, 1 → 60s, 2+ → 120s.
		const delay = error
			? Math.min(BASE_POLL_MS * Math.pow(2, consecutiveErrors), MAX_POLL_MS)
			: BASE_POLL_MS;
		pollTimer = setTimeout(fetchStatus, delay);
	}

	function formatTime(iso?: string): string {
		if (!iso) return '-';
		try { return new Date(iso).toLocaleString(); } catch { return iso; }
	}

	let stats = $derived(status?.stats ?? {});
	let funnel = $derived([
		{ label: m['discovery.Funnel Events Received'](), value: stats.EventsReceived ?? 0, cls: 'text-text' },
		{ label: m['discovery.Funnel Suppressed Recent'](), value: stats.SuppressedRecent ?? 0, cls: 'text-accent' },
		{ label: m['discovery.Funnel Known Skipped'](), value: stats.KnownHostSkipped ?? 0, cls: 'text-text-muted' },
		{ label: m['discovery.Funnel Identify Triggered'](), value: stats.IdentifyTriggered ?? 0, cls: 'text-primary' },
		{ label: m['discovery.Funnel Identify Alive'](), value: stats.IdentifyAlive ?? 0, cls: 'text-success' },
		{ label: m['discovery.Funnel Identify Dead'](), value: stats.IdentifyDead ?? 0, cls: 'text-error' },
		{ label: m['discovery.Funnel Devices Recorded'](), value: stats.DeviceRecorded ?? 0, cls: 'text-success font-semibold' }
	]);
</script>

<div class="p-4 sm:p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<div>
			<h2 class="text-2xl font-bold text-primary">{m['navigation.Discovery']()}</h2>
			<p class="text-sm text-muted mt-1">{m['discovery.Subtitle']()}</p>
		</div>
		<button
			onclick={fetchStatus}
			disabled={refreshing}
			class="px-4 py-2 border border-border text-text-muted rounded-lg
				hover:border-primary hover:text-primary transition-colors text-sm
				disabled:opacity-60 disabled:cursor-not-allowed"
		>
			{m['dashboard.Refresh']()}{#if refreshing}…{/if}
		</button>
	</div>

	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{error}
		</div>
	{/if}

	{#if loading}
		<PageSkeleton type="table" />
	{:else if !status || !status.enabled}
		<!-- Disabled state -->
		<EmptyState
			icon={RadarIcon}
			title={m['discovery.Disabled']()}
			description={m['discovery.Disabled Desc']()}
		/>
	{:else}
		<!-- Status overview card -->
		<div class="bg-surface border border-border rounded-lg p-4 mb-4">
			<div class="flex flex-wrap items-center gap-4">
				<div class="flex items-center gap-2">
					<span class="inline-block w-2.5 h-2.5 rounded-full bg-success animate-pulse-green"></span>
					<span class="text-sm font-medium text-success">{m['discovery.Enabled']()}</span>
				</div>
				{#if status.uptime}
					<div class="flex items-center gap-1.5">
						<span class="text-xs text-text-muted">{m['discovery.Uptime']()}</span>
						<span class="text-sm font-mono text-text">{status.uptime}</span>
					</div>
				{/if}
				{#if status.started_at}
					<div class="flex items-center gap-1.5">
						<span class="text-xs text-text-muted">{m['discovery.Started At']()}</span>
						<span class="text-sm text-text">{formatTime(status.started_at)}</span>
					</div>
				{/if}
			</div>
			{#if status.sources && status.sources.length > 0}
				<div class="flex flex-wrap items-center gap-2 mt-3 pt-3 border-t border-border">
					<span class="text-xs text-text-muted">{m['discovery.Sources']()}</span>
					{#each status.sources as src}
						<span class="text-xs px-2 py-0.5 rounded-full bg-primary/10 text-primary font-mono">{src}</span>
					{/each}
				</div>
			{/if}
			{#if status.config}
				<div class="flex flex-wrap items-center gap-4 mt-2 text-xs text-text-muted">
					<span>{m['discovery.Interval']()}: <span class="font-mono text-text">{(status.config.Interval ?? 0) / 1e9}s</span></span>
					<span>{m['discovery.Trigger Identify']()}: <span class="font-mono text-text">{onOffBadge(status.config.TriggerIdentify).label}</span></span>
				</div>
			{/if}
		</div>

		<!-- Pipeline funnel counters -->
		<div class="mb-4">
			<h3 class="text-sm font-semibold text-text mb-3">{m['discovery.Pipeline']()}</h3>
			<div class="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
				{#each funnel as stage}
					<div class="bg-surface border border-border rounded-lg p-3 text-center">
						<div class="text-2xl font-bold font-mono {stage.cls}">{stage.value}</div>
						<div class="text-[10px] text-text-muted uppercase tracking-wide mt-1">{stage.label}</div>
					</div>
				{/each}
			</div>
		</div>

		<!-- Recent discoveries -->
		<div>
			<h3 class="text-sm font-semibold text-text mb-3">{m['discovery.Recent']()}</h3>
			{#if status.recent_discoveries && status.recent_discoveries.length > 0}
				<div class="bg-surface border border-border rounded-lg overflow-hidden">
					<table class="w-full text-left">
						<thead class="bg-bg/50 border-b border-border">
							<tr>
								<th class="px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wide">{m['discovery.Col IP']()}</th>
								<th class="px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wide">{m['discovery.Col MAC']()}</th>
								<th class="px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wide">{m['discovery.Col Source']()}</th>
								<th class="px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wide">{m['discovery.Col Outcome']()}</th>
								<th class="px-4 py-2 text-xs font-medium text-text-muted uppercase tracking-wide">{m['discovery.Col Time']()}</th>
							</tr>
						</thead>
						<tbody>
							{#each [...status.recent_discoveries].reverse() as ev}
								{@const ob = discoveryOutcomeBadge(ev.outcome)}
								<tr class="border-b border-border/50 last:border-b-0">
									<td class="px-4 py-2 font-mono text-xs text-text">{ev.ip}</td>
									<td class="px-4 py-2 font-mono text-xs text-text-muted">{ev.mac ?? '-'}</td>
									<td class="px-4 py-2 font-mono text-xs text-text-muted">{ev.source}</td>
									<td class="px-4 py-2">
									<span class="text-xs px-2 py-0.5 rounded-full font-mono {ob.cls}">{ob.label}</span>
									</td>
									<td class="px-4 py-2 text-xs text-text-muted">{formatTime(ev.at)}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{:else}
				<div class="bg-surface border border-border rounded-lg p-6 text-center">
					<p class="text-sm text-text-muted">{m['discovery.No Recent']()}</p>
				</div>
			{/if}
		</div>
	{/if}
</div>
