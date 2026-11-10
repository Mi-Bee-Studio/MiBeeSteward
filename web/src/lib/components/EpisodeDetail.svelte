<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero
  General Public License v3.0 or later; see LICENSE for the full text. A
  commercial license is available for use cases the AGPL does not
  accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import type { ProbeQualityEpisode } from '$lib/types';

	let { episode }: { episode: ProbeQualityEpisode } = $props();

	const kindLabel = $derived(
		episode.kind === 'network'
			? m['probes.Episode Kind Network']()
			: m['probes.Episode Kind Path']()
	);
	const active = $derived(!episode.resolved_at);

	function pct(v: number): string {
		return `${Math.round(v * 100)}%`;
	}
	function vantageLabel(v: string): string {
		return v === 'center' ? m['probes.Vantage Center']() : v.replace(/^agent:/, '');
	}
	const attributionLabel: Record<string, (d: string) => string> = {
		egress_change: () => m['probes.Episode Attr Egress'](),
		path_change: () => m['probes.Episode Attr Path'](),
		peer_egress_degraded: () => m['probes.Episode Attr Peer'](),
		error_shape: (d) => d
	};
</script>

<div class="rounded-lg border border-border bg-surface p-3" data-episode-card data-episode-id={episode.id}>
	<div class="flex flex-wrap items-center gap-2">
		{#if active}
			<span class="rounded px-1.5 py-0.5 text-xs font-medium {episode.notified ? 'bg-error/10 text-error' : 'bg-warning/10 text-warning'}">
				{episode.notified ? m['probes.Episode Notified']() : m['probes.Episode Recorded']()}
			</span>
		{:else}
			<span class="rounded px-1.5 py-0.5 text-xs bg-success/10 text-success">{m['probes.Episode Resolved']()}</span>
		{/if}
		<span class="text-sm font-semibold">{kindLabel}</span>
		<span class="text-xs text-text-muted">
			{vantageLabel(episode.vantage_group)}
			{#if episode.target_group}· {episode.target_group}{/if}
		</span>
		<span class="ml-auto text-xs text-text-muted">
			{new Date(episode.started_at).toLocaleString()}
			{#if !active} → {new Date(episode.resolved_at!).toLocaleString()}{/if}
		</span>
	</div>

	<div class="mt-2 overflow-x-auto">
		<table class="w-full text-xs">
			<thead>
				<tr class="text-text-muted">
					<th class="py-1 pr-3 text-left font-medium">{m['probes.Column Target']()}</th>
					<th class="py-1 pr-3 text-left font-medium">{m['probes.Column Vantage']()}</th>
					<th class="py-1 pr-3 text-right font-medium">p50</th>
					<th class="py-1 pr-3 text-right font-medium">{m['probes.Episode Ok Rate']()}</th>
				</tr>
			</thead>
			<tbody>
				{#each episode.metric_degraded as met (met.target_id + met.vantage)}
					<tr class="border-t border-border/50">
						<td class="py-1 pr-3">{met.name}</td>
						<td class="py-1 pr-3 text-text-muted">{vantageLabel(met.vantage)}</td>
						<td class="py-1 pr-3 text-right font-mono">
							{#if met.base_p50_ms > 0}{Math.round(met.base_p50_ms)}→{/if}{Math.round(met.p50_ms)}ms
						</td>
						<td class="py-1 pr-3 text-right font-mono">{pct(met.base_ok_rate)}→{pct(met.ok_rate)}</td>
					</tr>
				{/each}
			</tbody>
		</table>
	</div>

	{#if episode.attribution.length > 0}
		<div class="mt-2">
			<div class="text-xs font-medium text-text-muted">{m['probes.Episode Attribution']()}</div>
			<ul class="mt-1 space-y-0.5">
				{#each episode.attribution as a (a.kind + a.detail)}
					<li class="text-xs">
						<span class="text-warning">•</span>
						{attributionLabel[a.kind]?.(a.detail) ?? a.detail}
					</li>
				{/each}
			</ul>
		</div>
	{:else if active}
		<p class="mt-2 text-xs text-text-muted">{m['probes.Episode No Attribution']()}</p>
	{/if}
</div>
