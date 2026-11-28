<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. See LICENSE for the full text. A commercial
  license is available for use cases the AGPL does not accommodate; see
  LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { formatDateTime } from '$lib/utils';
	import { getErrorMessage } from '$lib/utils/error';
	import EmptyState from './EmptyState.svelte';
	import PageSkeleton from './PageSkeleton.svelte';
	import { Fingerprint, Info, RefreshCw } from '@lucide/svelte';
	import type {
		DeviceIdentity,
		IdentityCandidate,
		IdentityConfidence,
		IdentityDevice,
		IdentityEvidence,
		IdentitySignal
	} from '$lib/types';

	let { deviceId }: { deviceId: number } = $props();

	let identity = $state<DeviceIdentity | null>(null);
	let loading = $state(true);
	let error = $state('');
	let reloadToken = $state(0);

	// The effect owns the request lifetime so changing deviceId cancels stale
	// responses and always starts from a clean loading state.
	$effect(() => {
		const id = deviceId;
		reloadToken;
		let active = true;
		identity = null;
		loading = true;
		error = '';

		api.get<DeviceIdentity>(`/devices/${id}/identity`)
			.then((result) => {
				if (!active) return;
				identity = result;
				loading = false;
			})
			.catch((err: unknown) => {
				if (!active) return;
				error = getErrorMessage(err);
				loading = false;
			});

		return () => {
			active = false;
		};
	});

	function retry() {
		reloadToken += 1;
	}

	function confidenceLabel(confidence: IdentityConfidence): string {
		switch (confidence) {
			case 'high': return m['identity.Confidence High']();
			case 'medium': return m['identity.Confidence Medium']();
			case 'low': return m['identity.Confidence Low']();
		}
	}

	function confidenceClass(confidence: IdentityConfidence): string {
		switch (confidence) {
			case 'high': return 'bg-success/10 text-success border-success/20';
			case 'medium': return 'bg-warning/10 text-warning border-warning/20';
			case 'low': return 'bg-surface-2 text-text-muted border-border';
		}
	}

	function signalLabel(signal: IdentitySignal): string {
		switch (signal) {
			case 'hostname': return m['identity.Signal Hostname']();
			case 'mac_alias': return m['identity.Signal MAC Alias']();
			case 'serial': return m['identity.Signal Serial']();
			case 'certificate': return m['identity.Signal Certificate']();
		}
	}

	function formatPercent(rate: number): string {
		return `${Math.round(rate * 100)}%`;
	}

	function peerDevice(candidate: IdentityCandidate): IdentityDevice | null {
		if (!identity) return null;
		return candidate.device_a.id === identity.device.id ? candidate.device_b : candidate.device_a;
	}

	function displayName(device: IdentityDevice): string {
		return device.name || `#${device.id}`;
	}
</script>

{#snippet fact(label: string, value: string)}
	<div class="min-w-0">
		<dt class="text-xs text-text-muted">{label}</dt>
		<dd class="mt-1 break-words font-mono text-xs text-text">{value || m['identity.Not Available']()}</dd>
	</div>
{/snippet}

{#snippet evidenceItems(items: IdentityEvidence[])}
	{#if items.length === 0}
		<p class="text-sm text-text-muted">{m['identity.No Evidence']()}</p>
	{:else}
		<ul class="space-y-3">
			{#each items as evidence, i (i)}
				<li class="rounded-lg border border-border bg-bg p-3">
					<div class="flex flex-wrap items-center gap-2">
						<span class="rounded-full border border-primary/20 bg-primary/10 px-2 py-0.5 text-xs font-medium text-primary">
							{signalLabel(evidence.signal)}
						</span>
						<span class="break-all font-mono text-xs text-text-muted">{m['identity.Source']()}: {evidence.source}</span>
					</div>
					<p class="mt-2 whitespace-pre-wrap break-words text-sm text-text">
						<span class="font-medium">{m['identity.Detail']()}:</span> {evidence.detail}
					</p>
					{#if evidence.vantage || evidence.observed_at}
						<dl class="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-xs text-text-muted">
							{#if evidence.vantage}
								<div class="flex gap-1.5">
									<dt>{m['identity.Vantage']()}:</dt>
									<dd class="font-mono">{evidence.vantage}</dd>
								</div>
							{/if}
							{#if evidence.observed_at}
								<div class="flex gap-1.5">
									<dt>{m['identity.Observed At']()}:</dt>
									<dd>{formatDateTime(evidence.observed_at)}</dd>
								</div>
							{/if}
						</dl>
					{/if}
				</li>
			{/each}
		</ul>
	{/if}
{/snippet}

<div class="space-y-5" aria-busy={loading}>
	{#if loading}
		<PageSkeleton type="detail" />
	{:else if error}
		<div class="rounded-lg border border-error/30 bg-error/5 p-4" role="alert">
			<p class="font-medium text-error">{m['identity.Load Failed']()}</p>
			<p class="mt-1 break-words text-sm text-text-muted">{error}</p>
			<button
				type="button"
				onclick={retry}
				class="mt-3 inline-flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm
					text-text transition-colors hover:border-primary hover:text-primary"
			>
				<RefreshCw class="h-4 w-4" />
				{m['identity.Retry']()}
			</button>
		</div>
	{:else if identity}
		{@const device = identity.device}
		<div class="flex flex-wrap items-start justify-between gap-3">
			<div class="min-w-0">
				<h3 class="break-words text-lg font-semibold text-text">{displayName(device)}</h3>
				<p class="mt-0.5 text-xs text-text-muted">
					{m['identity.Device Identity']()} · #{device.id}
				</p>
			</div>
			<div class="flex flex-wrap gap-2">
				{#if device.multi_homed}
					<span class="rounded-full border border-primary/20 bg-primary/10 px-2.5 py-1 text-xs font-medium text-primary">
						{m['identity.Multi Homed']()}
					</span>
				{/if}
				{#if device.stale}
					<span class="rounded-full border border-warning/20 bg-warning/10 px-2.5 py-1 text-xs font-medium text-warning">
						{m['identity.Stale']()}
					</span>
				{/if}
			</div>
		</div>

		<div class="flex items-start gap-2 rounded-lg border border-border bg-bg p-3 text-xs text-text-muted">
			<Info class="mt-0.5 h-4 w-4 shrink-0" />
			<p>{m['identity.Read Only']()}</p>
		</div>

		<section aria-labelledby="identity-facts-{device.id}">
			<h4 id="identity-facts-{device.id}" class="mb-3 text-sm font-semibold text-text">
				{m['identity.Identity Facts']()}
			</h4>
			<dl class="grid grid-cols-1 gap-4 rounded-xl border border-border bg-surface p-4 sm:grid-cols-2 lg:grid-cols-3">
				{@render fact(m['identity.Name'](), device.name)}
				{@render fact(m['identity.Device ID'](), String(device.id))}
				{@render fact(m['identity.Device UUID'](), device.device_uuid)}
				{@render fact(m['identity.Hostname'](), device.hostname ?? '')}
				{@render fact(m['identity.Serial Number'](), device.serial_number ?? '')}
				{@render fact(m['identity.IP Address'](), device.ip_address)}
				{@render fact(m['identity.MAC Address'](), device.mac_address)}
				{@render fact(m['identity.Type'](), device.type)}
				{@render fact(m['identity.Brand'](), device.brand)}
				{@render fact(m['identity.Model'](), device.model)}
				{@render fact(m['identity.Network ID'](), device.network_id == null ? '' : String(device.network_id))}
				{@render fact(m['identity.Status'](), device.status)}
				{@render fact(m['identity.Multi Homed'](), device.multi_homed ? m['identity.Yes']() : m['identity.No']())}
				{@render fact(m['identity.Stale'](), device.stale ? m['identity.Yes']() : m['identity.No']())}
				{@render fact(m['identity.Evidence Coverage'](), formatPercent(device.evidence_coverage))}
				{@render fact(m['identity.First Seen'](), formatDateTime(device.first_seen))}
				{@render fact(m['identity.Last Seen'](), formatDateTime(device.last_seen))}
				{@render fact(m['identity.Archived At'](), formatDateTime(device.archived_at))}

				<div class="sm:col-span-2 lg:col-span-3">
					<dt class="text-xs text-text-muted">{m['identity.MAC Aliases']()}</dt>
					<dd class="mt-2">
						{#if device.mac_aliases.length > 0}
							<ul class="flex flex-wrap gap-1.5">
								{#each device.mac_aliases as alias, i (i)}
									<li class="rounded-md border border-border bg-bg px-2 py-1 font-mono text-xs text-text">{alias}</li>
								{/each}
							</ul>
						{:else}
							<span class="text-xs text-text-muted">{m['identity.None']()}</span>
						{/if}
					</dd>
				</div>

				<div class="sm:col-span-2 lg:col-span-3">
					<dt class="text-xs text-text-muted">{m['identity.Certificate Fingerprints']()}</dt>
					<dd class="mt-2">
						{#if (device.certificate_fingerprints ?? []).length > 0}
							<ul class="space-y-1.5">
								{#each device.certificate_fingerprints ?? [] as fingerprint, i (i)}
									<li class="break-all rounded-md border border-border bg-bg px-2 py-1 font-mono text-xs text-text">{fingerprint}</li>
								{/each}
							</ul>
						{:else}
							<span class="text-xs text-text-muted">{m['identity.None']()}</span>
						{/if}
					</dd>
				</div>
			</dl>
		</section>

		<section aria-labelledby="identity-candidates-{device.id}">
			<div class="mb-3 flex items-center justify-between gap-3">
				<h4 id="identity-candidates-{device.id}" class="text-sm font-semibold text-text">
					{m['identity.Candidates']()}
				</h4>
				<span class="text-xs text-text-muted">
					{m['identity.Candidate Count']({ count: identity.candidates.length })}
				</span>
			</div>

			{#if identity.candidates.length === 0}
				<EmptyState
					icon={Fingerprint}
					title={m['identity.No Candidates']()}
					description={m['identity.No Device Candidates Desc']()}
				/>
			{:else}
				<div class="space-y-4">
					{#each identity.candidates as candidate (candidate.id)}
						{@const peer = peerDevice(candidate)}
						<article class="rounded-xl border border-border bg-surface p-4" data-identity-candidate={candidate.id}>
							<div class="flex flex-wrap items-start justify-between gap-3">
								<div class="min-w-0">
									<p class="text-xs text-text-muted">{m['identity.Matches']()}</p>
									<h5 class="mt-0.5 break-words font-medium text-text">
										{peer ? displayName(peer) : m['identity.Not Available']()}
									</h5>
									{#if peer}
										<p class="mt-1 break-words font-mono text-xs text-text-muted">
											#{peer.id} · {peer.ip_address || m['identity.Not Available']()}
											{#if peer.mac_address} · {peer.mac_address}{/if}
										</p>
									{/if}
								</div>
								<div class="flex flex-wrap items-center gap-2">
									<span class="rounded-full border px-2.5 py-1 text-xs font-medium {confidenceClass(candidate.confidence)}">
										{confidenceLabel(candidate.confidence)}
									</span>
									<span class="rounded-full border border-border bg-bg px-2.5 py-1 text-xs text-text-muted">
										{m['identity.Score']()}: {candidate.score}
									</span>
								</div>
							</div>

							<div class="mt-4 grid gap-3 sm:grid-cols-2">
								<div>
									<p class="text-xs text-text-muted">{m['identity.Signals']()}</p>
									<div class="mt-1.5 flex flex-wrap gap-1.5">
										{#each candidate.signals as signal, i (i)}
											<span class="rounded-md border border-border bg-bg px-2 py-1 text-xs text-text">{signalLabel(signal)}</span>
										{/each}
									</div>
								</div>
								<div>
									<p class="text-xs text-text-muted">{m['identity.Temporal Overlap']()}</p>
									<p class="mt-1.5 text-sm text-text">
										{candidate.temporal_overlap ? m['identity.Yes']() : m['identity.No']()}
									</p>
								</div>
							</div>

							<details class="mt-4 rounded-lg border border-border bg-bg">
								<summary class="cursor-pointer px-3 py-2 text-sm font-medium text-text">
									{m['identity.Evidence']()} ({candidate.evidence.length})
								</summary>
								<div class="border-t border-border p-3">
									{@render evidenceItems(candidate.evidence)}
								</div>
							</details>

							<div class="mt-4">
								<p class="text-xs text-text-muted">{m['identity.Counter Evidence']()}</p>
								{#if (candidate.counter_evidence ?? []).length > 0}
									<ul class="mt-1.5 list-disc space-y-1 pl-5 text-sm text-text">
										{#each candidate.counter_evidence ?? [] as item, i (i)}
											<li class="break-words">{item}</li>
										{/each}
									</ul>
								{:else}
									<p class="mt-1.5 text-sm text-text-muted">{m['identity.No Counter Evidence']()}</p>
								{/if}
							</div>
						</article>
					{/each}
				</div>
			{/if}
		</section>
	{/if}
</div>
