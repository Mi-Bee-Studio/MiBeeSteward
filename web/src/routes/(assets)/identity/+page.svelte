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
	import EmptyState from '$lib/components/EmptyState.svelte';
	import IdentityReviewPanel from '$lib/components/IdentityReviewPanel.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import { ArrowRight, ChevronDown, ChevronUp, Fingerprint, Info, RefreshCw } from '@lucide/svelte';
	import { onMount } from 'svelte';
	import type {
		IdentityCandidateList,
		IdentityConfidence,
		IdentityDevice,
		IdentityEvidence,
		IdentitySignal,
		Network
	} from '$lib/types';

	type ConfidenceFilter = '' | IdentityConfidence;

	let result = $state<IdentityCandidateList | null>(null);
	let networks = $state<Network[]>([]);
	let loading = $state(true);
	let error = $state('');
	let networkLoading = $state(true);
	let networkError = $state('');
	let limit = $state(50);
	let offset = $state(0);
	let minConfidence = $state<ConfidenceFilter>('');
	let networkId = $state('');
	let expandedCandidates = $state<Set<string>>(new Set());
	let requestVersion = 0;
	let networkRequestVersion = 0;

	let reviewOpen = $state(false);
	let selectedDevice = $state<IdentityDevice | null>(null);

	onMount(() => {
		void loadNetworks();
		void loadCandidates();
	});

	async function loadCandidates() {
		const version = ++requestVersion;
		loading = true;
		error = '';
		expandedCandidates = new Set();

		const params = new URLSearchParams();
		params.set('limit', String(limit));
		params.set('offset', String(offset));
		if (minConfidence) params.set('min_confidence', minConfidence);
		if (networkId) params.set('network_id', networkId);

		try {
			const response = await api.get<IdentityCandidateList>(`/identity/candidates?${params}`);
			if (version !== requestVersion) return;
			result = response;
		} catch (err: unknown) {
			if (version !== requestVersion) return;
			error = getErrorMessage(err);
		} finally {
			if (version === requestVersion) loading = false;
		}
	}

	async function loadNetworks() {
		const version = ++networkRequestVersion;
		networkLoading = true;
		networkError = '';
		try {
			const response = await api.get<{ networks: Network[]; total: number }>('/networks');
			if (version !== networkRequestVersion) return;
			networks = response.networks ?? [];
		} catch (err: unknown) {
			if (version !== networkRequestVersion) return;
			networkError = getErrorMessage(err);
		} finally {
			if (version === networkRequestVersion) networkLoading = false;
		}
	}

	function refresh() {
		void loadCandidates();
	}

	function retry() {
		void loadCandidates();
	}

	function handleConfidenceChange(event: Event) {
		minConfidence = (event.currentTarget as HTMLSelectElement).value as ConfidenceFilter;
		offset = 0;
		void loadCandidates();
	}

	function handleNetworkChange(event: Event) {
		networkId = (event.currentTarget as HTMLSelectElement).value;
		offset = 0;
		void loadCandidates();
	}

	function handlePageChange(newOffset: number) {
		offset = newOffset;
		void loadCandidates();
	}

	function handlePageSizeChange(newLimit: number) {
		limit = newLimit;
		offset = 0;
		void loadCandidates();
	}

	function toggleEvidence(candidateId: string) {
		const next = new Set(expandedCandidates);
		if (next.has(candidateId)) next.delete(candidateId);
		else next.add(candidateId);
		expandedCandidates = next;
	}

	function openReview(device: IdentityDevice) {
		selectedDevice = device;
		reviewOpen = true;
	}

	function closeReview() {
		reviewOpen = false;
		selectedDevice = null;
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

	function displayName(device: IdentityDevice): string {
		return device.name || `#${device.id}`;
	}

	function deviceSubtitle(device: IdentityDevice): string {
		return [device.ip_address, device.mac_address].filter(Boolean).join(' · ') || m['identity.Not Available']();
	}

	const summaryCards = $derived(result ? [
		{ key: 'active-devices', label: m['identity.Active Devices'](), value: String(result.summary.total_devices), tone: 'text-text' },
		{ key: 'candidates', label: m['identity.Candidates'](), value: String(result.summary.candidate_count), tone: 'text-primary' },
		{ key: 'high', label: m['identity.High Confidence'](), value: String(result.summary.high_count), tone: 'text-success' },
		{ key: 'medium', label: m['identity.Medium Confidence'](), value: String(result.summary.medium_count), tone: 'text-warning' },
		{ key: 'low', label: m['identity.Low Confidence'](), value: String(result.summary.low_count), tone: 'text-text-muted' },
		{ key: 'unknown', label: m['identity.Unknown Rate'](), value: formatPercent(result.summary.unknown_rate), tone: 'text-text' },
		{ key: 'stale', label: m['identity.Stale Rate'](), value: formatPercent(result.summary.stale_rate), tone: 'text-warning' },
		{ key: 'evidence-coverage', label: m['identity.Evidence Coverage'](), value: formatPercent(result.summary.evidence_coverage), tone: 'text-primary' }
	] : []);

	const reviewTitle = $derived(selectedDevice
		? m['identity.Review Device Named']({ name: displayName(selectedDevice) })
		: m['identity.Device Identity']());
</script>

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

<div class="mx-auto max-w-7xl space-y-6 p-6">
	<div class="flex flex-wrap items-start justify-between gap-3">
		<p class="max-w-3xl text-sm text-text-muted">{m['identity.Description']()}</p>
		<button
			type="button"
			onclick={refresh}
			disabled={loading}
			class="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-sm
				text-text transition-colors hover:border-primary hover:text-primary disabled:cursor-not-allowed disabled:opacity-50"
		>
			<RefreshCw class="h-4 w-4 {loading ? 'animate-spin' : ''}" />
			{m['identity.Refresh']()}
		</button>
	</div>

	<div class="flex items-start gap-2 rounded-lg border border-primary/20 bg-primary/5 p-3 text-sm">
		<Info class="mt-0.5 h-4 w-4 shrink-0 text-primary" />
		<div>
			<p class="font-medium text-text">{m['identity.Suggestions Only']()}</p>
			<p class="mt-0.5 text-text-muted">{m['identity.Suggestions Only Detail']()}</p>
		</div>
	</div>

	<div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
		<div>
			<label for="identity-confidence" class="mb-1 block text-xs text-text-muted">
				{m['identity.Minimum Confidence']()}
			</label>
			<select
				id="identity-confidence"
				data-confidence-filter
				value={minConfidence}
				onchange={handleConfidenceChange}
				class="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-text
					focus:border-primary focus:outline-none"
			>
				<option value="">{m['identity.All Confidence']()}</option>
				<option value="high">{m['identity.Confidence High']()}</option>
				<option value="medium">{m['identity.Confidence Medium']()}</option>
				<option value="low">{m['identity.Confidence Low']()}</option>
			</select>
		</div>
		<div>
			<label for="identity-network" class="mb-1 block text-xs text-text-muted">
				{m['identity.Network']()}
			</label>
			<select
				id="identity-network"
				data-network-filter
				value={networkId}
				onchange={handleNetworkChange}
				disabled={networkLoading || !!networkError}
				class="w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm text-text
					focus:border-primary focus:outline-none disabled:cursor-not-allowed disabled:opacity-60"
			>
				<option value="">{networkLoading ? m['identity.Networks Loading']() : m['identity.All Networks']()}</option>
				{#each networks as network (network.id)}
					<option value={network.id}>{network.name || network.cidr || `#${network.id}`}</option>
				{/each}
			</select>
			{#if networkError}
				<p class="mt-1 text-xs text-warning" role="status">
					{m['identity.Networks Load Failed']()}: {networkError}
				</p>
			{/if}
		</div>
	</div>

	{#if loading}
		<PageSkeleton type="table" />
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
	{:else if result}
		<section aria-labelledby="identity-summary">
			<div class="mb-3 flex flex-wrap items-baseline justify-between gap-2">
				<h2 id="identity-summary" class="text-sm font-semibold text-text">{m['identity.Summary']()}</h2>
				<p class="text-xs text-text-muted">{m['identity.Summary Scope']()}</p>
			</div>
			<div class="grid grid-cols-2 gap-3 md:grid-cols-4">
				{#each summaryCards as card (card.key)}
					<div class="rounded-xl border border-border bg-surface p-4" data-summary-card={card.key}>
						<div class="text-2xl font-semibold tabular-nums {card.tone}">{card.value}</div>
						<div class="mt-1 text-xs text-text-muted">{card.label}</div>
					</div>
				{/each}
			</div>
		</section>

		<section aria-labelledby="identity-candidate-list" class="overflow-hidden rounded-xl border border-border bg-surface">
			<div class="border-b border-border px-4 py-3">
				<h2 id="identity-candidate-list" class="text-sm font-medium text-text">{m['identity.Candidate List']()}</h2>
			</div>
			{#if result.candidates.length === 0}
				<EmptyState
					icon={Fingerprint}
					title={m['identity.No Candidates']()}
					description={m['identity.No Candidates Desc']()}
				/>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full min-w-[1100px] text-sm">
						<caption class="sr-only">{m['identity.Candidate List']()}</caption>
						<thead>
							<tr class="border-b border-border text-left text-xs text-text-muted">
								<th scope="col" class="px-4 py-2.5">{m['identity.Evidence']()}</th>
								<th scope="col" class="px-4 py-2.5">{m['identity.Devices']()}</th>
								<th scope="col" class="px-4 py-2.5">{m['identity.Confidence']()}</th>
								<th scope="col" class="px-4 py-2.5">{m['identity.Score']()}</th>
								<th scope="col" class="px-4 py-2.5">{m['identity.Signals']()}</th>
								<th scope="col" class="px-4 py-2.5">{m['identity.Temporal Overlap']()}</th>
								<th scope="col" class="px-4 py-2.5">{m['identity.Counter Evidence']()}</th>
							</tr>
						</thead>
						<tbody>
							{#each result.candidates as candidate (candidate.id)}
								<tr class="border-b border-border/50 align-top hover:bg-bg/40" data-candidate-id={candidate.id}>
									<td class="px-4 py-3">
										<button
											type="button"
											data-evidence-toggle={candidate.id}
											aria-expanded={expandedCandidates.has(candidate.id)}
											aria-controls="identity-evidence-{candidate.id}"
											onclick={() => toggleEvidence(candidate.id)}
											class="inline-flex items-center gap-1 whitespace-nowrap rounded-lg border border-border px-2.5 py-1.5
												text-xs text-text transition-colors hover:border-primary hover:text-primary"
										>
											{#if expandedCandidates.has(candidate.id)}
												<ChevronUp class="h-3.5 w-3.5" />
												{m['identity.Hide Evidence']()}
											{:else}
												<ChevronDown class="h-3.5 w-3.5" />
												{m['identity.Show Evidence']()}
											{/if}
										</button>
									</td>
									<td class="px-4 py-3">
										<div class="flex min-w-64 items-start gap-3">
											<button
												type="button"
												data-review-device={candidate.device_a.id}
												aria-label={m['identity.Review Device Named']({ name: displayName(candidate.device_a) })}
												onclick={() => openReview(candidate.device_a)}
												class="min-w-0 flex-1 rounded-md text-left transition-colors hover:text-primary focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
											>
												<span class="block break-words font-medium text-text">{displayName(candidate.device_a)}</span>
												<span class="mt-0.5 block break-words font-mono text-xs text-text-muted">
													#{candidate.device_a.id} · {deviceSubtitle(candidate.device_a)}
												</span>
											</button>
											<ArrowRight class="mt-1 h-4 w-4 shrink-0 text-text-muted" aria-hidden="true" />
											<button
												type="button"
												data-review-device={candidate.device_b.id}
												aria-label={m['identity.Review Device Named']({ name: displayName(candidate.device_b) })}
												onclick={() => openReview(candidate.device_b)}
												class="min-w-0 flex-1 rounded-md text-left transition-colors hover:text-primary focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
											>
												<span class="block break-words font-medium text-text">{displayName(candidate.device_b)}</span>
												<span class="mt-0.5 block break-words font-mono text-xs text-text-muted">
													#{candidate.device_b.id} · {deviceSubtitle(candidate.device_b)}
												</span>
											</button>
										</div>
									</td>
									<td class="px-4 py-3">
										<span class="whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-medium {confidenceClass(candidate.confidence)}">
											{confidenceLabel(candidate.confidence)}
										</span>
									</td>
									<td class="px-4 py-3 font-mono tabular-nums">{candidate.score}</td>
									<td class="px-4 py-3">
										<div class="flex min-w-32 flex-wrap gap-1.5">
											{#each candidate.signals as signal, i (i)}
												<span class="rounded-md border border-border bg-bg px-2 py-1 text-xs text-text">{signalLabel(signal)}</span>
											{/each}
										</div>
									</td>
									<td class="px-4 py-3">
										<span class="whitespace-nowrap text-xs">
											{candidate.temporal_overlap ? m['identity.Yes']() : m['identity.No']()}
										</span>
									</td>
									<td class="max-w-72 px-4 py-3">
										{#if (candidate.counter_evidence ?? []).length > 0}
											<ul class="list-disc space-y-1 pl-4 text-xs text-text-muted">
												{#each candidate.counter_evidence ?? [] as item, i (i)}
													<li class="break-words">{item}</li>
												{/each}
											</ul>
										{:else}
											<span class="text-xs text-text-muted">{m['identity.No Counter Evidence']()}</span>
										{/if}
									</td>
								</tr>
								{#if expandedCandidates.has(candidate.id)}
									<tr id="identity-evidence-{candidate.id}" class="border-b border-border/50 bg-bg/30">
										<td colspan="7" class="px-4 py-4">
											<div class="max-w-4xl">
												<h3 class="mb-3 text-sm font-medium text-text">
													{m['identity.Evidence']()} ({candidate.evidence.length})
												</h3>
												{@render evidenceItems(candidate.evidence)}
											</div>
										</td>
									</tr>
								{/if}
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>

		<Pagination
			total={result.total}
			{limit}
			{offset}
			pageSizeOptions={[20, 50, 100]}
			onPageChange={handlePageChange}
			onPageSizeChange={handlePageSizeChange}
		/>
	{/if}
</div>

<Modal bind:open={reviewOpen} title={reviewTitle} maxWidth="56rem" onClose={closeReview}>
	{#if selectedDevice}
		<IdentityReviewPanel deviceId={selectedDevice.id} />
	{/if}
</Modal>
