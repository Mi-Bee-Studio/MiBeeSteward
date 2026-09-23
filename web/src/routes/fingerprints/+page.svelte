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
	import { onMount } from 'svelte';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import Modal from '$lib/components/Modal.svelte';
	import { RefreshCw, FileCode2, Copy, Download, Check, Fingerprint } from '@lucide/svelte';

	interface UnidentifiedDevice {
		device_uuid: string;
		name: string;
		ip_address: string;
		mac_address: string;
		hostname: string;
		vendor: string;
		oui_vendor: string;
		os: string;
		ports: number[];
		services: string[];
	}

	interface UnidentifiedGroup {
		kind: 'oui' | 'ports' | 'hostname_prefix';
		signature: string;
		count: number;
		example_ips: string[];
	}

	interface Coverage {
		total: number;
		protocol: number;
		heuristic: number;
		unidentified: number;
		devices: UnidentifiedDevice[];
		groups: UnidentifiedGroup[];
	}

	let coverage = $state<Coverage | null>(null);
	let loading = $state(true);
	let error = $state('');

	// Rule-draft modal
	let draftOpen = $state(false);
	let draftLoading = $state(false);
	let draftText = $state('');
	let draftDevice = $state<UnidentifiedDevice | null>(null);
	let draftCopied = $state(false);

	onMount(() => {
		fetchCoverage();
	});

	async function fetchCoverage() {
		loading = true;
		error = '';
		try {
			coverage = await api.get<Coverage>('/fingerprints/coverage');
		} catch (err: unknown) {
			error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	const tierPct = $derived(
		coverage && coverage.total > 0
			? Math.round(((coverage.protocol + coverage.heuristic) / coverage.total) * 100)
			: 0
	);

	async function generateDraft(device: UnidentifiedDevice) {
		draftDevice = device;
		draftOpen = true;
		draftLoading = true;
		draftText = '';
		draftCopied = false;
		try {
			const res = await fetch(`/api/v1/devices/${device.device_uuid}/fingerprint-draft`, {
				method: 'POST',
				credentials: 'include',
				headers: {
					'X-CSRF-Token': (document.cookie.match(/csrf_token=([^;]+)/) || [])[1] || ''
				}
			});
			if (!res.ok) {
				const body = await res.json().catch(() => ({}));
				throw new Error(body.error || `HTTP ${res.status}`);
			}
			draftText = await res.text();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
			draftOpen = false;
		} finally {
			draftLoading = false;
		}
	}

	function copyDraft() {
		navigator.clipboard.writeText(draftText).then(() => {
			draftCopied = true;
			setTimeout(() => (draftCopied = false), 1500);
		});
	}

	function downloadDraft() {
		if (!draftDevice) return;
		const blob = new Blob([draftText], { type: 'text/yaml' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `mibee-rule-draft-${draftDevice.ip_address}.yaml`;
		a.click();
		URL.revokeObjectURL(url);
	}

	function groupKindLabel(kind: string): string {
		if (kind === 'oui') return m['fingerprints.Group OUI']();
		if (kind === 'ports') return m['fingerprints.Group Ports']();
		return m['fingerprints.Group Hostname']();
	}
</script>

<div class="p-6 max-w-7xl mx-auto space-y-6">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-xl font-semibold text-text flex items-center gap-2">
				<Fingerprint class="w-5 h-5 text-primary" />
				{m['fingerprints.Title']()}
			</h1>
			<p class="text-sm text-text-muted mt-1">{m['fingerprints.Description']()}</p>
		</div>
		<button
			type="button"
			onclick={fetchCoverage}
			class="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg border border-border
				hover:border-primary hover:text-primary transition-colors"
		>
			<RefreshCw class="w-4 h-4" />
			{m['common.Refresh']()}
		</button>
	</div>

	{#if loading}
		<PageSkeleton type="table" />
	{:else if error}
		<div class="rounded-lg border border-error/30 bg-error/5 p-4 text-sm text-error">{error}</div>
	{:else if coverage}
		<!-- Tier cards -->
		<div class="grid grid-cols-2 md:grid-cols-4 gap-4">
			<div class="rounded-xl border border-border bg-surface p-4">
				<div class="text-2xl font-semibold text-success">{coverage.protocol}</div>
				<div class="text-xs text-text-muted mt-1">{m['fingerprints.Tier Protocol']()}</div>
			</div>
			<div class="rounded-xl border border-border bg-surface p-4">
				<div class="text-2xl font-semibold text-primary">{coverage.heuristic}</div>
				<div class="text-xs text-text-muted mt-1">{m['fingerprints.Tier Heuristic']()}</div>
			</div>
			<div class="rounded-xl border border-border bg-surface p-4">
				<div class="text-2xl font-semibold text-warning">{coverage.unidentified}</div>
				<div class="text-xs text-text-muted mt-1">{m['fingerprints.Tier Unidentified']()}</div>
			</div>
			<div class="rounded-xl border border-border bg-surface p-4">
				<div class="text-2xl font-semibold text-text">{tierPct}%</div>
				<div class="text-xs text-text-muted mt-1">
					{m['fingerprints.Coverage Rate']()} · {coverage.total} {m['fingerprints.Devices Unit']()}
				</div>
			</div>
		</div>

		<!-- TOP groups -->
		{#if coverage.groups.length > 0}
			<div class="rounded-xl border border-border bg-surface p-4">
				<h2 class="text-sm font-medium text-text mb-3">{m['fingerprints.Top Groups']()}</h2>
				<div class="flex flex-wrap gap-2">
					{#each coverage.groups as g (g.kind + g.signature)}
						<span class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs bg-bg border border-border">
							<span class="text-text-muted">{groupKindLabel(g.kind)}</span>
							<span class="font-mono text-text">{g.signature}</span>
							<span class="px-1.5 rounded-full bg-primary/15 text-primary font-medium">{g.count}</span>
						</span>
					{/each}
				</div>
			</div>
		{/if}

		<!-- Unidentified devices -->
		<div class="rounded-xl border border-border bg-surface overflow-hidden">
			<div class="px-4 py-3 border-b border-border">
				<h2 class="text-sm font-medium text-text">{m['fingerprints.Unidentified List']()}</h2>
			</div>
			{#if coverage.devices.length === 0}
				<EmptyState
					title={m['fingerprints.All Identified']()}
					description={m['fingerprints.All Identified Desc']()}
				/>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full text-sm">
						<thead>
							<tr class="text-left text-xs text-text-muted border-b border-border">
								<th class="px-4 py-2.5">{m['fingerprints.IP']()}</th>
								<th class="px-4 py-2.5">{m['fingerprints.Hostname']()}</th>
								<th class="px-4 py-2.5">{m['fingerprints.Vendor']()}</th>
								<th class="px-4 py-2.5">{m['fingerprints.OUI Vendor']()}</th>
								<th class="px-4 py-2.5">{m['fingerprints.Ports']()}</th>
								<th class="px-4 py-2.5">{m['fingerprints.Services']()}</th>
								<th class="px-4 py-2.5 text-right">{m['common.Actions']()}</th>
							</tr>
						</thead>
						<tbody>
							{#each coverage.devices as d (d.device_uuid)}
								<tr class="border-b border-border/50 hover:bg-bg/50 transition-colors">
									<td class="px-4 py-2.5 font-mono text-xs">{d.ip_address}</td>
									<td class="px-4 py-2.5 text-xs">{d.hostname || '—'}</td>
									<td class="px-4 py-2.5 text-xs">{d.vendor || '—'}</td>
									<td class="px-4 py-2.5 text-xs">{d.oui_vendor || '—'}</td>
									<td class="px-4 py-2.5 font-mono text-xs">{d.ports.join(', ') || '—'}</td>
									<td class="px-4 py-2.5 text-xs">{d.services.join(', ') || '—'}</td>
									<td class="px-4 py-2.5 text-right">
										<button
											type="button"
											onclick={() => generateDraft(d)}
											class="inline-flex items-center gap-1 px-2.5 py-1 text-xs rounded-lg
												bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
										>
											<FileCode2 class="w-3.5 h-3.5" />
											{m['fingerprints.Generate Draft']()}
										</button>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</div>
	{/if}
</div>

<Modal bind:open={draftOpen} title={m['fingerprints.Draft Title']()} maxWidth="48rem">
	{#if draftLoading}
		<div class="py-8 text-center text-sm text-text-muted">...</div>
	{:else}
		<div class="space-y-3">
			<p class="text-xs text-text-muted">
				{m['fingerprints.Draft Device']()}: <span class="font-mono">{draftDevice?.ip_address}</span>
				{draftDevice?.hostname ? ` (${draftDevice.hostname})` : ''}
			</p>
			<pre class="max-h-[50vh] overflow-auto rounded-lg bg-bg border border-border p-3 text-xs
				font-mono text-text whitespace-pre">{draftText}</pre>
			<div class="flex justify-end gap-2">
				<button
					type="button"
					onclick={copyDraft}
					class="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg border border-border
						hover:border-primary hover:text-primary transition-colors"
				>
					{#if draftCopied}
						<Check class="w-4 h-4 text-success" />
					{:else}
						<Copy class="w-4 h-4" />
					{/if}
					{m['common.Copy']()}
				</button>
				<button
					type="button"
					onclick={downloadDraft}
					class="flex items-center gap-1.5 px-3 py-1.5 text-sm rounded-lg bg-primary text-white
						hover:bg-primary/90 transition-colors"
				>
					<Download class="w-4 h-4" />
					{m['fingerprints.Download']()}
				</button>
			</div>
		</div>
	{/if}
</Modal>
