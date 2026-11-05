<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. See LICENSE for the full text. A commercial
  license is available for use cases the AGPL does not accommodate. See
  LICENSE-COMMERCIAL.md.
-->

<!-- First-use "scan my own network" flow (#678): lists the center host's own
     IPv4 interfaces (GET /system/network-interfaces), lets the user pick one
     or more, then creates a daily task per network and triggers it right
     away — landing on the scan-tasks page to watch the first run. -->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { goto } from '$app/navigation';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import type { NetworkSuggestReport, SuggestedInterface } from '$lib/utils/netSuggest';
	import Modal from '$lib/components/Modal.svelte';
	import { LoaderCircle, Radar, Star, Wifi, Cable, Network, Globe } from '@lucide/svelte';

	let { open = $bindable(false) } = $props();

	let report = $state<NetworkSuggestReport | null>(null);
	let loading = $state(false);
	let creating = $state(false);
	let error = $state('');
	let selected = $state<Record<string, boolean>>({});

	// The daily 2am preset value from web/src/lib/utils/cron.ts (the same
	// default the scan-task form preselects).
	const DAILY_2AM = '0 2 * * *';

	// The backend's DefaultPipelineConfig (internal/domain/scanner.go) —
	// CreateTask has no zero-value fallback (an all-disabled pipeline is
	// rejected), so a minimal create must carry the default stages. timeout
	// must be 1-600 (0 is rejected); concurrent_hosts is server-defaulted.
	const DEFAULT_PIPELINE = {
		icmp: { enabled: true, timeout: 2 },
		snmp: { enabled: true, community: 'public' },
		port_scan: { enabled: true, ports: '22,80,443,9100', scan_type: 'connect' },
		service_detect: { enabled: true },
		prometheus: { enabled: true, ports: '9090,9100' },
		node_exporter: { enabled: true }
	};

	$effect(() => {
		if (open && !report && !loading) {
			load();
		}
	});

	async function load() {
		loading = true;
		error = '';
		try {
			report = await api.get<NetworkSuggestReport>('/system/network-interfaces');
			selected = {};
			// LAN-like networks are pre-checked; overlays/virtual need an
			// explicit opt-in.
			for (const option of dedupeOptions(report)) {
				selected[option.cidr] = option.iface.kind === 'lan' || option.iface.kind === 'wireless';
			}
		} catch (err: unknown) {
			error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	function kindIcon(kind: string) {
		if (kind === 'wireless') return Wifi;
		if (kind === 'vpn') return Globe;
		if (kind === 'virtual') return Network;
		return Cable;
	}

	// One selectable row per distinct network: a host with wired + wireless
	// on the same LAN lists two interfaces but is ON one network — creating
	// two same-target tasks would collide (and be pointless). Interfaces are
	// primary-first from the API, so the first occurrence represents the
	// network; extra interface names are shown on the row.
	function dedupeOptions(rep: NetworkSuggestReport | null) {
		const byCidr = new Map<string, { cidr: string; iface: SuggestedInterface; names: string[] }>();
		for (const iface of rep?.interfaces ?? []) {
			const existing = byCidr.get(iface.suggested_cidr);
			if (existing) {
				existing.names.push(iface.name);
				continue;
			}
			byCidr.set(iface.suggested_cidr, { cidr: iface.suggested_cidr, iface, names: [iface.name] });
		}
		return [...byCidr.values()];
	}

	const options = $derived(dedupeOptions(report));

	const selectedNetworks = $derived(options.filter((o) => selected[o.cidr]));

	async function createAndRun() {
		if (selectedNetworks.length === 0 || creating) return;
		creating = true;
		error = '';
		try {
			for (const network of selectedNetworks) {
				const task = await api.post<{ id: number }>('/scanner/tasks', {
					name: `lan-${network.cidr}`,
					targets: network.cidr,
					cron_expr: DAILY_2AM,
					timeout: 300,
					pipeline_config: DEFAULT_PIPELINE,
					enabled: true
				});
				await api.post(`/scanner/tasks/${task.id}/trigger`, {});
			}
			addToast('success', m['netsuggest.Created']({ count: selectedNetworks.length }));
			open = false;
			goto('/devices/scan-tasks');
		} catch (err: unknown) {
			error = getErrorMessage(err);
		} finally {
			creating = false;
		}
	}
</script>

<Modal bind:open title={m['netsuggest.Title']()} maxWidth="36rem">
	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{error}
		</div>
	{/if}

	{#if loading}
		<div class="flex items-center justify-center gap-2 py-10 text-muted">
			<LoaderCircle class="w-5 h-5 animate-spin" />
			<span class="text-sm">{m['netsuggest.Loading']()}</span>
		</div>
	{:else if report}
		<p class="text-sm text-muted mb-4">{m['netsuggest.Desc']()}</p>

		{#if report.warning === 'bridge_container'}
			<div class="mb-4 px-4 py-3 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
				{m['netsuggest.Bridge Warning']()}
			</div>
		{:else if report.warning === 'no_lan'}
			<div class="mb-4 px-4 py-3 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
				{m['netsuggest.No Lan Warning']()}
			</div>
		{/if}

		<div class="flex flex-col gap-2 mb-5">
			{#each options as option (option.cidr)}
				{@const Icon = kindIcon(option.iface.kind)}
				<label
					class="flex items-center gap-3 px-3 py-2.5 rounded-lg border border-border cursor-pointer
						hover:bg-surface-hover transition-colors {selected[option.cidr] ? 'border-primary/50 bg-primary/5' : ''}"
				>
					<input type="checkbox" bind:checked={selected[option.cidr]} class="checkbox" />
					<Icon class="w-4 h-4 shrink-0 text-muted" />
					<span class="flex-1 min-w-0">
						<span class="font-mono text-sm text-text break-all">{option.cidr}</span>
						<span class="text-xs text-muted ml-2">
							{option.names.join(' / ')}{#if option.cidr !== option.iface.cidr} · {m['netsuggest.Actual Cidr']({ cidr: option.iface.cidr })}{/if}
						</span>
					</span>
					{#if option.iface.primary}
						<span class="badge badge-primary shrink-0 flex items-center gap-1" title={m['netsuggest.Primary']()}>
							<Star class="w-3 h-3" />
							{m['netsuggest.Primary']()}
						</span>
					{/if}
				</label>
			{/each}
		</div>

		<div class="flex justify-end gap-2">
			<button type="button" class="btn btn-ghost" onclick={() => (open = false)}>
				{m['common.Cancel']()}
			</button>
			<button
				type="button"
				class="btn btn-primary"
				disabled={selectedNetworks.length === 0 || creating}
				onclick={createAndRun}
			>
				{#if creating}
					<LoaderCircle class="w-4 h-4 animate-spin" />
				{:else}
					<Radar class="w-4 h-4" />
				{/if}
				{m['netsuggest.Create And Run']()}
			</button>
		</div>
	{/if}
</Modal>
