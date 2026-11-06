<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. See LICENSE for the full text. A commercial
  license is available for use cases the AGPL does not accommodate. See
  LICENSE-COMMERCIAL.md.
-->

<!-- First-use checklist (#683): three steps above the dashboard's attention
     banner on an EMPTY inventory. Steps 1 and 3 complete themselves from
     server state (a scan task exists / an agent is registered); step 2 is an
     optional demo hint the user acks. All-done or any discovered device
     retires the card for good (persisted per center origin in localStorage —
     plain state, no tour-library dependency). -->

<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { demoMode } from '$lib/stores/demo';
	import { Radar, PartyPopper, Network, Check } from '@lucide/svelte';

	let {
		totalDevices,
		onOpenSmartScan
	}: {
		totalDevices: number;
		onOpenSmartScan: () => void;
	} = $props();

	// Server-derived completion (best-effort; a failed probe just leaves the
	// step "not done yet", which is honest for a fresh install).
	let taskTotal = $state(0);
	let agentTotal = $state(0);
	// The only persisted bit: the optional demo hint was acknowledged.
	let demoAcked = $state(false);
	let dismissed = $state(false);

	function storageKey() {
		try {
			return `mibee:onboarding:${window.location.origin}`;
		} catch {
			return 'mibee:onboarding';
		}
	}

	onMount(() => {
		try {
			const stored = JSON.parse(localStorage.getItem(storageKey()) ?? '{}');
			demoAcked = !!stored.demoAcked;
			dismissed = !!stored.dismissed;
		} catch {
			// corrupted or unavailable: defaults are fine
		}
		api.get<{ total: number }>('/scanner/tasks?limit=1')
			.then((r) => (taskTotal = r.total ?? 0))
			.catch(() => {});
		api.get<{ total: number }>('/agents/status')
			.then((r) => (agentTotal = r.total ?? 0))
			.catch(() => {});
	});

	function persist(patch: Record<string, boolean>) {
		try {
			const stored = JSON.parse(localStorage.getItem(storageKey()) ?? '{}');
			localStorage.setItem(storageKey(), JSON.stringify({ ...stored, ...patch }));
		} catch {
			// best-effort
		}
	}

	const step1Done = $derived(taskTotal > 0);
	const step2Done = $derived(demoAcked || $demoMode);
	const step3Done = $derived(agentTotal > 0);
	const allDone = $derived(step1Done && step2Done && step3Done);
	// The card retires when the inventory has anything in it (the first scan
	// IS completion), when everything is checked, or after an explicit hide.
	const visible = $derived(!dismissed && !allDone && totalDevices === 0);

	function ackDemo() {
		demoAcked = true;
		persist({ demoAcked: true });
	}

	function dismissCard() {
		dismissed = true;
		persist({ dismissed: true });
	}
</script>

{#if visible}
	<div class="mb-6 bg-surface border border-border rounded-lg p-4 md:p-5">
		<div class="flex items-start justify-between gap-3 mb-3">
			<div>
				<h2 class="text-base font-semibold text-text">{m['onboarding.Title']()}</h2>
				<p class="text-xs text-muted">{m['onboarding.Subtitle']()}</p>
			</div>
			<button
				type="button"
				class="text-muted hover:text-text shrink-0"
				onclick={dismissCard}
				aria-label={m['onboarding.Hide']()}
			>
				✕
			</button>
		</div>

		<ol class="flex flex-col gap-2">
			<li class="flex items-center gap-3 px-3 py-2.5 rounded-lg border {step1Done ? 'border-success/40 bg-success/5' : 'border-border'}">
				<span class="w-6 h-6 shrink-0 rounded-full flex items-center justify-center text-xs
					{step1Done ? 'bg-success/20 text-success' : 'bg-primary/10 text-primary'}">
					{#if step1Done}<Check class="w-3.5 h-3.5" />{:else}1{/if}
				</span>
				<span class="flex-1 min-w-0">
					<span class="block text-sm font-medium text-text">{m['onboarding.Step1 Title']()}</span>
					<span class="block text-xs text-muted">{m['onboarding.Step1 Desc']()}</span>
				</span>
				{#if !step1Done}
					<button type="button" class="btn btn-primary btn-sm shrink-0" onclick={onOpenSmartScan}>
						<Radar class="w-3.5 h-3.5" />
						{m['dashboard.Scan Network']()}
					</button>
				{/if}
			</li>

			<li class="flex items-center gap-3 px-3 py-2.5 rounded-lg border {step2Done ? 'border-success/40 bg-success/5' : 'border-border'}">
				<span class="w-6 h-6 shrink-0 rounded-full flex items-center justify-center text-xs
					{step2Done ? 'bg-success/20 text-success' : 'bg-primary/10 text-primary'}">
					{#if step2Done}<Check class="w-3.5 h-3.5" />{:else}2{/if}
				</span>
				<span class="flex-1 min-w-0">
					<span class="block text-sm font-medium text-text">{m['onboarding.Step2 Title']()}</span>
					<span class="block text-xs text-muted">{m['onboarding.Step2 Desc']()}</span>
				</span>
				{#if !step2Done}
					<button type="button" class="btn btn-sm btn-ghost shrink-0" onclick={ackDemo}>
						<PartyPopper class="w-3.5 h-3.5" />
						{m['onboarding.Step2 Ack']()}
					</button>
				{/if}
			</li>

			<li class="flex items-center gap-3 px-3 py-2.5 rounded-lg border {step3Done ? 'border-success/40 bg-success/5' : 'border-border'}">
				<span class="w-6 h-6 shrink-0 rounded-full flex items-center justify-center text-xs
					{step3Done ? 'bg-success/20 text-success' : 'bg-primary/10 text-primary'}">
					{#if step3Done}<Check class="w-3.5 h-3.5" />{:else}3{/if}
				</span>
				<span class="flex-1 min-w-0">
					<span class="block text-sm font-medium text-text">{m['onboarding.Step3 Title']()}</span>
					<span class="block text-xs text-muted">{m['onboarding.Step3 Desc']()}</span>
				</span>
				{#if !step3Done}
					<a href="/agents" class="btn btn-sm btn-ghost shrink-0">
						<Network class="w-3.5 h-3.5" />
						{m['onboarding.Step3 Action']()}
					</a>
				{/if}
			</li>
		</ol>
	</div>
{/if}
