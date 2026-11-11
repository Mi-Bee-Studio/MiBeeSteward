<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import { Radar, Sparkles, KeyRound } from '@lucide/svelte';

	interface ProbeSettings {
		quality: { enabled: boolean };
		quality_source: string;
		autogen: { enabled: boolean; max_targets: number; interval_seconds: number };
		autogen_source: string;
	}

	let loading = $state(true);
	let loadError = $state('');
	let saving = $state(false);
	let qualityEnabled = $state(true);
	let qualitySource = $state('config');
	let autogenEnabled = $state(false);
	let autogenSource = $state('config');
	let autogenMax = $state(100);
	let autogenInterval = $state(300);

	let isAdmin = $derived($auth.user?.role === 'admin');

	onMount(async () => {
		try {
			const s = await api.get<ProbeSettings>('/settings/probes');
			qualityEnabled = s.quality.enabled;
			qualitySource = s.quality_source;
			autogenEnabled = s.autogen.enabled;
			autogenSource = s.autogen_source;
			autogenMax = s.autogen.max_targets;
			autogenInterval = s.autogen.interval_seconds;
		} catch (err: unknown) {
			loadError = getErrorMessage(err);
		} finally {
			loading = false;
		}
	});

	async function handleSave() {
		saving = true;
		try {
			const s = await api.put<ProbeSettings>('/settings/probes', {
				quality: { enabled: qualityEnabled },
				autogen: {
					enabled: autogenEnabled,
					max_targets: Number(autogenMax),
					interval_seconds: Number(autogenInterval)
				}
			});
			qualityEnabled = s.quality.enabled;
			qualitySource = s.quality_source;
			autogenEnabled = s.autogen.enabled;
			autogenSource = s.autogen_source;
			addToast('success', m['probeSettings.saved']());
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			saving = false;
		}
	}

	function sourceBadge(source: string): string {
		return source === 'overlay'
			? m['security.source.overlay']()
			: m['security.source.config']();
	}
</script>

<div>
	{#if loading}
		<PageSkeleton type="form" />
	{:else if loadError}
		<div class="bg-error/10 border border-error/20 text-error rounded-xl p-4 text-sm">
			{loadError}
		</div>
	{:else if !isAdmin}
		<div class="bg-surface border border-border rounded-xl p-8 text-center text-muted">
			{m['errors.Forbidden']()}
		</div>
	{:else}
		<!-- Egress-quality matrix switch -->
		<div class="bg-surface border border-border rounded-xl p-6 mb-6">
			<div class="flex items-center justify-between mb-2">
				<h2 class="text-lg font-semibold text-text flex items-center gap-2">
					<Radar class="w-5 h-5 text-muted" />
					{m['probeSettings.quality.title']()}
				</h2>
				<span class="text-xs px-2 py-1 rounded-full {qualitySource === 'overlay' ? 'bg-primary/10 text-primary' : 'bg-bg text-muted'}">
					{sourceBadge(qualitySource)}
				</span>
			</div>
			<p class="text-sm text-muted mb-4">{m['probeSettings.quality.desc']()}</p>
			<button
				type="button"
				onclick={() => (qualityEnabled = !qualityEnabled)}
				role="switch"
				aria-checked={qualityEnabled}
				class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors {qualityEnabled ? 'bg-success' : 'bg-border'}"
			>
				<span class="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform {qualityEnabled ? 'translate-x-4.5' : 'translate-x-0.5'}"></span>
			</button>
			<p class="mt-2 text-xs text-muted">{m['probeSettings.quality.note']()}</p>
		</div>

		<!-- Discover-then-probe autogen switch -->
		<div class="bg-surface border border-border rounded-xl p-6 mb-6">
			<div class="flex items-center justify-between mb-2">
				<h2 class="text-lg font-semibold text-text flex items-center gap-2">
					<Sparkles class="w-5 h-5 text-muted" />
					{m['probeSettings.autogen.title']()}
				</h2>
				<span class="text-xs px-2 py-1 rounded-full {autogenSource === 'overlay' ? 'bg-primary/10 text-primary' : 'bg-bg text-muted'}">
					{sourceBadge(autogenSource)}
				</span>
			</div>
			<p class="text-sm text-muted mb-4">{m['probeSettings.autogen.desc']()}</p>
			<button
				type="button"
				onclick={() => (autogenEnabled = !autogenEnabled)}
				role="switch"
				aria-checked={autogenEnabled}
				class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors {autogenEnabled ? 'bg-success' : 'bg-border'}"
			>
				<span class="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform {autogenEnabled ? 'translate-x-4.5' : 'translate-x-0.5'}"></span>
			</button>
			<p class="mt-3 text-xs text-muted">
				{m['probeSettings.autogen.params']({ interval: autogenInterval, max: autogenMax })}
			</p>
		</div>

		<div class="flex items-center justify-between gap-4">
			<p class="text-xs text-muted flex items-center gap-1.5">
				<KeyRound class="w-3.5 h-3.5 shrink-0" />
				{m['probeSettings.apply_note']()}
			</p>
			<LoadingButton onclick={handleSave} loading={saving} variant="primary" label={m['probeSettings.save']()} />
		</div>
	{/if}
</div>
