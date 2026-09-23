<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import { refreshPasswordPolicy } from '$lib/stores/passwordPolicy';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import { ArrowLeft, ShieldCheck, Server, KeyRound, AlertTriangle } from '@lucide/svelte';

	interface PasswordPolicy {
		min_length: number;
		require_uppercase: boolean;
		require_lowercase: boolean;
		require_digit: boolean;
		require_special: boolean;
	}
	interface AuthSettings {
		password_policy: PasswordPolicy;
		password_policy_source: string;
		lockout: { max_failed_attempts: number; lock_minutes: number };
		lockout_source: string;
	}
	interface SystemInfo {
		version: string;
		network: { name: string; cidr: string; site: string };
		master_key_configured: boolean;
		demo_mode: boolean;
	}

	let loading = $state(true);
	let loadError = $state('');
	let saving = $state(false);
	let policySource = $state('config');
	let lockoutSource = $state('config');
	let system = $state<SystemInfo | null>(null);

	let minLength = $state(8);
	let reqUpper = $state(true);
	let reqLower = $state(true);
	let reqDigit = $state(true);
	let reqSpecial = $state(false);
	let maxAttempts = $state(5);
	let lockMinutes = $state(30);

	let isAdmin = $derived($auth.user?.role === 'admin');

	// Live hint of what the policy will require: built from the CURRENT form
	// state so toggles give immediate feedback (the backend enforces on submit).
	let policyHint = $derived.by(() => {
		const parts: string[] = [m['security.hint.length']({ min: minLength })];
		if (reqUpper) parts.push(m['security.hint.uppercase']());
		if (reqLower) parts.push(m['security.hint.lowercase']());
		if (reqDigit) parts.push(m['security.hint.digit']());
		if (reqSpecial) parts.push(m['security.hint.special']());
		return parts.join(m['security.hint.joiner']());
	});

	onMount(async () => {
		try {
			const [settings, sys] = await Promise.all([
				api.get<AuthSettings>('/settings/auth'),
				api.get<SystemInfo>('/system')
			]);
			policySource = settings.password_policy_source;
			lockoutSource = settings.lockout_source;
			minLength = settings.password_policy.min_length;
			reqUpper = settings.password_policy.require_uppercase;
			reqLower = settings.password_policy.require_lowercase;
			reqDigit = settings.password_policy.require_digit;
			reqSpecial = settings.password_policy.require_special;
			maxAttempts = settings.lockout.max_failed_attempts;
			lockMinutes = settings.lockout.lock_minutes;
			system = sys;
		} catch (err: unknown) {
			loadError = getErrorMessage(err);
		} finally {
			loading = false;
		}
	});

	async function handleSave() {
		saving = true;
		try {
			await api.put('/settings/auth', {
				password_policy: {
					min_length: Number(minLength),
					require_uppercase: reqUpper,
					require_lowercase: reqLower,
					require_digit: reqDigit,
					require_special: reqSpecial
				},
				lockout: {
					max_failed_attempts: Number(maxAttempts),
					lock_minutes: Number(lockMinutes)
				}
			});
			// The single-flight policy cache would serve the stale pre-edit
			// value for the rest of the session: force a refresh so every
			// password form (login force-change, users page, settings) picks
			// up the new rules immediately.
			await refreshPasswordPolicy();
			policySource = 'overlay';
			lockoutSource = 'overlay';
			addToast('success', m['security.saved']());
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

<svelte:head>
	<title>{m['security.title']()} · MiBee Steward</title>
</svelte:head>

<div class="max-w-3xl mx-auto px-4 py-8">
	<div class="flex items-center gap-3 mb-6">
		<button
			type="button"
			onclick={() => goto('/settings')}
			class="p-2 rounded-lg hover:bg-surface transition-colors"
			aria-label={m['common.Back']()}
		>
			<ArrowLeft class="w-5 h-5" />
		</button>
		<h1 class="text-2xl font-bold text-text flex items-center gap-2">
			<ShieldCheck class="w-6 h-6 text-primary" />
			{m['security.title']()}
		</h1>
	</div>

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
		<!-- System info (read-only) -->
		{#if system}
			<div class="bg-surface border border-border rounded-xl p-6 mb-6">
				<h2 class="text-lg font-semibold text-text mb-4 flex items-center gap-2">
					<Server class="w-5 h-5 text-muted" />
					{m['security.system.title']()}
				</h2>
				<dl class="grid grid-cols-1 sm:grid-cols-2 gap-x-8 gap-y-3 text-sm">
					<div class="flex justify-between sm:block">
						<dt class="text-muted">{m['security.system.version']()}</dt>
						<dd class="font-mono text-text">{system.version || 'dev'}</dd>
					</div>
					<div class="flex justify-between sm:block">
						<dt class="text-muted">{m['security.system.network']()}</dt>
						<dd class="text-text">
							{system.network.name}
							{#if system.network.cidr}<span class="text-muted font-mono"> ({system.network.cidr})</span>{/if}
						</dd>
					</div>
					<div class="flex justify-between sm:block">
						<dt class="text-muted">{m['security.system.master_key']()}</dt>
						<dd class={system.master_key_configured ? 'text-success' : 'text-warning'}>
							{system.master_key_configured
								? m['security.system.master_key_configured']()
								: m['security.system.master_key_missing']()}
						</dd>
					</div>
					{#if system.demo_mode}
						<div class="flex justify-between sm:block">
							<dt class="text-muted">{m['security.system.demo']()}</dt>
							<dd class="text-warning">{m['demo.Banner']()}</dd>
						</div>
					{/if}
				</dl>
				{#if !system.master_key_configured}
					<p class="mt-4 text-xs text-muted flex items-start gap-1.5">
						<AlertTriangle class="w-3.5 h-3.5 mt-0.5 shrink-0 text-warning" />
						{m['security.system.master_key_note']()}
					</p>
				{/if}
			</div>
		{/if}

		<!-- Password policy -->
		<div class="bg-surface border border-border rounded-xl p-6 mb-6">
			<div class="flex items-center justify-between mb-4">
				<h2 class="text-lg font-semibold text-text">{m['security.policy.title']()}</h2>
				<span class="text-xs px-2 py-1 rounded-full {policySource === 'overlay' ? 'bg-primary/10 text-primary' : 'bg-bg text-muted'}">
					{sourceBadge(policySource)}
				</span>
			</div>

			<div class="space-y-4">
				<label class="block">
					<span class="text-sm text-muted">{m['security.policy.min_length']()}</span>
					<input
						type="number"
						min="1"
						max="1024"
						bind:value={minLength}
						class="mt-1 w-32 px-3 py-2 bg-bg border border-border rounded-lg text-text focus:border-primary focus:outline-none"
					/>
				</label>

				<div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
					{#each [
						{ id: 'upper', label: m['security.policy.require_uppercase'](), checked: reqUpper },
						{ id: 'lower', label: m['security.policy.require_lowercase'](), checked: reqLower },
						{ id: 'digit', label: m['security.policy.require_digit'](), checked: reqDigit },
						{ id: 'special', label: m['security.policy.require_special'](), checked: reqSpecial }
					] as item (item.id)}
						<label class="flex items-center gap-2.5 text-sm text-text cursor-pointer">
							<input
								type="checkbox"
								checked={item.checked}
								onchange={(e) => {
									const v = (e.target as HTMLInputElement).checked;
									if (item.id === 'upper') reqUpper = v;
									else if (item.id === 'lower') reqLower = v;
									else if (item.id === 'digit') reqDigit = v;
									else reqSpecial = v;
								}}
								class="w-4 h-4 accent-[var(--color-primary)]"
							/>
							{item.label}
						</label>
					{/each}
				</div>

				<p class="text-xs text-muted bg-bg rounded-lg px-3 py-2">
					{policyHint}
				</p>
			</div>
		</div>

		<!-- Login lockout -->
		<div class="bg-surface border border-border rounded-xl p-6 mb-6">
			<div class="flex items-center justify-between mb-4">
				<h2 class="text-lg font-semibold text-text">{m['security.lockout.title']()}</h2>
				<span class="text-xs px-2 py-1 rounded-full {lockoutSource === 'overlay' ? 'bg-primary/10 text-primary' : 'bg-bg text-muted'}">
					{sourceBadge(lockoutSource)}
				</span>
			</div>
			<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
				<label class="block">
					<span class="text-sm text-muted">{m['security.lockout.max_attempts']()}</span>
					<input
						type="number"
						min="1"
						max="1000"
						bind:value={maxAttempts}
						class="mt-1 w-full px-3 py-2 bg-bg border border-border rounded-lg text-text focus:border-primary focus:outline-none"
					/>
				</label>
				<label class="block">
					<span class="text-sm text-muted">{m['security.lockout.minutes']()}</span>
					<input
						type="number"
						min="1"
						max="10080"
						bind:value={lockMinutes}
						class="mt-1 w-full px-3 py-2 bg-bg border border-border rounded-lg text-text focus:border-primary focus:outline-none"
					/>
				</label>
			</div>
		</div>

		<div class="flex items-center justify-between gap-4">
			<p class="text-xs text-muted flex items-center gap-1.5">
				<KeyRound class="w-3.5 h-3.5 shrink-0" />
				{m['security.apply_note']()}
			</p>
			<LoadingButton onclick={handleSave} loading={saving} variant="primary" label={m['security.save']()} />
		</div>
	{/if}
</div>
