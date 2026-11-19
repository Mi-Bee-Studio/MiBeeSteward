<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  STUN server list editor (#751): the gateway-profile (UPnP + NAT mapping
  behavior) infrastructure choice. Defaults are PUBLIC infrastructure only;
  users may add their own nodes. The opt-in switch defaults OFF - probing
  exposes the site's public mapping to the selected third parties.
-->
<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import { Globe, Plus, Trash2, PlugZap, RotateCcw, ShieldCheck } from '@lucide/svelte';

	interface StunServer {
		endpoint: string;
		label: string;
		builtin: boolean;
		enabled: boolean;
	}
	interface StunSettings {
		enabled: boolean;
		source: string;
		burst_timeout_ms: number;
		servers: StunServer[];
	}
	interface TestResult {
		ok: boolean;
		mapped_ip?: string;
		mapped_port?: number;
		rtt_ms?: number;
		error?: string;
	}

	let loading = $state(true);
	let saving = $state(false);
	let testing = $state('');
	let enabled = $state(false);
	let source = $state('default');
	let servers = $state<StunServer[]>([]);
	let newEndpoint = $state('');
	let newLabel = $state('');
	let testResults = $state<Record<string, TestResult | 'loading'>>({});

	let isAdmin = $derived($auth.user?.role === 'admin');
	let dirty = $state(false);

	async function reload(query = '') {
		const s = await api.get<StunSettings>(`/settings/probes/stun-servers${query}`);
		enabled = s.enabled;
		source = s.source;
		servers = s.servers;
		testResults = {};
		dirty = false;
	}

	$effect(() => {
		(async () => {
			try {
				await reload();
			} catch (err: unknown) {
				addToast('error', getErrorMessage(err));
			} finally {
				loading = false;
			}
		})();
	});

	async function handleSave() {
		saving = true;
		try {
			const s = await api.put<StunSettings>('/settings/probes/stun-servers', {
				enabled,
				servers: servers.map((r) => ({ endpoint: r.endpoint, label: r.label, enabled: r.enabled }))
			});
			enabled = s.enabled;
			source = s.source;
			servers = s.servers;
			dirty = false;
			addToast('success', m['stun.saved']());
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			saving = false;
		}
	}

	async function handleTest(row: StunServer) {
		testing = row.endpoint;
		testResults = { ...testResults, [row.endpoint]: 'loading' };
		try {
			const res = await api.post<TestResult>('/settings/probes/stun-servers/test', {
				endpoint: row.endpoint
			});
			testResults = { ...testResults, [row.endpoint]: res };
		} catch (err: unknown) {
			testResults = { ...testResults, [row.endpoint]: { ok: false, error: getErrorMessage(err) } };
		} finally {
			testing = '';
		}
	}

	async function restoreDefaults() {
		try {
			const s = await api.get<StunSettings>('/settings/probes/stun-servers?defaults=1');
			servers = s.servers;
			dirty = true;
			testResults = {};
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	function addRow() {
		const ep = newEndpoint.trim();
		if (!ep) return;
		if (servers.some((r) => r.endpoint === ep)) {
			addToast('error', m['stun.duplicate']());
			return;
		}
		servers = [...servers, { endpoint: ep, label: newLabel.trim() || ep, builtin: false, enabled: true }];
		newEndpoint = '';
		newLabel = '';
		dirty = true;
	}

	function removeRow(row: StunServer) {
		servers = servers.filter((r) => r.endpoint !== row.endpoint);
		dirty = true;
	}

	function toggleRow(row: StunServer) {
		servers = servers.map((r) => (r.endpoint === row.endpoint ? { ...r, enabled: !r.enabled } : r));
		dirty = true;
	}

	function testText(row: StunServer): string {
		const raw = testResults[row.endpoint];
		if (!raw || raw === 'loading') return '';
		const t = raw as TestResult;
		if (t.ok) {
			return m['stun.test.ok']({ ip: t.mapped_ip ?? '?', rtt: Math.round((t.rtt_ms ?? 0) * 10) / 10 });
		}
		return m['stun.test.fail']({ error: (t.error ?? '').slice(0, 80) });
	}

	function sourceBadge(src: string): string {
		return src === 'overlay' ? m['security.source.overlay']() : m['security.source.config']();
	}
</script>

<div class="bg-surface border border-border rounded-xl p-6 mb-6">
	<div class="flex items-center justify-between mb-2">
		<h2 class="text-lg font-semibold text-text flex items-center gap-2">
			<Globe class="w-5 h-5 text-muted" />
			{m['stun.title']()}
		</h2>
		<span class="text-xs px-2 py-1 rounded-full {source === 'overlay' ? 'bg-primary/10 text-primary' : 'bg-bg text-muted'}">
			{sourceBadge(source)}
		</span>
	</div>
	<p class="text-sm text-muted mb-1">{m['stun.desc']()}</p>
	<p class="text-xs text-muted mb-4 flex items-start gap-1.5">
		<ShieldCheck class="w-3.5 h-3.5 shrink-0 mt-0.5" />
		{m['stun.optin_note']()}
	</p>

	<button
		type="button"
		onclick={() => {
			enabled = !enabled;
			dirty = true;
		}}
		role="switch"
		aria-checked={enabled}
		class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors {enabled ? 'bg-success' : 'bg-border'}"
	>
		<span class="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform {enabled ? 'translate-x-4.5' : 'translate-x-0.5'}"></span>
	</button>

	{#if !loading && isAdmin}
		<div class="mt-4 space-y-1">
			{#each servers as row (row.endpoint)}
				<div class="flex items-center gap-2 py-1.5 border-b border-border/50 last:border-0">
					<input
						type="checkbox"
						checked={row.enabled}
						onchange={() => toggleRow(row)}
						class="accent-primary"
						aria-label={row.endpoint}
					/>
					<div class="min-w-0 flex-1">
						<div class="flex items-center gap-1.5">
							<span class="text-sm text-text truncate">{row.label}</span>
							{#if row.builtin}
								<span class="text-[0.625rem] px-1.5 py-0.5 rounded bg-bg text-muted">{m['stun.builtin']()}</span>
							{/if}
						</div>
						<div class="text-xs font-mono text-muted truncate">{row.endpoint}</div>
					{#if testResults[row.endpoint] && testResults[row.endpoint] !== 'loading'}
						{@const t = testResults[row.endpoint] as TestResult}
						<div class="text-xs {t.ok ? 'text-success' : 'text-error'}">
							{testText(row)}
						</div>
					{/if}
					</div>
					<button
						type="button"
						disabled={testing === row.endpoint}
						onclick={() => handleTest(row)}
						class="px-2 py-1 text-xs rounded-md border border-border text-muted hover:text-text flex items-center gap-1 disabled:opacity-50"
					>
						<PlugZap class="w-3.5 h-3.5" />
						{m['stun.test']()}
					</button>
					{#if !row.builtin}
						<button
							type="button"
							onclick={() => removeRow(row)}
							class="p-1.5 rounded text-muted hover:text-error"
							aria-label={m['common.Delete']()}
						>
							<Trash2 class="w-4 h-4" />
						</button>
					{/if}
				</div>
			{/each}
		</div>

		<!-- Add custom node -->
		<div class="mt-4 flex items-center gap-2 flex-wrap">
			<input
				class="input font-mono text-xs flex-1 min-w-52"
				placeholder={m['stun.endpoint.placeholder']()}
				bind:value={newEndpoint}
			/>
			<input class="input text-xs w-40" placeholder={m['stun.label.placeholder']()} bind:value={newLabel} />
			<button type="button" onclick={addRow} class="px-2.5 py-1.5 text-xs rounded-md border border-border text-text hover:bg-bg flex items-center gap-1">
				<Plus class="w-3.5 h-3.5" />
				{m['stun.add']()}
			</button>
			<button
				type="button"
				onclick={restoreDefaults}
				class="px-2.5 py-1.5 text-xs rounded-md border border-border text-muted hover:text-text flex items-center gap-1"
			>
				<RotateCcw class="w-3.5 h-3.5" />
				{m['stun.restore']()}
			</button>
		</div>

		<div class="mt-4 flex items-center justify-between gap-4">
			<p class="text-xs text-muted">{m['stun.list_note']({ count: servers.filter((r) => r.enabled).length })}</p>
			<button
				type="button"
				disabled={!dirty || saving}
				onclick={handleSave}
				class="px-3 py-1.5 text-sm rounded-md bg-primary text-white hover:bg-primary/90 disabled:opacity-50"
			>
				{saving ? m['stun.saving']() : m['probeSettings.save']()}
			</button>
		</div>
	{/if}
</div>

