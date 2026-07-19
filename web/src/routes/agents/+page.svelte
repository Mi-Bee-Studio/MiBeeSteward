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
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';

	import Modal from '$lib/components/Modal.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { Bot as BotIcon } from '@lucide/svelte';

	import type { AgentToken, AgentTokenCreated, AgentCommand, Network } from '$lib/types';

	// --- State ---
	let tokens = $state<AgentToken[]>([]);
	let networks = $state<Network[]>([]);
	let loading = $state(true);
	let error = $state('');

	// --- Command history ---
	let commands = $state<AgentCommand[]>([]);
	let commandsTotal = $state(0);
	let commandsLoading = $state(false);
	let commandsExpandedId = $state<number | null>(null);
	let commandPollTimer: ReturnType<typeof setInterval> | null = null;

	// Auth is consumed directly via the $auth store (auto-subscribed in .svelte).
	let isAdmin = $derived($auth.user?.role === 'admin');

	// Network name lookup map
	let networkNames = $derived.by(() => {
		const map: Record<number, string> = {};
		for (const n of networks) map[n.id] = n.name;
		return map;
	});

	// --- Create Token Modal ---
	let createModalOpen = $state(false);
	let formAgentId = $state('');
	let formNetworkId = $state('');
	let formName = $state('');
	let formLoading = $state(false);
	// After creation, show the one-time plaintext token
	let createdToken = $state<string | null>(null);

	// --- Revoke ConfirmDialog ---
	let revokeDialogOpen = $state(false);
	let revokeTarget = $state<AgentToken | null>(null);

	// --- Scan Trigger Modal ---
	let scanModalOpen = $state(false);
	let scanAgentId = $state('');
	let scanTargets = $state('');
	let scanTimeout = $state(120);
	let scanLoading = $state(false);

	onMount(() => {
		fetchTokens();
		fetchNetworks();
		fetchCommands();
		// Poll the command queue so the admin sees status transitions
		// (pending → acknowledged → done/failed) without a manual refresh.
		commandPollTimer = setInterval(fetchCommands, 10000);
	});

	onDestroy(() => {
		if (commandPollTimer) clearInterval(commandPollTimer);
	});

	async function fetchCommands() {
		commandsLoading = true;
		try {
			const res = await api.get<{ commands: AgentCommand[]; total: number }>('/agents/commands/all?limit=30');
			commands = res.commands || [];
			commandsTotal = res.total || 0;
		} catch {
			// Non-critical — the command panel just stays empty.
		} finally {
			commandsLoading = false;
		}
	}

	async function fetchTokens() {
		loading = true;
		error = '';
		try {
			// Backend returns a bare JSON array, not {data: [...]}.
			const res = await api.get<AgentToken[]>('/agents/tokens/');
			tokens = res || [];
		} catch (err: unknown) {
			error = getErrorMessage(err);
			addToast('error', error);
		} finally {
			loading = false;
		}
	}

	async function fetchNetworks() {
		try {
			const res = await api.get<Network[]>('/networks');
			networks = res || [];
		} catch {
			// Non-critical — the network dropdown just stays empty.
		}
	}

	// --- Create Token ---
	function resetForm() {
		formAgentId = '';
		formNetworkId = '';
		formName = '';
		createdToken = null;
	}

	// The one-time token (createdToken) is unrecoverable — once the modal
	// closes it's gone forever. confirmDiscard gates the close on the
	// existing "unsaved changes" overlay so Esc / backdrop / X all warn first
	// instead of silently discarding the token. Returning true when a token
	// is showing pops the discard confirmation; the user must click Discard
	// to actually close.
	function confirmTokenDiscard(): boolean {
		return createdToken !== null;
	}

	function openCreate() {
		resetForm();
		createModalOpen = true;
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!formAgentId) { addToast('error', m['agents.Agent ID Required']()); return; }
		if (!formNetworkId) { addToast('error', m['agents.Network Required']()); return; }
		formLoading = true;
		try {
			const res = await api.post<AgentTokenCreated>('/agents/tokens/', {
				agent_id: formAgentId,
				network_id: Number(formNetworkId),
				name: formName || undefined
			});
			// Show the one-time token instead of closing the modal.
			createdToken = res.token;
			addToast('success', m['agents.Token Created']());
			fetchTokens();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			formLoading = false;
		}
	}

	// --- Revoke ---
	function openRevoke(token: AgentToken) {
		revokeTarget = token;
		revokeDialogOpen = true;
	}

	async function confirmRevoke() {
		if (!revokeTarget) return;
		try {
			await api.post(`/agents/tokens/${revokeTarget.id}/revoke`, {});
			revokeTarget = null;
			addToast('success', m['agents.Token Revoked']());
			fetchTokens();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Trigger Scan ---
	function openScan(agentId: string) {
		scanAgentId = agentId;
		scanTargets = '';
		scanTimeout = 120;
		scanModalOpen = true;
	}

	async function handleScanSubmit(e: Event) {
		e.preventDefault();
		if (!scanTargets) { addToast('error', m['agents.Targets Required']()); return; }
		scanLoading = true;
		try {
			await api.post(`/agents/${scanAgentId}/commands/`, {
					command: 'scan',
					payload: { targets: scanTargets, timeout: scanTimeout }
				});
				scanModalOpen = false;
				addToast('success', (m['agents.Scan Triggered']()).replace('{agentId}', scanAgentId));
				fetchCommands();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			scanLoading = false;
		}
	}

	// --- Helpers ---
	function formatTime(iso?: string | null): string {
		if (!iso) return '-';
		try { return new Date(iso).toLocaleString(); } catch { return iso; }
	}

	function timeAgo(iso?: string | null): string {
		if (!iso) return '-';
		try {
			const diff = Date.now() - new Date(iso).getTime();
			const mins = Math.floor(diff / 60000);
			if (mins < 1) return '<1m';
			if (mins < 60) return `${mins}m`;
			const hrs = Math.floor(mins / 60);
			if (hrs < 24) return `${hrs}h`;
			return `${Math.floor(hrs / 24)}d`;
		} catch { return iso; }
	}

	function tokenStatus(t: AgentToken): { label: string; cls: string } {
		if (t.revoked_at) return { label: m['agents.Revoked'](), cls: 'bg-error/10 text-error' };
		if (t.last_used_at) {
			const age = Date.now() - new Date(t.last_used_at).getTime();
			if (age < 5 * 60 * 1000) return { label: m['agents.Active'](), cls: 'bg-success/10 text-success' };
		}
		return { label: m['agents.Idle'](), cls: 'bg-surface text-text-muted border border-border' };
	}

	async function copyToken() {
		if (!createdToken) return;
		try {
			await navigator.clipboard.writeText(createdToken);
			addToast('success', m['agents.Copied']());
		} catch {
			addToast('error', 'Failed to copy');
		}
	}

	// --- DataTable columns ---
	const columns = $derived([
		{
			key: 'agent_id',
			label: m['agents.Agent ID'](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-medium text-text font-mono text-sm">${String(row.agent_id)}</span>`
		},
		{
			key: 'name',
			label: m['agents.Name'](),
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted">${row.name ? String(row.name) : '-'}</span>`
		},
		{
			key: 'network',
			label: m['agents.Network'](),
			render: (row: Record<string, unknown>) => {
				const nid = row.network_id as number | undefined;
				const name = nid ? (networkNames[nid] ?? `#${nid}`) : '-';
				return `<span class="text-text-muted">${name}</span>`;
			}
		},
		{
			key: 'status',
			label: m['agents.Status'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const t = row as unknown as AgentToken;
				const s = tokenStatus(t);
				return `<span class="text-xs px-2 py-0.5 rounded-full font-mono ${s.cls}">${s.label}</span>`;
			}
		},
		{
			key: 'last_used_at',
			label: m['agents.Last Used'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const v = row.last_used_at as string | null | undefined;
				if (!v) return `<span class="text-text-muted">-</span>`;
				return `<span class="text-text-muted text-xs">${timeAgo(v)}</span>`;
			}
		},
		{
			key: 'created_at',
			label: m['agents.Created At'](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted text-xs">${formatTime(row.created_at as string)}</span>`
		},
		{
			key: 'actions',
			label: m['common.Actions'](),
			render: (row: Record<string, unknown>) => {
				const agentId = String(row.agent_id);
				const tokenId = row.id;
				const isRevoked = !!row.revoked_at;
				const scanBtn = isRevoked ? '' : `<button data-scan-id="${agentId}" class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors">${m['agents.Trigger Scan']()}</button>`;
				const revokeBtn = isRevoked ? '' : `<button data-revoke-id="${tokenId}" class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors">${m['agents.Revoke']()}</button>`;
				return `<div class="flex items-center gap-2">${scanBtn}${revokeBtn}</div>`;
			}
		}
	]);

	// --- Command status helper ---
	function commandStatusBadge(status: string): { label: string; cls: string } {
		switch (status) {
			case 'pending': return { label: m['agents.Pending'](), cls: 'bg-warning/10 text-warning' };
			case 'acknowledged': return { label: m['agents.Acknowledged'](), cls: 'bg-accent/10 text-accent' };
			case 'done': return { label: m['agents.Done'](), cls: 'bg-success/10 text-success' };
			case 'failed': return { label: m['agents.Failed'](), cls: 'bg-error/10 text-error' };
			default: return { label: status, cls: 'bg-surface text-text-muted border border-border' };
		}
	}

	function prettyJson(raw: string | null | undefined): string {
		if (!raw) return '';
		try {
			return JSON.stringify(JSON.parse(raw), null, 2);
		} catch {
			return raw;
		}
	}

	// --- Command history columns ---
	const commandColumns = $derived([
		{
			key: '_expand',
			label: '',
			sortable: false,
			render: (row: Record<string, unknown>) => {
				const id = row.id as number;
				const isOpen = commandsExpandedId === id;
				return `<button data-action="expand" data-id="${id}" class="p-1 rounded hover:bg-primary/10 transition-colors text-text-muted">`
					+ `<svg class="w-3.5 h-3.5 transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">`
					+ `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg></button>`;
			}
		},
		{
			key: 'agent_id',
			label: m['agents.Agent ID'](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-mono text-xs text-text">${String(row.agent_id)}</span>`
		},
		{
			key: 'command',
			label: m['agents.Command'](),
			render: (row: Record<string, unknown>) =>
				`<span class="font-mono text-xs text-text">${String(row.command)}</span>`
		},
		{
			key: 'status',
			label: m['agents.Status'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const s = commandStatusBadge(String(row.status));
				return `<span class="text-xs px-2 py-0.5 rounded-full font-mono ${s.cls}">${s.label}</span>`;
			}
		},
		{
			key: 'created_at',
			label: m['agents.Created'](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted text-xs">${formatTime(row.created_at as string)}</span>`
		},
		{
			key: 'acknowledged_at',
			label: m['agents.Acknowledged'](),
			render: (row: Record<string, unknown>) => {
				const v = row.acknowledged_at as string | null | undefined;
				return `<span class="text-text-muted text-xs">${v ? formatTime(v) : '-'}</span>`;
			}
		}
	]);
</script>

{#if !$auth.token}
	<div class="p-6 text-center text-text-muted">
		<p>{m["errors.Unauthorized Desc"]()}</p>
		<a href="/login" class="text-primary hover:underline text-sm mt-2 inline-block">{m["navigation.Login"]()}</a>
	</div>
{:else if !isAdmin}
	<div class="p-6 text-center text-text-muted">
		<p>{m["errors.Forbidden Desc"]()}</p>
	</div>
{:else}
<div class="p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<h2 class="text-2xl font-bold text-primary">{m['agents.Title']()}</h2>
		<button onclick={openCreate} class="btn btn-primary">
			+ {m['agents.Create Token']()}
		</button>
	</div>

	<!-- Error -->
	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{error}
		</div>
	{/if}

	<!-- Content -->
	{#if loading}
		<PageSkeleton type="table" />
	{:else if tokens.length === 0}
		<EmptyState
			icon={BotIcon}
			title={m['agents.No Tokens']()}
			description={m['agents.No Tokens Desc']()}
			actionLabel={m['agents.Create Token']()}
			onAction={openCreate}
		/>
	{:else}
		<div class="bg-surface border border-border rounded-lg p-4">
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<!-- svelte-ignore a11y_click_events_have_key_events -->
			<div onclick={(e) => {
				const target = e.target as HTMLElement;
				const scanBtn = target.closest('[data-scan-id]') as HTMLElement | null;
				if (scanBtn) { openScan(String(scanBtn.dataset.scanId)); return; }
				const revokeBtn = target.closest('[data-revoke-id]') as HTMLElement | null;
				if (revokeBtn) {
					const id = Number(revokeBtn.dataset.revokeId);
					const token = tokens.find((t) => t.id === id);
					if (token) openRevoke(token);
				}
			}}>
				<DataTable
					{columns}
					rows={tokens as unknown as Record<string, unknown>[]}
					searchPlaceholder={(m['common.Search']()) + '...'}
					searchableKeys={['agent_id', 'name']}
					emptyTitle={m['agents.No Tokens']()}
				/>
			</div>
			</div>
		{/if}

		<!-- Command History (center → agent command queue) -->
		<div class="mt-8">
			<div class="flex items-center justify-between mb-4">
				<h3 class="text-lg font-semibold text-text">
					{m['agents.Command History']()}
					<span class="text-text-muted font-normal text-sm">({commandsTotal})</span>
				</h3>
				<button
					onclick={fetchCommands}
					class="px-3 py-1.5 border border-border text-text-muted rounded-lg
						hover:border-primary hover:text-primary transition-colors text-xs"
				>
					{m["dashboard.Refresh"]()}
				</button>
			</div>

			{#if commands.length === 0 && !commandsLoading}
				<div class="bg-surface border border-border rounded-lg p-4 text-center">
					<p class="text-sm text-text-muted">{m['agents.No Commands']()}</p>
				</div>
			{:else}
				<div class="bg-surface border border-border rounded-lg p-4">
					<div onclick={(e) => {
						const btn = (e.target as HTMLElement).closest('[data-action="expand"]') as HTMLElement | null;
						if (btn) {
							const id = Number(btn.dataset.id);
							commandsExpandedId = commandsExpandedId === id ? null : id;
						}
					}}>
						<DataTable
							columns={commandColumns}
							rows={commands as unknown as Record<string, unknown>[]}
							searchableKeys={['agent_id', 'command', 'status']}
							emptyTitle={m['agents.No Commands']()}
							expandedRowId={commandsExpandedId ?? undefined}
						>
							{#snippet expandedContent(row)}
								{@const cmd = commands.find((c) => c.id === row.id)}
								<div class="border-t border-border bg-bg/40 px-6 py-4 space-y-3">
									{#if cmd?.payload}
										<div>
											<span class="text-[10px] text-text-muted uppercase tracking-wide">Payload</span>
											<pre class="text-xs text-text bg-bg/50 border border-border rounded p-2 mt-1 overflow-x-auto whitespace-pre-wrap break-all max-h-40">{prettyJson(cmd.payload)}</pre>
										</div>
									{/if}
									{#if cmd?.result}
										<div>
											<span class="text-[10px] text-text-muted uppercase tracking-wide">Result</span>
											<pre class="text-xs text-text bg-bg/50 border border-border rounded p-2 mt-1 overflow-x-auto whitespace-pre-wrap break-all max-h-40">{prettyJson(cmd.result)}</pre>
										</div>
									{/if}
								</div>
							{/snippet}
						</DataTable>
					</div>
				</div>
			{/if}
		</div>
	</div>
{/if}

<!-- Create Token Modal -->
<Modal
	bind:open={createModalOpen}
	title={m['agents.Create Token']()}
	onClose={resetForm}
	confirmDiscard={confirmTokenDiscard}
	discardTitle={m['agents.Token Discard Title']()}
	discardMessage={m['agents.Token Discard Message']()}
>
	{#if createdToken}
		<!-- One-time token display view (after successful creation) -->
		<div class="space-y-4">
			<div class="px-4 py-3 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
				⚠️ {m['agents.Token Warning']()}
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1">Token</label>
				<div class="flex gap-2">
					<input readonly value={createdToken} class="input font-mono text-xs" />
					<button onclick={copyToken} class="btn btn-secondary whitespace-nowrap">
						{m['agents.Copy Token']()}
					</button>
				</div>
			</div>
			<div class="flex gap-3 pt-2">
				<button
					type="button"
					onclick={() => { createModalOpen = false; resetForm(); }}
					class="btn btn-primary"
				>
					{m['common.Close']()}
				</button>
			</div>
		</div>
	{:else}
		<!-- Create form view -->
		<form onsubmit={handleSubmit} class="space-y-4">
			<!-- Agent ID -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['agents.Agent ID']()} *</label>
				<input bind:value={formAgentId} required placeholder="e.g. agent-lan-62" class="input" />
			</div>

			<!-- Network -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['agents.Network']()} *</label>
				<select bind:value={formNetworkId} required class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:border-primary focus:outline-none">
					<option value="">{m['devices.All Networks']()}</option>
					{#each networks as net}
						<option value={String(net.id)}>{net.name}{net.cidr ? ` (${net.cidr})` : ''}</option>
					{/each}
				</select>
			</div>

			<!-- Name (optional) -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['agents.Name']()}</label>
				<input bind:value={formName} placeholder="e.g. Branch Beijing LAN-62" class="input" />
			</div>

			<!-- Actions -->
			<div class="flex gap-3 pt-2">
				<LoadingButton type="submit" loading={formLoading} variant="primary" label={m['common.Save']()} />
				<button type="button" onclick={() => { createModalOpen = false; resetForm(); }} class="btn btn-secondary">
					{m['common.Cancel']()}
				</button>
			</div>
		</form>
	{/if}
</Modal>

<!-- Revoke ConfirmDialog -->
<ConfirmDialog
	bind:open={revokeDialogOpen}
	title={m['agents.Revoke']()}
	message={revokeTarget ? (m['agents.Revoke Confirm']()) : ''}
	confirmLabel={m['agents.Revoke']()}
	confirmVariant="danger"
	onConfirm={confirmRevoke}
	onCancel={() => { revokeTarget = null; }}
/>

<!-- Trigger Scan Modal -->
<Modal bind:open={scanModalOpen} title={`${m['agents.Trigger Scan']()}: ${scanAgentId}`}>
	<form onsubmit={handleScanSubmit} class="space-y-4">
		<!-- Targets -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m['agents.Scan Targets']()} *</label>
			<input bind:value={scanTargets} required placeholder={m['agents.Scan Targets Placeholder']()} class="input" />
		</div>

		<!-- Timeout -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m['agents.Timeout']()}</label>
			<input type="number" bind:value={scanTimeout} min="10" max="600" class="input" />
		</div>

		<!-- Actions -->
		<div class="flex gap-3 pt-2">
			<LoadingButton type="submit" loading={scanLoading} variant="primary" label={m['agents.Trigger Scan']()} />
			<button type="button" onclick={() => { scanModalOpen = false; }} class="btn btn-secondary">
				{m['common.Cancel']()}
			</button>
		</div>
	</form>
</Modal>
