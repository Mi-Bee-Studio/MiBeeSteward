<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { Bot as BotIcon } from '@lucide/svelte';

	import type { AgentToken, AgentTokenCreated, Network } from '$lib/types';

	// --- State ---
	let tokens = $state<AgentToken[]>([]);
	let networks = $state<Network[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Auth
	let authState = $state<{ user: { username: string; role: string } | null; token: string | null }>({
		user: null,
		token: null
	});
	let isAdmin = $derived(authState.user?.role === 'admin');

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
		const unsub = auth.subscribe((v) => { authState = v; });
		if (get(auth).token) {
			fetchTokens();
			fetchNetworks();
		}
		return unsub;
	});

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

	function openCreate() {
		resetForm();
		createModalOpen = true;
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!formAgentId) { addToast('error', m['agents.Agent ID Required']?.() ?? 'Agent ID is required'); return; }
		if (!formNetworkId) { addToast('error', m['agents.Network Required']?.() ?? 'Network is required'); return; }
		formLoading = true;
		try {
			const res = await api.post<AgentTokenCreated>('/agents/tokens/', {
				agent_id: formAgentId,
				network_id: Number(formNetworkId),
				name: formName || undefined
			});
			// Show the one-time token instead of closing the modal.
			createdToken = res.token;
			addToast('success', m['agents.Token Created']?.() ?? 'Agent token created');
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
			addToast('success', m['agents.Token Revoked']?.() ?? 'Agent token revoked');
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
		if (!scanTargets) { addToast('error', m['agents.Targets Required']?.() ?? 'Scan targets are required'); return; }
		scanLoading = true;
		try {
			await api.post(`/agents/${scanAgentId}/commands/`, {
				command: 'scan',
				payload: { targets: scanTargets, timeout: scanTimeout }
			});
			scanModalOpen = false;
			addToast('success', (m['agents.Scan Triggered']?.() ?? 'Scan command queued for {agentId}').replace('{agentId}', scanAgentId));
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
		if (t.revoked_at) return { label: m['agents.Revoked']?.() ?? 'Revoked', cls: 'bg-error/10 text-error' };
		if (t.last_used_at) {
			const age = Date.now() - new Date(t.last_used_at).getTime();
			if (age < 5 * 60 * 1000) return { label: m['agents.Active']?.() ?? 'Active', cls: 'bg-success/10 text-success' };
		}
		return { label: m['agents.Idle']?.() ?? 'Idle', cls: 'bg-surface text-text-muted border border-border' };
	}

	async function copyToken() {
		if (!createdToken) return;
		try {
			await navigator.clipboard.writeText(createdToken);
			addToast('success', m['agents.Copied']?.() ?? 'Copied to clipboard');
		} catch {
			addToast('error', 'Failed to copy');
		}
	}

	// --- DataTable columns ---
	const columns = $derived([
		{
			key: 'agent_id',
			label: m['agents.Agent ID']?.() ?? 'Agent ID',
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-medium text-text font-mono text-sm">${String(row.agent_id)}</span>`
		},
		{
			key: 'name',
			label: m['agents.Name']?.() ?? 'Name',
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted">${row.name ? String(row.name) : '-'}</span>`
		},
		{
			key: 'network',
			label: m['agents.Network']?.() ?? 'Network',
			render: (row: Record<string, unknown>) => {
				const nid = row.network_id as number | undefined;
				const name = nid ? (networkNames[nid] ?? `#${nid}`) : '-';
				return `<span class="text-text-muted">${name}</span>`;
			}
		},
		{
			key: 'status',
			label: m['agents.Status']?.() ?? 'Status',
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const t = row as unknown as AgentToken;
				const s = tokenStatus(t);
				return `<span class="text-xs px-2 py-0.5 rounded-full font-mono ${s.cls}">${s.label}</span>`;
			}
		},
		{
			key: 'last_used_at',
			label: m['agents.Last Used']?.() ?? 'Last Used',
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const v = row.last_used_at as string | null | undefined;
				if (!v) return `<span class="text-text-muted">-</span>`;
				return `<span class="text-text-muted text-xs">${timeAgo(v)}</span>`;
			}
		},
		{
			key: 'created_at',
			label: m['agents.Created At']?.() ?? 'Created At',
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted text-xs">${formatTime(row.created_at as string)}</span>`
		},
		{
			key: 'actions',
			label: m['common.Actions']?.() ?? 'Actions',
			render: (row: Record<string, unknown>) => {
				const agentId = String(row.agent_id);
				const tokenId = row.id;
				const isRevoked = !!row.revoked_at;
				const scanBtn = isRevoked ? '' : `<button data-scan-id="${agentId}" class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors">${m['agents.Trigger Scan']?.() ?? 'Scan'}</button>`;
				const revokeBtn = isRevoked ? '' : `<button data-revoke-id="${tokenId}" class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors">${m['agents.Revoke']?.() ?? 'Revoke'}</button>`;
				return `<div class="flex items-center gap-2">${scanBtn}${revokeBtn}</div>`;
			}
		}
	]);
</script>

{#if !authState.token}
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
		<h2 class="text-2xl font-bold text-primary">{m['agents.Title']?.() ?? 'Agent Management'}</h2>
		<button onclick={openCreate} class="btn btn-primary">
			+ {m['agents.Create Token']?.() ?? 'Create Token'}
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
			title={m['agents.No Tokens']?.() ?? 'No agent tokens'}
			description={m['agents.No Tokens Desc']?.() ?? 'Create an agent token to allow a remote agent to report discoveries.'}
			actionLabel={m['agents.Create Token']?.() ?? 'Create Token'}
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
					searchPlaceholder={(m['common.Search']?.() ?? 'Search') + '...'}
					searchableKeys={['agent_id', 'name']}
					emptyTitle={m['agents.No Tokens']?.() ?? 'No agent tokens'}
				/>
			</div>
		</div>
	{/if}
</div>
{/if}

<!-- Create Token Modal -->
<Modal bind:open={createModalOpen} title={m['agents.Create Token']?.() ?? 'Create Token'} onClose={resetForm}>
	{#if createdToken}
		<!-- One-time token display view (after successful creation) -->
		<div class="space-y-4">
			<div class="px-4 py-3 bg-warning/10 border border-warning/30 rounded-lg text-sm text-warning">
				⚠️ {m['agents.Token Warning']?.() ?? 'This token is shown only once. Copy it now.'}
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1">Token</label>
				<div class="flex gap-2">
					<input readonly value={createdToken} class="input font-mono text-xs" />
					<button onclick={copyToken} class="btn btn-secondary whitespace-nowrap">
						{m['agents.Copy Token']?.() ?? 'Copy'}
					</button>
				</div>
			</div>
			<div class="flex gap-3 pt-2">
				<button
					type="button"
					onclick={() => { createModalOpen = false; resetForm(); }}
					class="btn btn-primary"
				>
					{m['common.Close']?.() ?? 'Close'}
				</button>
			</div>
		</div>
	{:else}
		<!-- Create form view -->
		<form onsubmit={handleSubmit} class="space-y-4">
			<!-- Agent ID -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['agents.Agent ID']?.() ?? 'Agent ID'} *</label>
				<input bind:value={formAgentId} required placeholder="e.g. agent-lan-62" class="input" />
			</div>

			<!-- Network -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['agents.Network']?.() ?? 'Network'} *</label>
				<select bind:value={formNetworkId} required class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text focus:border-primary focus:outline-none">
					<option value="">{m['devices.All Networks']?.() ?? 'Select...'}</option>
					{#each networks as net}
						<option value={String(net.id)}>{net.name}{net.cidr ? ` (${net.cidr})` : ''}</option>
					{/each}
				</select>
			</div>

			<!-- Name (optional) -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['agents.Name']?.() ?? 'Name'}</label>
				<input bind:value={formName} placeholder="e.g. Branch Beijing LAN-62" class="input" />
			</div>

			<!-- Actions -->
			<div class="flex gap-3 pt-2">
				<button type="submit" disabled={formLoading} class="btn btn-primary">
					{formLoading ? '...' : m['common.Save']?.() ?? 'Create'}
				</button>
				<button type="button" onclick={() => { createModalOpen = false; resetForm(); }} class="btn btn-secondary">
					{m['common.Cancel']?.() ?? 'Cancel'}
				</button>
			</div>
		</form>
	{/if}
</Modal>

<!-- Revoke ConfirmDialog -->
<ConfirmDialog
	bind:open={revokeDialogOpen}
	title={m['agents.Revoke']?.() ?? 'Revoke Token'}
	message={revokeTarget ? (m['agents.Revoke Confirm']?.() ?? 'Are you sure?') : ''}
	confirmLabel={m['agents.Revoke']?.() ?? 'Revoke'}
	confirmVariant="danger"
	onConfirm={confirmRevoke}
	onCancel={() => { revokeTarget = null; }}
/>

<!-- Trigger Scan Modal -->
<Modal bind:open={scanModalOpen} title={`${m['agents.Trigger Scan']?.() ?? 'Trigger Scan'}: ${scanAgentId}`}>
	<form onsubmit={handleScanSubmit} class="space-y-4">
		<!-- Targets -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m['agents.Scan Targets']?.() ?? 'Scan Targets'} *</label>
			<input bind:value={scanTargets} required placeholder={m['agents.Scan Targets Placeholder']?.() ?? 'e.g. 192.168.62.0/24'} class="input" />
		</div>

		<!-- Timeout -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m['agents.Timeout']?.() ?? 'Timeout (seconds)'}</label>
			<input type="number" bind:value={scanTimeout} min="10" max="600" class="input" />
		</div>

		<!-- Actions -->
		<div class="flex gap-3 pt-2">
			<button type="submit" disabled={scanLoading} class="btn btn-primary">
				{scanLoading ? '...' : m['agents.Trigger Scan']?.() ?? 'Trigger Scan'}
			</button>
			<button type="button" onclick={() => { scanModalOpen = false; }} class="btn btn-secondary">
				{m['common.Cancel']?.() ?? 'Cancel'}
			</button>
		</div>
	</form>
</Modal>
