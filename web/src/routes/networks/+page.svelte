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
	import { get } from 'svelte/store';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';

	import Modal from '$lib/components/Modal.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { Network as NetworkIcon } from '@lucide/svelte';
	import type { Network } from '$lib/types';

	let networks = $state<Network[]>([]);
	let loading = $state(true);
	let error = $state('');

	// Auth
	let authState = $state<{ user: { username: string; role: string } | null; token: string | null }>({
		user: null,
		token: null
	});
	let isAdmin = $derived(authState.user?.role === 'admin');

	// --- Create/Edit modal ---
	let formOpen = $state(false);
	let editingId = $state<number | null>(null);
	let formName = $state('');
	let formCidr = $state('');
	let formSite = $state('');
	let formError = $state('');
	let formLoading = $state(false);

	// --- Delete confirm ---
	let deleteOpen = $state(false);
	let deleteTarget = $state<Network | null>(null);
	let deleteLoading = $state(false);

	onMount(() => {
		const unsub = auth.subscribe((v) => { authState = v; });
		if (get(auth).token) {
			fetchNetworks();
		}
		return unsub;
	});

	async function fetchNetworks() {
		loading = true;
		error = '';
		try {
			const res = await api.get<Network[]>('/networks');
			networks = res || [];
		} catch (err: unknown) {
			// Inline banner only on initial load (parallel toast was noisy).
			error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		formName = '';
		formCidr = '';
		formSite = '';
		formError = '';
		editingId = null;
	}

	function openCreate() {
		resetForm();
		formOpen = true;
	}

	function openEdit(net: Network) {
		editingId = net.id;
		formName = net.name;
		formCidr = net.cidr ?? '';
		formSite = net.site ?? '';
		formError = '';
		formOpen = true;
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		if (!formName.trim()) {
			formError = m['networks.Name Required']?.() ?? 'Name is required';
			return;
		}
		formLoading = true;
		formError = '';
		const body = {
			name: formName.trim(),
			cidr: formCidr.trim() || undefined,
			site: formSite.trim() || undefined
		};
		try {
			if (editingId !== null) {
				await api.put(`/networks/${editingId}`, body);
				addToast('success', m['networks.Updated']?.() ?? 'Network updated');
			} else {
				await api.post('/networks', body);
				addToast('success', m['networks.Created']?.() ?? 'Network created');
			}
			formOpen = false;
			resetForm();
			fetchNetworks();
		} catch (err: unknown) {
			formError = getErrorMessage(err);
		} finally {
			formLoading = false;
		}
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		deleteLoading = true;
		try {
			await api.delete(`/networks/${deleteTarget.id}`);
			addToast('success', m['networks.Deleted']?.() ?? 'Network deleted');
			deleteTarget = null;
			fetchNetworks();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			deleteLoading = false;
		}
	}

	// --- DataTable columns ---
	const columns = $derived([
		{
			key: 'name',
			label: m['networks.Name']?.() ?? 'Name',
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-medium text-text">${String(row.name)}</span>`
		},
		{
			key: 'cidr',
			label: 'CIDR',
			render: (row: Record<string, unknown>) => {
				const v = row.cidr as string | null | undefined;
				return v ? `<span class="font-mono text-xs text-text-muted">${v}</span>` : '<span class="text-text-muted">-</span>';
			}
		},
		{
			key: 'site',
			label: m['networks.Site']?.() ?? 'Site',
			render: (row: Record<string, unknown>) => {
				const v = row.site as string | null | undefined;
				return v ? `<span class="text-text-muted">${v}</span>` : '<span class="text-text-muted">-</span>';
			}
		},
		{
			key: 'agent_id',
			label: m['networks.Agent']?.() ?? 'Agent',
			render: (row: Record<string, unknown>) => {
				const v = row.agent_id as string | null | undefined;
				if (!v) return '<span class="text-text-muted text-xs">-</span>';
				return `<span class="text-xs px-2 py-0.5 rounded-full bg-accent/10 text-accent font-mono">${v}</span>`;
			}
		},
		{
			key: 'actions',
			label: m['common.Actions']?.() ?? 'Actions',
			render: (row: Record<string, unknown>) => {
				const id = row.id;
				const agentManaged = !!row.agent_id;
				const revokeHint = agentManaged ? ` title="${m['networks.Agent Managed Hint']?.() ?? 'Agent-managed — deleting clears the agent binding'}"` : '';
				return `<div class="flex gap-2">`
					+ `<button data-edit-id="${id}" class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10">${m['common.Edit']?.() ?? 'Edit'}</button>`
					+ `<button data-delete-id="${id}"${revokeHint} class="text-xs px-2 py-1 rounded text-error hover:bg-error/10">${m['common.Delete']?.() ?? 'Delete'}</button>`
					+ `</div>`;
			}
		}
	]);
</script>

{#if !authState.token}
	<div class="p-6 text-center text-text-muted">
		<p>{m['errors.Unauthorized Desc']?.() ?? 'Please log in.'}</p>
		<a href="/login" class="text-primary hover:underline text-sm mt-2 inline-block">{m['navigation.Login']()}</a>
	</div>
{:else if !isAdmin}
	<div class="p-6 text-center text-text-muted">
		<p>{m['errors.Forbidden Desc']?.() ?? 'Admin access required.'}</p>
	</div>
{:else}
<div class="p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<h2 class="text-2xl font-bold text-primary">{m['networks.Title']?.() ?? 'Networks'}</h2>
		<button onclick={openCreate} class="btn btn-primary">
			+ {m['networks.Create']?.() ?? 'Create Network'}
		</button>
	</div>

	<!-- Info banner: what networks are for -->
	<div class="mb-4 px-4 py-3 bg-primary/5 border border-primary/20 rounded-lg text-sm text-text-muted">
		{m['networks.Help']?.() ?? 'Logical networks are the subnets devices are discovered on. The center\'s own network is auto-resolved from config; create additional networks here to bind remote discovery agents to them.'}
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
	{:else if networks.length === 0}
		<EmptyState
			icon={NetworkIcon}
			title={m['networks.Empty']?.() ?? 'No networks defined'}
			description={m['networks.Empty Desc']?.() ?? 'Create a network to bind a discovery agent to it.'}
			actionLabel={m['networks.Create']?.() ?? 'Create Network'}
			onAction={openCreate}
		/>
	{:else}
		<div class="bg-surface border border-border rounded-lg p-4">
			<!-- svelte-ignore a11y_no_static_element_interactions -->
			<!-- svelte-ignore a11y_click_events_have_key_events -->
			<div onclick={(e) => {
				const target = e.target as HTMLElement;
				const editBtn = target.closest('[data-edit-id]') as HTMLElement | null;
				if (editBtn) {
					const id = Number(editBtn.dataset.editId);
					const net = networks.find((n) => n.id === id);
					if (net) openEdit(net);
					return;
				}
				const delBtn = target.closest('[data-delete-id]') as HTMLElement | null;
				if (delBtn) {
					const id = Number(delBtn.dataset.deleteId);
					const net = networks.find((n) => n.id === id);
					if (net) { deleteTarget = net; deleteOpen = true; }
				}
			}}>
				<DataTable
					{columns}
					rows={networks as unknown as Record<string, unknown>[]}
					searchableKeys={['name', 'site']}
					emptyTitle={m['networks.Empty']?.() ?? 'No networks'}
				/>
			</div>
		</div>
	{/if}
</div>
{/if}

<!-- Create/Edit Modal -->
<Modal bind:open={formOpen} title={editingId !== null ? (m['networks.Edit']?.() ?? 'Edit Network') : (m['networks.Create']?.() ?? 'Create Network')} maxWidth="36rem" onClose={resetForm}>
	{#if formError}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{formError}
		</div>
	{/if}

	<form onsubmit={handleSubmit} class="space-y-4">
		<!-- Name -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m['networks.Name']?.() ?? 'Name'} *</label>
			<input bind:value={formName} required placeholder="e.g. lan-beijing-62" class="input" />
			<p class="text-xs text-text-muted mt-1">{m['networks.Name Help']?.() ?? 'Unique identifier (e.g. lan-62, datacenter-fra)'}</p>
		</div>

		<!-- CIDR -->
		<div>
			<label class="block text-xs text-text-muted mb-1">CIDR</label>
			<input bind:value={formCidr} placeholder="e.g. 192.168.62.0/24" class="input font-mono" />
			<p class="text-xs text-text-muted mt-1">{m['networks.Cidr Help']?.() ?? 'Advisory — used for display, not enforcement'}</p>
		</div>

		<!-- Site -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m['networks.Site']?.() ?? 'Site'}</label>
			<input bind:value={formSite} placeholder="e.g. Beijing branch / datacenter / cloud" class="input" />
		</div>

		<!-- Actions -->
		<div class="flex gap-3 pt-2">
			<LoadingButton type="submit" loading={formLoading} variant="primary" label={m['common.Save']?.() ?? 'Save'} />
			<button type="button" onclick={() => { formOpen = false; resetForm(); }} class="btn btn-secondary">
				{m['common.Cancel']?.() ?? 'Cancel'}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete confirmation -->
<ConfirmDialog
	bind:open={deleteOpen}
	title={m['networks.Delete']?.() ?? 'Delete Network'}
	message={deleteTarget ? `${m['networks.Delete Confirm']?.() ?? 'Delete network'} "${deleteTarget.name}"? ${m['networks.Delete Warning']?.() ?? 'Devices on this network will have their network binding cleared.'}` : ''}
	confirmLabel={m['common.Delete']?.() ?? 'Delete'}
	confirmVariant="danger"
	onConfirm={confirmDelete}
	onCancel={() => { deleteTarget = null; }}
/>
