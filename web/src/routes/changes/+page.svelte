<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import DataTable from '$lib/components/DataTable.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import type { ChangeLogEntry, ChangeType, Network } from '$lib/types';

	let changes = $state<ChangeLogEntry[]>([]);
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');
	let offset = $state(0);
	const limit = 50;

	// Auth
	let authState = $state<{ user: { username: string; role: string } | null; token: string | null }>({
		user: null,
		token: null
	});

	// Filters
	let filterNetwork = $state('');
	let filterChangeType = $state('');
	let networks = $state<Network[]>([]);

	const changeTypes: ChangeType[] = ['device_added', 'device_changed', 'device_lost'];

	onMount(() => {
		const unsub = auth.subscribe((v) => {
			authState = v;
		});
		if (get(auth).token) {
			fetchChanges();
			// Best-effort: populate the network filter dropdown.
			api.get<Network[]>('/networks').then((n) => { networks = n || []; }).catch(() => {});
		}
		return unsub;
	});

	async function fetchChanges() {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			params.set('limit', String(limit));
			params.set('offset', String(offset));
			if (filterNetwork) params.set('network_id', filterNetwork);
			if (filterChangeType) params.set('change_type', filterChangeType);
			const res = await api.get<{ changes: ChangeLogEntry[]; total: number }>(`/changes?${params}`);
			changes = res.changes || [];
			total = res.total || 0;
		} catch (err: unknown) {
			error = getErrorMessage(err);
			addToast('error', error);
		} finally {
			loading = false;
		}
	}

	function applyFilters() {
		offset = 0;
		fetchChanges();
	}

	function resetFilters() {
		filterNetwork = '';
		filterChangeType = '';
		offset = 0;
		fetchChanges();
	}

	function handlePageChange(newOffset: number) {
		offset = newOffset;
		fetchChanges();
	}

	function formatTime(iso: string): string {
		if (!iso) return '-';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	// changeTypeLabel returns the localized label for a change type, falling
	// back to the raw value if the i18n key is absent (pre-paraglide-regen).
	function changeTypeLabel(t: string): string {
		switch (t) {
			case 'device_added': return m['changes.Event Added']?.() ?? 'Device Added';
			case 'device_changed': return m['changes.Event Changed']?.() ?? 'Device Changed';
			case 'device_lost': return m['changes.Event Lost']?.() ?? 'Device Lost';
			default: return t;
		}
	}

	// changeTypeBadge returns the Tailwind color classes for a change type:
	// added=success(green), changed=accent(blue), lost=error(red).
	function changeTypeBadge(t: string): string {
		switch (t) {
			case 'device_added': return 'bg-success/10 text-success';
			case 'device_changed': return 'bg-accent/10 text-accent';
			case 'device_lost': return 'bg-error/10 text-error';
			default: return 'bg-surface border border-border text-text-muted';
		}
	}

	// formatData pretty-prints the before_data/after_data JSON (the device
	// snapshot for added/lost, or the {field:[old,new]} diff map for changed).
	function formatData(s?: string): string {
		if (!s) return '-';
		try {
			return JSON.stringify(JSON.parse(s), null, 2);
		} catch {
			return s;
		}
	}

	const columns = $derived([
		{
			key: 'detected_at',
			label: m['changes.Timestamp']?.() ?? 'Time',
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-mono text-xs text-text-muted">${formatTime(String(row.detected_at))}</span>`
		},
		{
			key: 'change_type',
			label: m['changes.Change Type']?.() ?? 'Event',
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const t = String(row.change_type);
				return `<span class="text-xs px-2 py-0.5 rounded-full font-mono ${changeTypeBadge(t)}">${changeTypeLabel(t)}</span>`;
			}
		},
		{
			key: 'entity_id',
			label: m['changes.Device ID']?.() ?? 'Device',
			render: (row: Record<string, unknown>) =>
				`<span class="font-mono text-xs text-text-muted">${row.entity_id ? '#' + row.entity_id : '-'}</span>`
		},
		{
			key: 'network_id',
			label: m['changes.Network']?.() ?? 'Network',
			render: (row: Record<string, unknown>) => {
				const nid = row.network_id as number | undefined;
				if (!nid) return `<span class="text-xs text-text-muted">-</span>`;
				const net = networks.find((n) => n.id === nid);
				return `<span class="text-xs text-text-muted">${net ? net.name : '#' + nid}</span>`;
			}
		},
		{
			key: 'agent_id',
			label: m['changes.Agent']?.() ?? 'Agent',
			render: (row: Record<string, unknown>) =>
				`<span class="font-mono text-xs text-text-muted">${row.agent_id ? String(row.agent_id) : '-'}</span>`
		},
		{
			key: 'after_data',
			label: m['changes.Details']?.() ?? 'Details',
			render: (row: Record<string, unknown>) => {
				const after = row.after_data ? formatData(String(row.after_data)) : '';
				const before = row.before_data ? formatData(String(row.before_data)) : '';
				if (!after && !before) return `<span class="text-xs text-text-muted">-</span>`;
				// Show a truncated preview; full JSON available in the row expand.
				const preview = (after || before).slice(0, 80);
				return `<span class="font-mono text-xs text-text-muted" title="${escapeAttrSimple(preview)}">${escapeHtmlSimple(preview)}${(after || before).length > 80 ? '…' : ''}</span>`;
			}
		}
	]);

	function escapeHtmlSimple(s: string): string {
		return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
	}
	function escapeAttrSimple(s: string): string {
		return escapeHtmlSimple(s).replace(/"/g, '&quot;');
	}
</script>

{#if !authState.token}
	<div class="p-6 text-center text-text-muted">
		<p>{m["errors.Unauthorized Desc"]?.() ?? 'Please log in.'}</p>
		<a href="/login" class="text-primary hover:underline text-sm mt-2 inline-block">{m["navigation.Login"]()}</a>
	</div>
{:else}
<div class="p-4 sm:p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<h2 class="text-2xl font-bold text-primary">{m['changes.Change History']?.() ?? 'Change History'}</h2>
		<button
			onclick={fetchChanges}
			class="px-4 py-2 border border-border text-text-muted rounded-lg
				hover:border-primary hover:text-primary transition-colors text-sm"
		>
			{m["dashboard.Refresh"]()}
		</button>
	</div>

	<!-- Filters -->
	<div class="bg-surface border border-border rounded-lg p-4 mb-4">
		<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
			<!-- Network filter -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['changes.Network']?.() ?? 'Network'}</label>
				<select
					bind:value={filterNetwork}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				>
					<option value="">{m['devices.All Networks']?.() ?? 'All Networks'}</option>
					{#each networks as net}
						<option value={String(net.id)}>{net.name}</option>
					{/each}
				</select>
			</div>

			<!-- Change type filter -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m['changes.Change Type']?.() ?? 'Event'}</label>
				<select
					bind:value={filterChangeType}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				>
					<option value="">{m['changes.All Events']?.() ?? 'All Events'}</option>
					{#each changeTypes as ct}
						<option value={ct}>{changeTypeLabel(ct)}</option>
					{/each}
				</select>
			</div>

			<!-- Buttons -->
			<div class="flex items-end gap-2 col-span-2">
				<button
					onclick={applyFilters}
					class="px-4 py-2 bg-primary text-text-inverse font-semibold rounded-lg
						hover:bg-primary-hover transition-colors text-sm"
				>
					{m["common.Filter"]()}
				</button>
				<button
					onclick={resetFilters}
					class="px-3 py-2 border border-border text-text-muted rounded-lg
						hover:border-primary hover:text-primary transition-colors text-sm"
				>
					{m["audit.Reset"]()}
				</button>
			</div>
		</div>
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
	{:else if changes.length === 0}
		<EmptyState
			icon="📊"
			title={m['changes.No Changes']?.() ?? 'No changes yet'}
			description={m['changes.No Changes Desc']?.() ?? 'Device changes will appear here once scans detect additions, modifications, or losses.'}
		/>
	{:else}
		<div class="bg-surface border border-border rounded-lg p-4">
			<DataTable
				{columns}
				rows={changes as unknown as Record<string, unknown>[]}
				searchPlaceholder="{m['common.Search']?.() ?? 'Search'}..."
				searchableKeys={['change_type', 'agent_id', 'entity_id']}
				emptyTitle={m['changes.No Changes']?.() ?? 'No changes'}
			/>

			<div class="mt-4">
				<Pagination {total} {limit} {offset} onPageChange={handlePageChange} />
			</div>
		</div>
	{/if}
</div>
{/if}
