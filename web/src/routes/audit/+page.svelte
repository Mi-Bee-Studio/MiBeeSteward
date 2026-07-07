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

	interface AuditLog {
		id: number;
		user_id: number;
		username: string;
		action: string;
		resource_type: string;
		resource_id: string;
		ip_address: string;
		user_agent: string;
		details: string;
		created_at: string;
	}

	let logs = $state<AuditLog[]>([]);
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
	let filterUser = $state('');
	let filterAction = $state('');
	let filterResourceType = $state('');
	let filterDateFrom = $state('');
	let filterDateTo = $state('');

	// Available filter options (fetched from API or hardcoded)
	let users = $state<{ id: number; username: string }[]>([]);
	const commonActions = [
		'auth.login.success',
		'auth.login.failure',
		'auth.logout',
		'auth.password.change',
		'admin.user.create',
		'admin.user.delete',
		'device.create',
		'device.update',
		'device.delete',
		'file.upload',
		'file.delete',
		'scanner.scan',
		'scanner.add_devices'
	];
	const resourceTypes = ['user', 'device', 'document', 'system', 'heartbeat_config', 'notification_channel'];

	onMount(() => {
		const unsub = auth.subscribe((v) => {
			authState = v;
		});
		if (get(auth).token) {
			fetchAuditLogs();
			fetchUsers();
		}
		return unsub;
	});

	async function fetchUsers() {
		try {
			const res = await api.get<{ users: { id: number; username: string }[]; total: number }>('/users?limit=100&offset=0');
			users = res.users || [];
		} catch {
			// Non-critical — filter dropdown just won't populate
		}
	}

	async function fetchAuditLogs() {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			params.set('limit', String(limit));
			params.set('offset', String(offset));
			if (filterUser) params.set('user_id', filterUser);
			if (filterAction) params.set('action', filterAction);
			if (filterResourceType) params.set('resource_type', filterResourceType);
			if (filterDateFrom) params.set('date_from', filterDateFrom);
			if (filterDateTo) params.set('date_to', filterDateTo);
			const res = await api.get<{ audit_logs: AuditLog[]; total: number }>(`/audit-logs?${params}`);
			logs = res.audit_logs || [];
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
		fetchAuditLogs();
	}

	function resetFilters() {
		filterUser = '';
		filterAction = '';
		filterResourceType = '';
		filterDateFrom = '';
		filterDateTo = '';
		offset = 0;
		fetchAuditLogs();
	}

	function handlePageChange(newOffset: number) {
		offset = newOffset;
		fetchAuditLogs();
	}

	function formatTime(iso: string): string {
		if (!iso) return '-';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	let isAdmin = $derived(authState.user?.role === 'admin');

	const columns = $derived([
		{
			key: 'created_at',
			label: m["audit.Timestamp"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-mono text-xs text-text-muted">${formatTime(String(row.created_at))}</span>`
		},
		{
			key: 'username',
			label: m["audit.User"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-medium text-text">${String(row.username)}</span>`
		},
		{
			key: 'action',
			label: m["audit.Action"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const action = String(row.action);
				const isAuth = action.startsWith('auth.');
				const isAdminAction = action.startsWith('admin.');
				const cls = isAuth
					? 'bg-accent/10 text-accent'
					: isAdminAction
						? 'bg-error/10 text-error'
						: 'bg-primary/10 text-primary';
				return `<span class="text-xs px-2 py-0.5 rounded-full font-mono ${cls}">${action}</span>`;
			}
		},
		{
			key: 'resource_type',
			label: m["audit.Resource Type"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const rt = String(row.resource_type || '-');
				return `<span class="text-xs px-2 py-0.5 rounded bg-surface border border-border text-text-muted">${rt}</span>`;
			}
		},
		{
			key: 'resource_id',
			label: m["audit.Resource ID"](),
			render: (row: Record<string, unknown>) =>
				`<span class="font-mono text-xs text-text-muted">${row.resource_id ? String(row.resource_id) : '-'}</span>`
		},
		{
			key: 'ip_address',
			label: m["audit.IP Address"](),
			render: (row: Record<string, unknown>) =>
				`<span class="font-mono text-xs text-text-muted">${row.ip_address ? String(row.ip_address) : '-'}</span>`
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
<div class="p-4 sm:p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<h2 class="text-2xl font-bold text-primary">{m["audit.Audit Logs"]()}</h2>
		<button
			onclick={fetchAuditLogs}
			class="px-4 py-2 border border-border text-text-muted rounded-lg
				hover:border-primary hover:text-primary transition-colors text-sm"
		>
			{m["dashboard.Refresh"]()}
		</button>
	</div>

	<!-- Filters -->
	<div class="bg-surface border border-border rounded-lg p-4 mb-4">
		<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-3">
			<!-- User filter -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["audit.User"]()}</label>
				<select
					bind:value={filterUser}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				>
					<option value="">{m["audit.All Users"]()}</option>
					{#each users as u}
						<option value={String(u.id)}>{u.username}</option>
					{/each}
				</select>
			</div>

			<!-- Action filter -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["audit.Action"]()}</label>
				<select
					bind:value={filterAction}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				>
					<option value="">{m["audit.All Actions"]()}</option>
					{#each commonActions as a}
						<option value={a}>{a}</option>
					{/each}
				</select>
			</div>

			<!-- Resource Type filter -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["audit.Resource Type"]()}</label>
				<select
					bind:value={filterResourceType}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				>
					<option value="">{m["audit.All Types"]()}</option>
					{#each resourceTypes as rt}
						<option value={rt}>{rt}</option>
					{/each}
				</select>
			</div>

			<!-- Date From -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["audit.Date From"]()}</label>
				<input
					type="date"
					bind:value={filterDateFrom}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				/>
			</div>

			<!-- Date To -->
			<div>
				<label class="block text-xs text-text-muted mb-1">{m["audit.Date To"]()}</label>
				<input
					type="date"
					bind:value={filterDateTo}
					class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
						focus:border-primary focus:outline-none"
				/>
			</div>

			<!-- Buttons -->
			<div class="flex items-end gap-2">
				<button
					onclick={applyFilters}
					class="flex-1 px-4 py-2 bg-primary text-text-inverse font-semibold rounded-lg
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
	{:else if logs.length === 0}
		<EmptyState
			icon="📋"
			title={m["common.No Results"]()}
			description={m["audit.No Logs Desc"]()}
		/>
	{:else}
		<div class="bg-surface border border-border rounded-lg p-4">
			<DataTable
				{columns}
				rows={logs as unknown as Record<string, unknown>[]}
				searchPlaceholder="{m["common.Search"]()}..."
				searchableKeys={['username', 'action', 'resource_type', 'ip_address']}
				emptyTitle={m["common.No Results"]()}
			/>

			<div class="mt-4">
				<Pagination {total} {limit} {offset} onPageChange={handlePageChange} />
			</div>
		</div>
	{/if}
</div>
{/if}
