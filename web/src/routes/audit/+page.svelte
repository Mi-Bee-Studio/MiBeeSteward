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
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import DataTable from '$lib/components/DataTable.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import type { AuditLog } from '$lib/types';

	let logs = $state<AuditLog[]>([]);
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');
	let offset = $state(0);
	const limit = 50;

	// Expanded row (details viewer).
	let expandedId = $state<number | null>(null);

	// Auth is consumed directly via the $auth store (auto-subscribed in .svelte).

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
		fetchAuditLogs();
		fetchUsers();
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

	// Pretty-print the details JSON (audit events record structured detail
	// payloads — e.g. file uploads, link operations).
	function formatDetails(raw: string): string {
		if (!raw) return '';
		try {
			return JSON.stringify(JSON.parse(raw), null, 2);
		} catch {
			return raw;
		}
	}

	async function exportAuditLogs(format: 'csv' | 'json') {
		try {
			const params = new URLSearchParams();
			params.set('format', format);
			if (filterUser) params.set('user_id', filterUser);
			if (filterAction) params.set('action', filterAction);
			if (filterResourceType) params.set('resource_type', filterResourceType);
			if (filterDateFrom) params.set('date_from', filterDateFrom);
			if (filterDateTo) params.set('date_to', filterDateTo);
			const blob = await api.download(`/audit-logs/export?${params}`);
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `audit-logs.${format}`;
			document.body.appendChild(a);
			a.click();
			a.remove();
			URL.revokeObjectURL(url);
			addToast('success', m['devices.Export']?.() ?? 'Exported');
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	let isAdmin = $derived($auth.user?.role === 'admin');

	const columns = $derived([
		{
			key: '_expand',
			label: '',
			sortable: false,
			render: (row: Record<string, unknown>) => {
				const id = row.id as number;
				const isOpen = expandedId === id;
				return `<button data-action="expand" data-id="${id}" class="p-1 rounded hover:bg-primary/10 transition-colors text-text-muted">`
					+ `<svg class="w-3.5 h-3.5 transition-transform duration-200 ${isOpen ? 'rotate-90' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">`
					+ `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg></button>`;
			}
		},
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
		},
		{
			key: 'details',
			label: m['audit.Details']?.() ?? 'Details',
			render: (row: Record<string, unknown>) => {
				const d = row.details ? String(row.details) : '';
				if (!d) return `<span class="text-xs text-text-muted">-</span>`;
				const preview = d.slice(0, 60);
				return `<span class="font-mono text-xs text-text-muted">${escapeHtmlSimple(preview)}${d.length > 60 ? '…' : ''}</span>`;
			}
		}
	]);

	function escapeHtmlSimple(s: string): string {
		return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
	}
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
<div class="p-4 sm:p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<h2 class="text-2xl font-bold text-primary">{m["audit.Audit Logs"]()}</h2>
		<div class="flex items-center gap-2">
			<div class="relative group">
				<button class="px-4 py-2 border border-border text-text-muted rounded-lg
					hover:border-primary hover:text-primary transition-colors text-sm">
					{m['devices.Export']?.() ?? 'Export'}
				</button>
				<div class="absolute right-0 top-full mt-1 bg-surface border border-border rounded-lg
					opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all z-10 min-w-[120px]"
					style="box-shadow: var(--shadow-md);">
					<button onclick={() => exportAuditLogs('csv')}
						class="w-full text-left px-4 py-2 text-sm text-text hover:bg-surface-2 rounded-t-lg">
						{m['devices.Export CSV']?.() ?? 'Export CSV'}
					</button>
					<button onclick={() => exportAuditLogs('json')}
						class="w-full text-left px-4 py-2 text-sm text-text hover:bg-surface-2 rounded-b-lg">
						{m['devices.Export JSON']?.() ?? 'Export JSON'}
					</button>
				</div>
			</div>
			<button
				onclick={fetchAuditLogs}
				class="px-4 py-2 border border-border text-text-muted rounded-lg
					hover:border-primary hover:text-primary transition-colors text-sm"
			>
				{m["dashboard.Refresh"]()}
			</button>
		</div>
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
				<div onclick={(e) => {
					const btn = (e.target as HTMLElement).closest('[data-action="expand"]') as HTMLElement | null;
					if (btn) {
						const id = Number(btn.dataset.id);
						expandedId = expandedId === id ? null : id;
					}
				}}>
				<DataTable
					{columns}
					rows={logs as unknown as Record<string, unknown>[]}
					searchPlaceholder="{m["common.Search"]()}..."
					searchableKeys={['username', 'action', 'resource_type', 'ip_address']}
					emptyTitle={m["common.No Results"]()}
					expandedRowId={expandedId ?? undefined}
				>
					{#snippet expandedContent(row)}
						{@const log = logs.find((l) => l.id === row.id)}
						<div class="border-t border-border bg-bg/40 px-6 py-4 space-y-3">
							{#if log?.user_agent}
								<div>
									<span class="text-[10px] text-text-muted uppercase tracking-wide">User Agent</span>
									<p class="font-mono text-xs text-text mt-0.5 break-all">{log.user_agent}</p>
								</div>
							{/if}
							{#if log?.details}
								<div>
									<span class="text-[10px] text-text-muted uppercase tracking-wide">Details</span>
									<pre class="text-xs text-text bg-bg/50 border border-border rounded p-2 mt-1 overflow-x-auto whitespace-pre-wrap break-all max-h-48">{formatDetails(log.details)}</pre>
								</div>
							{:else}
								<p class="text-xs text-text-muted italic">{m['audit.No Details']?.() ?? 'No detail payload.'}</p>
							{/if}
						</div>
					{/snippet}
				</DataTable>
				</div>

			<div class="mt-4">
				<Pagination {total} {limit} {offset} onPageChange={handlePageChange} />
			</div>
		</div>
	{/if}
</div>
{/if}
