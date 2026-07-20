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
	import { userSchema, validateField, validateForm } from '$lib/utils/validation';

	import Modal from '$lib/components/Modal.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import { Users as UsersIcon } from '@lucide/svelte';

	interface User {
		id: number;
		username: string;
		email: string;
		role: string;
		created_at: string;
	}

	let users = $state<User[]>([]);
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');

	let offset = $state(0);
	const limit = 20;

	// Auth is consumed directly via the $auth store (auto-subscribed in .svelte).

	// Modal state
	let createModalOpen = $state(false);
	let deleteDialogOpen = $state(false);
	let deleteTarget = $state<User | null>(null);
	let formLoading = $state(false);

	// Reset password state
	let resetTarget = $state<User | null>(null);
	let resetDialogOpen = $state(false);
	let resetPassword = $state('');
	let resetConfirmPassword = $state('');
	let resetLoading = $state(false);

	// Form fields
	let formUsername = $state('');
	let formEmail = $state('');
	let formPassword = $state('');
	let formRole = $state('user');

	// Validation errors (field-level, shown on blur)
	let fieldErrors = $state<Record<string, string>>({});
	// Track which fields have been touched (blurred)
	let touched = $state<Record<string, boolean>>({});

	onMount(() => {
		fetchUsers();
	});

	async function fetchUsers() {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			params.set('limit', String(limit));
			params.set('offset', String(offset));
			const res = await api.get<{ users: User[]; total: number }>(`/users?${params}`);
			users = res.users || [];
			total = res.total || 0;
		} catch (err: unknown) {
			// Inline banner only on initial load — a parallel toast here was
			// noisy double-notification for a single failure.
			error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	function resetForm() {
		formUsername = '';
		formEmail = '';
		formPassword = '';
		formRole = 'user';
		fieldErrors = {};
		touched = {};
	}

	function openCreate() {
		resetForm();
		createModalOpen = true;
	}

	function handleBlur(field: string, value: string) {
		touched[field] = true;
		const result = validateField(userSchema, field, value);
		if (!result.valid && result.error) {
			fieldErrors[field] = result.error;
		} else {
			delete fieldErrors[field];
		}
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		formLoading = true;

		const formData = {
			username: formUsername,
			email: formEmail,
			password: formPassword,
			role: formRole
		};

		// Full form validation
		const validation = validateForm(userSchema, formData);
		if (!validation.valid) {
			fieldErrors = validation.errors;
			// Mark all fields as touched so errors show
			touched = { username: true, email: true, password: true, role: true };
			formLoading = false;
			return;
		}

		try {
			await api.post('/auth/register', formData);
			createModalOpen = false;
			resetForm();
			addToast('success', m["common.Success"]());
			fetchUsers();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			formLoading = false;
		}
	}

	function openDelete(user: User) {
		deleteTarget = user;
		deleteDialogOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/users/${deleteTarget.id}`);
			deleteTarget = null;
			addToast('success', m["common.Success"]());
			fetchUsers();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	function openReset(user: User) {
		resetTarget = user;
		resetPassword = '';
		resetConfirmPassword = '';
		resetDialogOpen = true;
	}

	async function confirmResetPassword() {
		if (!resetTarget) return;
		if (!resetPassword) {
			addToast('error', m["users.Password Required"]());
			return;
		}
		if (resetPassword !== resetConfirmPassword) {
			addToast('error', m["users.Passwords Do Not Match"]());
			return;
		}
		resetLoading = true;
		try {
			await api.post(`/users/${resetTarget.id}/reset-password`, { new_password: resetPassword });
			resetTarget = null;
			resetPassword = '';
			resetConfirmPassword = '';
			resetDialogOpen = false;
			addToast('success', m["users.Password Reset Success"]());
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			resetLoading = false;
		}
	}

	function formatTime(iso: string): string {
		if (!iso) return '-';
		try {
			return new Date(iso).toLocaleString();
		} catch {
			return iso;
		}
	}

	function handlePageChange(newOffset: number) {
		offset = newOffset;
		fetchUsers();
	}

	// Admin-only guard
	let isAdmin = $derived($auth.user?.role === 'admin');

	// DataTable columns
	const columns = $derived([
		{
			key: 'username',
			label: m["users.Username"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="font-medium text-text">${String(row.username)}</span>`
		},
		{
			key: 'email',
			label: m["users.Email"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted">${row.email ? String(row.email) : '-'}</span>`
		},
		{
			key: 'role',
			label: m["users.Role"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const role = String(row.role);
				if (role === 'admin') {
					return `<span class="text-xs px-2 py-0.5 rounded font-mono bg-accent/10 text-accent">${role}</span>`;
				}
				return `<span class="text-xs px-2 py-0.5 rounded font-mono bg-surface text-text-muted border border-border">${role}</span>`;
			}
		},
		{
			key: 'created_at',
			label: m["users.Created At"](),
			sortable: true,
			render: (row: Record<string, unknown>) =>
				`<span class="text-text-muted">${formatTime(String(row.created_at))}</span>`
		},
		{
			key: 'actions',
			label: m["common.Actions"](),
			render: (row: Record<string, unknown>) => {
				const userId = row.id;
				return `<div class="flex items-center gap-2">
					<button data-reset-id="${userId}" class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors">${m["users.Reset Password"]()}</button>
					<button data-delete-id="${userId}" class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors">${m["common.Delete"]()}</button>
				</div>`;
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
		<h2 class="text-2xl font-bold text-primary">{m["users.User List"]()}</h2>
		<button
			onclick={openCreate}
			class="btn btn-primary"
		>
			+ {m["users.Add User"]()}
		</button>
	</div>

	<!-- Error -->
	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{error}
		</div>
	{/if}

	<!-- Loading skeleton -->
	{#if loading}
		<PageSkeleton type="table" />
	{:else if users.length === 0}
		<EmptyState
			icon={UsersIcon}
			title={m["common.No Results"]()}
			description={m["users.No Users Desc"]()}
			actionLabel={m["users.Add User"]()}
			onAction={openCreate}
		/>
	{:else}
		<!-- User table -->
		<div class="bg-surface border border-border rounded-lg p-4">
				<!-- Wrap DataTable + handle delete clicks -->
				<!-- svelte-ignore a11y_no_static_element_interactions -->
				<!-- svelte-ignore a11y_click_events_have_key_events -->
				<div onclick={(e) => {
					const target = e.target as HTMLElement;
					const deleteBtn = target.closest('[data-delete-id]') as HTMLElement | null;
					if (deleteBtn) {
						const id = Number(deleteBtn.dataset.deleteId);
						const user = users.find((u) => u.id === id);
						if (user) openDelete(user);
					}
					const resetBtn = target.closest('[data-reset-id]') as HTMLElement | null;
					if (resetBtn) {
						const id = Number(resetBtn.dataset.resetId);
						const user = users.find((u) => u.id === id);
						if (user) openReset(user);
					}
				}}>
					<DataTable
						{columns}
						rows={users as unknown as Record<string, unknown>[]}
						searchPlaceholder={m["common.Search"]() + '...'}
						searchableKeys={['username', 'email', 'role']}
						emptyTitle={m["common.No Results"]()}
					/>
				</div>

			<!-- Pagination -->
			<Pagination {total} {limit} {offset} onPageChange={handlePageChange} />
		</div>
	{/if}
</div>
{/if}

<!-- Create User Modal -->
<Modal bind:open={createModalOpen} title={m["users.Add User"]()} onClose={resetForm}>
	<form onsubmit={handleSubmit} class="space-y-4">
		<!-- Username -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["users.Username"]()} *</label>
			<input
				bind:value={formUsername}
				onblur={() => handleBlur('username', formUsername)}
				required
				class="input"
			/>
			{#if touched.username && fieldErrors.username}
				<p class="mt-1 text-xs text-error">{fieldErrors.username}</p>
			{/if}
		</div>

		<!-- Email -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["users.Email"]()}</label>
			<input
				type="email"
				bind:value={formEmail}
				onblur={() => handleBlur('email', formEmail)}
				class="input"
			/>
			{#if touched.email && fieldErrors.email}
				<p class="mt-1 text-xs text-error">{fieldErrors.email}</p>
			{/if}
		</div>

		<!-- Password -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["users.Password"]()} *</label>
			<input
				type="password"
				bind:value={formPassword}
				onblur={() => handleBlur('password', formPassword)}
				required
				class="input"
			/>
			{#if touched.password && fieldErrors.password}
				<p class="mt-1 text-xs text-error">{fieldErrors.password}</p>
			{/if}
		</div>

		<!-- Role -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["users.Role"]()}</label>
			<select
				bind:value={formRole}
				onchange={() => handleBlur('role', formRole)}
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none"
			>
				<option value="user">{m["users.User"]()}</option>
				<option value="admin">{m["users.Admin"]()}</option>
			</select>
		</div>

		<!-- Actions -->
		<div class="flex gap-3 pt-2">
			<LoadingButton type="submit" loading={formLoading} variant="primary" label={m["common.Save"]()} />
			<button
				type="button"
				onclick={() => { createModalOpen = false; resetForm(); }}
				class="btn btn-secondary"
			>
				{m["common.Cancel"]()}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete confirmation -->
<ConfirmDialog
	bind:open={deleteDialogOpen}
	title={m["users.Delete User"]()}
	message={deleteTarget ? `${m["common.Are you sure?"]()} "${deleteTarget.username}"` : ''}
	confirmLabel={m["common.Delete"]()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
	onCancel={() => { deleteTarget = null; }}
/>

<!-- Reset password Modal -->
<Modal bind:open={resetDialogOpen} title={m["users.Reset Password"]()}>
	<form onsubmit={(e) => { e.preventDefault(); confirmResetPassword(); }} class="space-y-4">
		<!-- New password -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["users.New Password"]()} *</label>
			<input
				type="password"
				bind:value={resetPassword}
				required
				class="input"
			/>
		</div>

		<!-- Confirm password -->
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["users.Confirm Password"]()} *</label>
			<input
				type="password"
				bind:value={resetConfirmPassword}
				required
				class="input"
			/>
			{#if resetConfirmPassword && resetPassword !== resetConfirmPassword}
				<p class="mt-1 text-xs text-error">{m["users.Passwords Do Not Match"]()}</p>
			{/if}
		</div>

		<!-- Actions -->
		<div class="flex gap-3 pt-2">
			<LoadingButton type="submit" loading={resetLoading} variant="primary" label={m["users.Reset Password"]()} />
			<button
				type="button"
				onclick={() => { resetDialogOpen = false; resetTarget = null; }}
				class="btn btn-secondary"
			>
				{m["common.Cancel"]()}
			</button>
		</div>
	</form>
</Modal>
