<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 MiBee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { addToast } from '$lib/stores/toast';
	import type {
		SNMPCredential,
		SNMPCredentialRequest,
		SNMPCredentialListResponse
	} from '$lib/types';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import { LoaderCircle, Plus, Pencil, Trash2, ArrowLeft } from '@lucide/svelte';

	let credentials = $state<SNMPCredential[]>([]);
	let loading = $state(true);
	let error = $state('');
	let disabled = $state(false); // server reports master_key missing on create/update attempt

	// Modal state
	let modalOpen = $state(false);
	let editing = $state<SNMPCredential | null>(null);
	let saving = $state(false);

	// Form fields (kept flat for simple bind:value wiring)
	let formName = $state('');
	let formLevel = $state<SNMPCredential['security_level']>('v1v2c');
	let formCommunity = $state('');
	let formUsername = $state('');
	let formAuthProtocol = $state('');
	let formAuthPassphrase = $state('');
	let formPrivProtocol = $state('');
	let formPrivPassphrase = $state('');
	let formNotes = $state('');

	// Delete confirmation
	let deleteDialogOpen = $state(false);
	let deleteTarget = $state<SNMPCredential | null>(null);

	const authProtocols = ['MD5', 'SHA', 'SHA224', 'SHA256', 'SHA384', 'SHA512'];
	const privProtocols = ['DES', 'AES', 'AES192', 'AES256', 'AES192C', 'AES256C'];

	const isV3 = $derived(formLevel !== 'v1v2c');
	const needsAuth = $derived(formLevel === 'authNoPriv' || formLevel === 'authPriv');
	const needsPriv = $derived(formLevel === 'authPriv');

	onMount(loadCredentials);

	async function loadCredentials() {
		loading = true;
		error = '';
		try {
			const res = await api.get<SNMPCredentialListResponse>('/snmp-credentials');
			credentials = res.credentials;
		} catch (e) {
			error = getErrorMessage(e);
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		editing = null;
		formName = '';
		formLevel = 'v1v2c';
		formCommunity = 'public';
		formUsername = '';
		formAuthProtocol = '';
		formAuthPassphrase = '';
		formPrivProtocol = '';
		formPrivPassphrase = '';
		formNotes = '';
		modalOpen = true;
	}

	function openEdit(c: SNMPCredential) {
		editing = c;
		formName = c.name;
		formLevel = c.security_level;
		formCommunity = c.community ?? '';
		formUsername = c.username ?? '';
		formAuthProtocol = c.auth_protocol ?? '';
		formAuthPassphrase = ''; // never prefill — server keeps "leave unchanged" on blank
		formPrivProtocol = c.priv_protocol ?? '';
		formPrivPassphrase = '';
		formNotes = c.notes ?? '';
		modalOpen = true;
	}

	function validateForm(): string | null {
		if (!formName.trim()) return m['snmpCredentials.Name Required']();
		if (formLevel === 'v1v2c') {
			if (!formCommunity.trim()) return m['snmpCredentials.Community Required']();
		} else {
			// v3 levels
			if (!formUsername.trim()) return m['snmpCredentials.Username Required']();
			if (needsAuth && !formAuthProtocol) return m['snmpCredentials.Auth Protocol Required']();
			if (needsPriv && !formPrivProtocol) return m['snmpCredentials.Priv Protocol Required']();
			// CREATE requires passphrases; UPDATE allows blank (leave-unchanged)
			if (!editing) {
				if (needsAuth && !formAuthPassphrase) return m['snmpCredentials.Auth Protocol Required']();
				if (needsPriv && !formPrivPassphrase) return m['snmpCredentials.Priv Protocol Required']();
			}
		}
		return null;
	}

	async function save() {
		const verr = validateForm();
		if (verr) {
			addToast('error', verr);
			return;
		}
		saving = true;
		disabled = false;
		const body: SNMPCredentialRequest = {
			name: formName.trim(),
			security_level: formLevel,
			notes: formNotes.trim()
		};
		if (formLevel === 'v1v2c') {
			body.community = formCommunity.trim();
		} else {
			body.username = formUsername.trim();
			if (needsAuth) {
				body.auth_protocol = formAuthProtocol;
				if (formAuthPassphrase) body.auth_passphrase = formAuthPassphrase;
			}
			if (needsPriv) {
				body.priv_protocol = formPrivProtocol;
				if (formPrivPassphrase) body.priv_passphrase = formPrivPassphrase;
			}
		}
		try {
			if (editing) {
				await api.put(`/snmp-credentials/${editing.id}`, body);
				addToast('success', m['snmpCredentials.Updated']());
			} else {
				await api.post('/snmp-credentials', body);
				addToast('success', m['snmpCredentials.Created']());
			}
			modalOpen = false;
			await loadCredentials();
		} catch (e) {
			// 503 = master_key not configured server-side
			const msg = getErrorMessage(e);
			if (msg.includes('disabled') || msg.includes('master_key')) {
				disabled = true;
			}
			addToast('error', msg);
		} finally {
			saving = false;
		}
	}

	function confirmDelete(c: SNMPCredential) {
		deleteTarget = c;
		deleteDialogOpen = true;
	}

	async function doDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/snmp-credentials/${deleteTarget.id}`);
			addToast('success', m['snmpCredentials.Deleted']());
			await loadCredentials();
		} catch (e) {
			addToast('error', getErrorMessage(e));
		} finally {
			deleteDialogOpen = false;
			deleteTarget = null;
		}
	}

	function levelLabel(level: string): string {
		// Direct switch (not dynamic m[key]) — paraglide's typed message index
		// can't resolve a computed key, so we enumerate the four levels.
		switch (level) {
			case 'v1v2c':
				return m['snmpCredentials.v1v2c']();
			case 'noAuthNoPriv':
				return m['snmpCredentials.noAuthNoPriv']();
			case 'authNoPriv':
				return m['snmpCredentials.authNoPriv']();
			case 'authPriv':
				return m['snmpCredentials.authPriv']();
			default:
				return level;
		}
	}
</script>

<svelte:head>
	<title>{m['snmpCredentials.Title']()} · MiBee Steward</title>
</svelte:head>

{#if loading}
	<PageSkeleton type="table" />
{:else}
	<div class="p-6 max-w-6xl mx-auto">
		<a href="/settings" class="inline-flex items-center gap-2 text-sm text-text-muted hover:text-text mb-4">
			<ArrowLeft class="w-4 h-4" />
			{m['navigation.Settings']()}
		</a>

		<div class="flex items-center justify-between mb-6">
			<div>
				<h1 class="text-2xl font-bold text-text">{m['snmpCredentials.Title']()}</h1>
				<p class="text-sm text-text-muted mt-1">{m['snmpCredentials.Description']()}</p>
			</div>
			<button
				type="button"
				onclick={openCreate}
				class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-hover transition-colors"
			>
				<Plus class="w-4 h-4" />
				{m['snmpCredentials.Create']()}
			</button>
		</div>

		{#if disabled}
			<div class="mb-4 p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/30 text-sm text-yellow-200">
				{m['snmpCredentials.Disabled']()}
			</div>
		{/if}

		{#if error}
			<div class="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-sm text-red-200">
				{error}
			</div>
		{/if}

		{#if credentials.length === 0}
			<EmptyState
				title={m['snmpCredentials.No Credentials']()}
				description={m['snmpCredentials.No Credentials Desc']()}
			/>
		{:else}
			<div class="bg-surface border border-border rounded-xl overflow-hidden">
				<table class="w-full text-sm">
					<thead class="bg-surface-hover text-text-muted text-left">
						<tr>
							<th class="px-4 py-3 font-medium">{m['snmpCredentials.Name']()}</th>
							<th class="px-4 py-3 font-medium">{m['snmpCredentials.Security Level']()}</th>
							<th class="px-4 py-3 font-medium">{m['snmpCredentials.Username']()}</th>
							<th class="px-4 py-3 font-medium">{m['snmpCredentials.Auth Protocol']()}</th>
							<th class="px-4 py-3 font-medium">{m['snmpCredentials.Priv Protocol']()}</th>
							<th class="px-4 py-3 font-medium text-right">{m['audit.Action']()}</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-border">
						{#each credentials as c (c.id)}
							<tr class="hover:bg-surface-hover/50">
								<td class="px-4 py-3 text-text font-medium">{c.name}</td>
								<td class="px-4 py-3">
									<span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-primary/10 text-primary">
										{levelLabel(c.security_level)}
									</span>
								</td>
								<td class="px-4 py-3 text-text-muted">{c.username || c.community || '—'}</td>
								<td class="px-4 py-3 text-text-muted">
									{#if c.has_auth}<span class="text-green-400">✓</span> {c.auth_protocol}{:else}—{/if}
								</td>
								<td class="px-4 py-3 text-text-muted">
									{#if c.has_priv}<span class="text-green-400">✓</span> {c.priv_protocol}{:else}—{/if}
								</td>
								<td class="px-4 py-3 text-right">
									<button
										type="button"
										onclick={() => openEdit(c)}
										class="p-1.5 text-text-muted hover:text-primary rounded"
										title={m['snmpCredentials.Edit']()}
									>
										<Pencil class="w-4 h-4" />
									</button>
									<button
										type="button"
										onclick={() => confirmDelete(c)}
										class="p-1.5 text-text-muted hover:text-red-400 rounded ml-1"
										title={m['snmpCredentials.Delete']()}
									>
										<Trash2 class="w-4 h-4" />
									</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		{/if}
	</div>
{/if}

<Modal bind:open={modalOpen} title={editing ? m['snmpCredentials.Edit']() : m['snmpCredentials.Create']()}>
	<form onsubmit={(e) => { e.preventDefault(); save(); }} class="space-y-4">
		<!-- Name (all levels) -->
		<div>
			<label class="block text-sm text-text mb-1" for="cred-name">{m['snmpCredentials.Name']()}</label>
			<input
				id="cred-name"
				type="text"
				bind:value={formName}
				placeholder="core-switch-v3"
				class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text"
			/>
		</div>

		<!-- Security level -->
		<div>
			<label class="block text-sm text-text mb-1" for="cred-level">{m['snmpCredentials.Security Level']()}</label>
			<select
				id="cred-level"
				bind:value={formLevel}
				class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text"
			>
				<option value="v1v2c">{m['snmpCredentials.v1v2c']()}</option>
				<option value="noAuthNoPriv">{m['snmpCredentials.noAuthNoPriv']()}</option>
				<option value="authNoPriv">{m['snmpCredentials.authNoPriv']()}</option>
				<option value="authPriv">{m['snmpCredentials.authPriv']()}</option>
			</select>
		</div>

		<!-- v1/v2c: community -->
		{#if !isV3}
			<div>
				<label class="block text-sm text-text mb-1" for="cred-community">{m['snmpCredentials.Community']()}</label>
				<input
					id="cred-community"
					type="text"
					bind:value={formCommunity}
					placeholder="public"
					class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text font-mono"
				/>
			</div>
		{/if}

		<!-- v3 fields -->
		{#if isV3}
			<div>
				<label class="block text-sm text-text mb-1" for="cred-user">{m['snmpCredentials.Username']()}</label>
				<input
					id="cred-user"
					type="text"
					bind:value={formUsername}
					placeholder="snmpadmin"
					class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text"
				/>
			</div>
		{/if}

		{#if needsAuth}
			<div>
				<label class="block text-sm text-text mb-1" for="cred-auth-proto">{m['snmpCredentials.Auth Protocol']()}</label>
				<select
					id="cred-auth-proto"
					bind:value={formAuthProtocol}
					class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text"
				>
					<option value="">—</option>
					{#each authProtocols as p}
						<option value={p}>{p}</option>
					{/each}
				</select>
			</div>
			<div>
				<label class="block text-sm text-text mb-1" for="cred-auth-pass">{m['snmpCredentials.Auth Passphrase']()}</label>
				<input
					id="cred-auth-pass"
					type="password"
					bind:value={formAuthPassphrase}
					placeholder={editing ? m['snmpCredentials.Passphrase Unchanged Hint']() : ''}
					class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text font-mono"
					autocomplete="new-password"
				/>
			</div>
		{/if}

		{#if needsPriv}
			<div>
				<label class="block text-sm text-text mb-1" for="cred-priv-proto">{m['snmpCredentials.Priv Protocol']()}</label>
				<select
					id="cred-priv-proto"
					bind:value={formPrivProtocol}
					class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text"
				>
					<option value="">—</option>
					{#each privProtocols as p}
						<option value={p}>{p}</option>
					{/each}
				</select>
			</div>
			<div>
				<label class="block text-sm text-text mb-1" for="cred-priv-pass">{m['snmpCredentials.Priv Passphrase']()}</label>
				<input
					id="cred-priv-pass"
					type="password"
					bind:value={formPrivPassphrase}
					placeholder={editing ? m['snmpCredentials.Passphrase Unchanged Hint']() : ''}
					class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text font-mono"
					autocomplete="new-password"
				/>
			</div>
		{/if}

		<!-- Notes (all levels) -->
		<div>
			<label class="block text-sm text-text mb-1" for="cred-notes">{m['snmpCredentials.Notes']()}</label>
			<textarea
				id="cred-notes"
				bind:value={formNotes}
				rows="2"
				placeholder=""
				class="w-full px-3 py-2 bg-surface-hover border border-border rounded-lg text-text"
			></textarea>
		</div>

		<div class="flex justify-end gap-2 pt-2">
			<button
				type="button"
				onclick={() => (modalOpen = false)}
				class="px-4 py-2 text-text-muted hover:text-text rounded-lg"
			>
				{m['snmpCredentials.Cancel']()}
			</button>
			<button
				type="submit"
				disabled={saving}
				class="inline-flex items-center gap-2 px-4 py-2 bg-primary text-white rounded-lg hover:bg-primary-hover disabled:opacity-50 transition-colors"
			>
				{#if saving}<LoaderCircle class="w-4 h-4 animate-spin" />{/if}
				{m['snmpCredentials.Save']()}
			</button>
		</div>
	</form>
</Modal>

<ConfirmDialog
	bind:open={deleteDialogOpen}
	title={m['snmpCredentials.Delete']()}
	message={m['snmpCredentials.Delete Confirm']()}
	confirmLabel={m['snmpCredentials.Delete']()}
	confirmVariant="danger"
	onConfirm={doDelete}
/>
