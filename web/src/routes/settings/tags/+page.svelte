<script lang="ts">
	/**
	 * Tag dictionary management (#665/#668): built-ins (protected, editable
	 * label/color) + custom tags (full CRUD). Admin-only surface — the page
	 * hides itself for non-admins (the API enforces it too).
	 */
	import { onMount } from 'svelte';
	import { m } from '$lib/i18n-paraglide';
	import { auth } from '$lib/stores/auth';
	import { addToast } from '$lib/stores/toast';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import { listTags, createTag, updateTag, deleteTag, tagDisplayName, type Tag } from '$lib/api/archiveTags';

	let tags = $state<Tag[]>([]);
	let loading = $state(true);
	let error = $state('');

	let createOpen = $state(false);
	let editTarget = $state<Tag | null>(null);
	let deleteTarget = $state<Tag | null>(null);
	let busy = $state(false);

	let formKey = $state('');
	let formName = $state('');
	let formColor = $state('#2563eb');
	let formDesc = $state('');

	// Admin gate: derived from the auth store ($auth auto-subscribes).
	let isAdmin = $derived(($auth.user?.role ?? '') === 'admin');

	async function load() {
		loading = true;
		error = '';
		try {
			const resp = await listTags();
			tags = resp.tags ?? [];
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	function openCreate() {
		formKey = '';
		formName = '';
		formColor = '#2563eb';
		formDesc = '';
		createOpen = true;
	}

	function openEdit(tag: Tag) {
		editTarget = tag;
		formName = tag.name;
		formColor = tag.color || '#2563eb';
		formDesc = tag.description;
	}

	async function doCreate() {
		busy = true;
		try {
			await createTag({ key: formKey, name: formName, color: formColor, description: formDesc });
			addToast(m['tags.Created'](), 'success');
			createOpen = false;
			await load();
		} catch (e) {
			addToast(e instanceof Error ? e.message : String(e), 'error');
		} finally {
			busy = false;
		}
	}

	async function doEdit() {
		if (!editTarget) return;
		busy = true;
		try {
			await updateTag(editTarget.id, { name: formName, color: formColor, description: formDesc });
			addToast(m['tags.Updated'](), 'success');
			editTarget = null;
			await load();
		} catch (e) {
			addToast(e instanceof Error ? e.message : String(e), 'error');
		} finally {
			busy = false;
		}
	}

	async function doDelete() {
		if (!deleteTarget) return;
		busy = true;
		try {
			await deleteTag(deleteTarget.id);
			addToast(m['tags.Deleted'](), 'success');
			deleteTarget = null;
			await load();
		} catch (e) {
			addToast(e instanceof Error ? e.message : String(e), 'error');
		} finally {
			busy = false;
		}
	}

	onMount(() => {
		load();
	});
</script>

<div class="p-4 sm:p-6">
	<div class="mb-6 flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
		<div>
			<h1 class="text-xl font-semibold">{m['tags.Title']()}</h1>
			<p class="text-sm text-muted">{m['tags.Subtitle']()}</p>
		</div>
		{#if isAdmin}
			<button
				class="rounded-lg bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90"
				onclick={openCreate}
			>
				{m['tags.New']()}
			</button>
		{/if}
	</div>

	{#if error}
		<div class="mb-4 rounded-lg border border-error/40 bg-error/10 px-4 py-3 text-sm text-error">{error}</div>
	{/if}

	{#if loading}
		<div class="space-y-2">
			{#each Array(4) as _}
				<div class="h-12 animate-pulse rounded-lg bg-muted/40"></div>
			{/each}
		</div>
	{:else if tags.length === 0}
		<EmptyState title={m['tags.Empty']()} />
	{:else}
		<div class="overflow-x-auto rounded-lg border border-border bg-card">
			<table class="w-full text-sm">
				<thead class="bg-muted/50 text-xs uppercase tracking-wide text-muted">
					<tr>
						<th class="px-3 py-2 text-left">{m['tags.Col Tag']()}</th>
						<th class="px-3 py-2 text-left">Key</th>
						<th class="px-3 py-2 text-left">{m['tags.Col Desc']()}</th>
						<th class="px-3 py-2 text-left">{m['tags.Col Kind']()}</th>
						{#if isAdmin}
							<th class="px-3 py-2 text-right">{m['archive.Actions']()}</th>
						{/if}
					</tr>
				</thead>
				<tbody class="divide-y divide-border">
					{#each tags as tag (tag.id)}
						<tr class="hover:bg-muted/20">
							<td class="px-3 py-2">
								<span
									class="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-xs font-medium"
									style="background: {tag.color || '#888888'}22; color: {tag.color || '#888888'}"
								>
									{tagDisplayName(tag)}
								</span>
							</td>
							<td class="px-3 py-2 font-mono text-xs">{tag.key}</td>
							<td class="px-3 py-2 text-xs text-muted">{tag.description || '-'}</td>
							<td class="px-3 py-2 text-xs">
								{tag.builtin === 1 ? m['tags.Builtin']() : m['tags.Custom']()}
							</td>
							{#if isAdmin}
								<td class="whitespace-nowrap px-3 py-2 text-right">
									<button
										class="rounded px-2 py-1 text-xs text-primary hover:bg-primary/10"
										onclick={() => openEdit(tag)}
									>
										{m['common.Edit']()}
									</button>
									{#if tag.builtin !== 1}
										<button
											class="rounded px-2 py-1 text-xs text-error hover:bg-error/10"
											onclick={() => (deleteTarget = tag)}
										>
											{m['common.Delete']()}
										</button>
									{/if}
								</td>
							{/if}
						</tr>
					{/each}
				</tbody>
			</table>
		</div>
	{/if}
</div>

{#if createOpen}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
		<div class="w-full max-w-md rounded-lg border border-border bg-card p-5">
			<h2 class="mb-4 text-lg font-semibold">{m['tags.New']()}</h2>
			<label class="mb-1 block text-xs text-muted">Key</label>
			<input
				class="mb-3 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm font-mono"
				placeholder="visitor"
				bind:value={formKey}
			/>
			<label class="mb-1 block text-xs text-muted">{m['tags.Col Tag']()}</label>
			<input
				class="mb-3 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
				bind:value={formName}
			/>
			<label class="mb-1 block text-xs text-muted">{m['tags.Color']()}</label>
			<input type="color" class="mb-3 h-9 w-full rounded-lg border border-border bg-background" bind:value={formColor} />
			<label class="mb-1 block text-xs text-muted">{m['tags.Col Desc']()}</label>
			<input
				class="mb-4 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
				bind:value={formDesc}
			/>
			<div class="flex justify-end gap-2">
				<button class="rounded-lg border border-border px-3 py-1.5 text-sm" onclick={() => (createOpen = false)}>
					{m['common.Cancel']()}
				</button>
				<button
					class="rounded-lg bg-primary px-3 py-1.5 text-sm text-primary-foreground"
					disabled={busy || !formKey}
					onclick={doCreate}
				>
					{m['common.Create']()}
				</button>
			</div>
		</div>
	</div>
{/if}

{#if editTarget}
	<div class="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
		<div class="w-full max-w-md rounded-lg border border-border bg-card p-5">
			<h2 class="mb-4 text-lg font-semibold">{m['common.Edit']()}: {editTarget.name}</h2>
			<label class="mb-1 block text-xs text-muted">{m['tags.Col Tag']()}</label>
			<input
				class="mb-3 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
				bind:value={formName}
			/>
			<label class="mb-1 block text-xs text-muted">{m['tags.Color']()}</label>
			<input type="color" class="mb-3 h-9 w-full rounded-lg border border-border bg-background" bind:value={formColor} />
			<label class="mb-1 block text-xs text-muted">{m['tags.Col Desc']()}</label>
			<input
				class="mb-4 w-full rounded-lg border border-border bg-background px-3 py-2 text-sm"
				bind:value={formDesc}
			/>
			<div class="flex justify-end gap-2">
				<button class="rounded-lg border border-border px-3 py-1.5 text-sm" onclick={() => (editTarget = null)}>
					{m['common.Cancel']()}
				</button>
				<button
					class="rounded-lg bg-primary px-3 py-1.5 text-sm text-primary-foreground"
					disabled={busy || !formName}
					onclick={doEdit}
				>
					{m['common.Save']()}
				</button>
			</div>
		</div>
	</div>
{/if}

<ConfirmDialog
	open={deleteTarget !== null}
	title={m['tags.Delete Title']()}
	message={deleteTarget ? m['tags.Delete Msg']({ name: deleteTarget.name }) : ''}
	confirmLabel={m['common.Delete']()}
	confirmVariant="danger"
	loading={busy}
	onConfirm={doDelete}
	onCancel={() => (deleteTarget = null)}
/>
