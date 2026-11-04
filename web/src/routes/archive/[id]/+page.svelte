<script lang="ts">
	/**
	 * Device dossier (#666/#667): the merged lifetime timeline of one archived
	 * device — archive lifecycle events, changes, config versions, TLS certs,
	 * documents and sightings — plus the manual archive actions.
	 */
	import { onMount } from 'svelte';
	import { m } from '$lib/i18n-paraglide';
	import { page as pageStore } from '$app/state';
	import { addToast } from '$lib/stores/toast';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import {
		getDossier,
		restoreDevice,
		putArchiveSettings,
		type DossierEntry
	} from '$lib/api/archiveTags';

	let entries = $state<DossierEntry[]>([]);
	let loading = $state(true);
	let error = $state('');
	let restoreOpen = $state(false);
	let actionBusy = $state(false);

	const id = $derived(Number(pageStore.params.id));

	async function load() {
		loading = true;
		error = '';
		try {
			const resp = await getDossier(id);
			entries = resp.entries ?? [];
		} catch (e) {
			error = e instanceof Error ? e.message : String(e);
		} finally {
			loading = false;
		}
	}

	function fmt(ts: string): string {
		const d = new Date(ts);
		return Number.isNaN(d.getTime()) ? '-' : d.toLocaleString();
	}

	function kindLabel(kind: DossierEntry['kind']): string {
		switch (kind) {
			case 'archive_event':
				return m['archive.Kind Archive Event']();
			case 'change':
				return m['archive.Kind Change']();
			case 'config':
				return m['archive.Kind Config']();
			case 'cert':
				return m['archive.Kind Cert']();
			case 'document':
				return m['archive.Kind Document']();
			case 'sighting':
				return m['archive.Kind Sighting']();
		}
	}

	function kindClass(kind: DossierEntry['kind']): string {
		switch (kind) {
			case 'archive_event':
				return 'bg-primary/15 text-primary';
			case 'change':
				return 'bg-secondary/20 text-secondary';
			case 'config':
				return 'bg-muted text-foreground';
			case 'cert':
				return 'bg-warning/20 text-warning';
			case 'document':
				return 'bg-success/15 text-success';
			case 'sighting':
				return 'bg-muted text-muted';
		}
	}

	async function doRestore() {
		actionBusy = true;
		try {
			await restoreDevice(id, true);
			addToast(m['archive.Restored Generic'](), 'success');
			restoreOpen = false;
			await load();
		} catch (e) {
			addToast(e instanceof Error ? e.message : String(e), 'error');
		} finally {
			actionBusy = false;
		}
	}

	onMount(load);
</script>

<div class="p-4 sm:p-6">
	<div class="mb-6 flex flex-col items-start justify-between gap-3 sm:flex-row sm:items-center">
		<div>
			<h1 class="text-xl font-semibold">{m['archive.Dossier Title']()}</h1>
			<p class="text-sm text-muted">{m['archive.Dossier Subtitle']()}</p>
		</div>
		<div class="flex gap-2">
			<button
				class="rounded-lg bg-primary px-3 py-1.5 text-sm text-primary-foreground hover:opacity-90"
				disabled={actionBusy}
				onclick={() => (restoreOpen = true)}
			>
				{m['archive.Restore Action']()}
			</button>
			<a
				href="/devices/{id}"
				class="rounded-lg border border-border px-3 py-1.5 text-sm hover:bg-muted/20"
			>
				{m['archive.Open Device']()}
			</a>
			<a href="/archive" class="rounded-lg border border-border px-3 py-1.5 text-sm hover:bg-muted/20">
				{m['archive.Back']()}
			</a>
		</div>
	</div>

	{#if error}
		<div class="mb-4 rounded-lg border border-error/40 bg-error/10 px-4 py-3 text-sm text-error">{error}</div>
	{/if}

	{#if loading}
		<div class="space-y-2">
			{#each Array(8) as _}
				<div class="h-14 animate-pulse rounded-lg bg-muted/40"></div>
			{/each}
		</div>
	{:else if entries.length === 0}
		<EmptyState title={m['archive.Dossier Empty']()} />
	{:else}
		<ol class="relative space-y-3 border-l border-border pl-5">
			{#each entries as e (e.kind + e.occurred_at + e.summary)}
				<li class="relative">
					<span
						class="absolute -left-[27px] top-1.5 h-3 w-3 rounded-full border-2 border-card {e.kind ===
						'archive_event'
							? 'bg-primary'
							: e.kind === 'change'
								? 'bg-secondary'
								: 'bg-muted'}"
					></span>
					<div class="rounded-lg border border-border bg-card px-4 py-3">
						<div class="flex flex-wrap items-center gap-2">
							<span class="rounded-full px-2 py-0.5 text-xs {kindClass(e.kind)}">{kindLabel(e.kind)}</span>
							<span class="text-sm font-medium">{e.summary}</span>
							<span class="ml-auto text-xs text-muted">{fmt(e.occurred_at)}</span>
						</div>
					</div>
				</li>
			{/each}
		</ol>
	{/if}
</div>

<ConfirmDialog
	open={restoreOpen}
	title={m['archive.Restore Title']()}
	message={m['archive.Restore Force Msg Generic']()}
	confirmLabel={m['archive.Restore Action']()}
	loading={actionBusy}
	onConfirm={doRestore}
	onCancel={() => (restoreOpen = false)}
/>
