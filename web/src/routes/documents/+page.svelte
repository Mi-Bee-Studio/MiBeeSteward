<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { getErrorMessage } from '$lib/utils';
	import { addToast } from '$lib/stores/toast';
	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import { onMount } from 'svelte';

	interface Document {
		id: number;
		title: string;
		type: string;
		url: string;
		description: string;
		file_path: string;
		file_size: number;
		mime_type: string;
		created_at: string;
	}

	let documents = $state<Document[]>([]);
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');
	let offset = $state(0);
	const limit = 20;

	// URL form modal
	let urlModalOpen = $state(false);
	let formTitle = $state('');
	let formUrl = $state('');
	let formDescription = $state('');
	let formLoading = $state(false);
	let formError = $state('');
	let editingDocument = $state<Document | null>(null);

	// File upload modal
	let fileModalOpen = $state(false);
	let formFileTitle = $state('');
	let formFileDescription = $state('');
	let formFile = $state<File | null>(null);
	let uploading = $state(false);
	let uploadProgress = $state(0);

	// Delete confirmation
	let deleteOpen = $state(false);
	let deleteTarget = $state<Document | null>(null);
	let deleteMessage = $state('');

	// File preview modal
	let previewOpen = $state(false);
	let previewDoc = $state<Document | null>(null);

	onMount(fetchDocuments);

	async function fetchDocuments() {
		loading = true;
		error = '';
		try {
			const params = new URLSearchParams();
			params.set('limit', String(limit));
			params.set('offset', String(offset));
			const res = await api.get<{ documents: Document[]; total: number }>(`/documents?${params}`);
			documents = res.documents || [];
			total = res.total || 0;
		} catch (err: unknown) {
			error = getErrorMessage(err);
			addToast('error', error);
		} finally {
			loading = false;
		}
	}

	// --- URL form ---
	function openUrlCreate() {
		editingDocument = null;
		formTitle = '';
		formUrl = '';
		formDescription = '';
		formError = '';
		urlModalOpen = true;
	}

	function openEdit(doc: Document) {
		editingDocument = doc;
		if (doc.type === 'url') {
			formTitle = doc.title;
			formUrl = doc.url;
			formDescription = doc.description || '';
		} else {
			// file docs can edit metadata only, treat like url form
			formTitle = doc.title;
			formUrl = doc.url || '';
			formDescription = doc.description || '';
		}
		formError = '';
		urlModalOpen = true;
	}

	async function handleUrlSubmit(e: Event) {
		e.preventDefault();
		formLoading = true;
		formError = '';
		try {
			if (editingDocument) {
				await api.put(`/documents/${editingDocument.id}`, {
					title: formTitle,
					type: editingDocument.type,
					url: formUrl,
					description: formDescription
				});
				addToast('success', m["documents.Edit Document"]());
			} else {
				await api.post('/documents', {
					title: formTitle,
					type: 'url',
					url: formUrl,
					description: formDescription
				});
				addToast('success', m["documents.Create Document"]());
			}
			urlModalOpen = false;
			editingDocument = null;
			fetchDocuments();
		} catch (err: unknown) {
			formError = getErrorMessage(err);
			addToast('error', formError);
		} finally {
			formLoading = false;
		}
	}

	// --- File upload ---
	function openFileCreate() {
		editingDocument = null;
		formFileTitle = '';
		formFileDescription = '';
		formFile = null;
		formError = '';
		fileModalOpen = true;
	}

	async function handleFileSubmit(e: Event) {
		e.preventDefault();
		if (!formFile && !editingDocument) {
			formError = m["documents.no_file_selected"]();
			return;
		}
		formLoading = true;
		uploading = !editingDocument;
		uploadProgress = 0;
		formError = '';
		try {
			if (editingDocument) {
				await api.put(`/documents/${editingDocument.id}`, {
					title: formFileTitle || editingDocument.title,
					description: formFileDescription ?? editingDocument.description
				});
				addToast('success', m["documents.Edit Document"]());
			} else {
				const fd = new FormData();
				fd.append('file', formFile!);
				fd.append('title', formFileTitle);
				fd.append('description', formFileDescription);
				await api.upload('/documents/upload', fd, (percent) => {
					uploadProgress = percent;
				});
				addToast('success', m["documents.Upload"]());
			}
			fileModalOpen = false;
			editingDocument = null;
			fetchDocuments();
		} catch (err: unknown) {
			formError = getErrorMessage(err);
			addToast('error', formError);
		} finally {
			formLoading = false;
			uploading = false;
		}
	}

	// --- Delete ---
	function requestDelete(doc: Document) {
		deleteTarget = doc;
		deleteOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		const target = deleteTarget;
		try {
			await api.delete(`/documents/${target.id}`);
			addToast('success', m["documents.Delete Document"](), {
				callback: async () => {
					try {
						await api.post(`/documents/${target.id}/restore`, {});
						fetchDocuments();
					} catch {
						addToast('error', 'Restore failed');
					}
				},
				label: m["common.Undo"](),
				timeout: 10000
			});
			deleteOpen = false;
			deleteTarget = null;
			fetchDocuments();
		} catch (err: unknown) {
			const msg = getErrorMessage(err);
			addToast('error', msg);
		}
	}

	// --- File Preview ---
	function openPreview(doc: Document) {
		previewDoc = doc;
		previewOpen = true;
	}

	function isPreviewable(doc: Document): boolean {
		const mime = doc.mime_type?.toLowerCase() || '';
		const ext = doc.file_path?.split('.').pop()?.toLowerCase() || '';
		return mime.startsWith('image/') || mime === 'application/pdf'
			|| ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext)
			|| ext === 'pdf';
	}

	function isImage(doc: Document): boolean {
		const mime = doc.mime_type?.toLowerCase() || '';
		const ext = doc.file_path?.split('.').pop()?.toLowerCase() || '';
		return mime.startsWith('image/') || ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp'].includes(ext);
	}

	function isPdf(doc: Document): boolean {
		const mime = doc.mime_type?.toLowerCase() || '';
		const ext = doc.file_path?.split('.').pop()?.toLowerCase() || '';
		return mime === 'application/pdf' || ext === 'pdf';
	}

	function formatSize(bytes: number): string {
		if (bytes === 0) return '-';
		const units = ['B', 'KB', 'MB', 'GB'];
		let i = 0;
		let size = bytes;
		while (size >= 1024 && i < units.length - 1) { size /= 1024; i++; }
		return `${size.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
	}

	function handlePageChange(newOffset: number) {
		offset = newOffset;
		fetchDocuments();
	}

	// Delete message computed
	$effect(() => {
		if (deleteTarget) {
			deleteMessage = m['common.Are you sure?']() + " '" + (deleteTarget?.title ?? '') + "'";
		} else {
			deleteMessage = '';
		}
	});

	// DataTable column definitions
	const columns = $derived([
		{
			key: 'title',
			label: m["documents.Title"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const doc = row as unknown as Document;
				if (doc.type === 'url') {
					return `<a href="${doc.url}" target="_blank" rel="noopener" class="hover:text-primary transition-colors">${doc.title} ↗</a>`;
				}
				return doc.title;
			}
		},
		{
			key: 'type',
			label: m["documents.Type"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const doc = row as unknown as Document;
				const isUrl = doc.type === 'url';
				const label = isUrl ? 'URL' : m["documents.File"]();
				const cls = isUrl
					? 'text-accent'
					: 'text-primary';
				return `<span class="text-xs px-2 py-0.5 rounded-full ${isUrl ? 'bg-accent/10' : 'bg-primary/10'} ${cls}">${label}</span>`;
			}
		},
		{
			key: 'description',
			label: m["documents.Description"](),
			render: (row: Record<string, unknown>) => {
				const desc = (row as unknown as Document).description;
				return `<span class="text-text-muted">${desc || '-'}</span>`;
			}
		},
		{
			key: 'file_size',
			label: m["documents.File Size"](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const size = (row as unknown as Document).file_size;
				return `<span class="font-mono text-text-muted">${formatSize(size)}</span>`;
			}
		},
		{
			key: 'actions',
			label: m["common.Actions"](),
			render: (row: Record<string, unknown>) => {
				const doc = row as unknown as Document;
				let btns = '';
				// Preview button for previewable files
				if (doc.type !== 'url' && isPreviewable(doc)) {
					btns += `<button data-action="preview" data-id="${doc.id}" class="text-xs px-2 py-1 rounded text-success hover:bg-success/10 transition-colors">${m["documents.Preview"]()}</button>`;
				}
				btns += `<button data-action="edit" data-id="${doc.id}" class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10 transition-colors">${m["common.Edit"]()}</button>`;
				if (doc.type !== 'url' && doc.file_path) {
					btns += `<a href="/api/v1/documents/${doc.id}/download" class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors">${m["documents.Download"]()}</a>`;
				}
				btns += `<button data-action="delete" data-id="${doc.id}" class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors">${m["common.Delete"]()}</button>`;
				return `<div class="flex gap-2">${btns}</div>`;
			}
		}
	]);

	// Since DataTable uses @html, button clicks need event delegation
	function handleTableClick(e: MouseEvent) {
		const target = e.target as HTMLElement;
		const btn = target.closest('[data-action]') as HTMLElement | null;
		if (!btn) return;
		const action = btn.dataset.action;
		const id = Number(btn.dataset.id);
		const doc = documents.find((d) => d.id === id);
		if (!doc) return;
		if (action === 'edit') openEdit(doc);
		if (action === 'delete') requestDelete(doc);
		if (action === 'preview') openPreview(doc);
	}
</script>

<div class="p-4 sm:p-6">
	<!-- Header -->
	<div class="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-6">
		<h2 class="text-2xl font-bold text-primary">{m["documents.Title"]()}</h2>
		<div class="flex gap-2">
			<button
				onclick={openUrlCreate}
				class="px-4 py-2 bg-primary text-text-inverse font-semibold rounded-lg
					hover:bg-primary-hover transition-colors text-sm"
			>
				+ {m["documents.Add URL"]()}
			</button>
			<button
				onclick={openFileCreate}
				class="px-4 py-2 border border-primary text-primary font-semibold rounded-lg
					hover:bg-primary/10 transition-colors text-sm"
			>
				+ {m["documents.Upload"]()}
			</button>
		</div>
	</div>

	<!-- Content -->
	{#if loading}
		<PageSkeleton type="table" />
	{:else if error && documents.length === 0}
		<EmptyState
			icon="⚠"
			title={m["common.Error"]()}
			description={error}
			actionLabel={m["common.Back"]()}
			onAction={fetchDocuments}
		/>
	{:else if documents.length === 0}
		<EmptyState
			icon="📄"
			title={m["common.No Results"]()}
			description={m["documents.empty_description"]()}
			actionLabel={m["documents.Add URL"]()}
			onAction={openUrlCreate}
		/>
	{:else}
		<div onclick={handleTableClick}>
			<DataTable
				{columns}
				rows={documents as unknown as Record<string, unknown>[]}
				searchableKeys={['title', 'description', 'type']}
				searchPlaceholder="{m["common.Search"]()}..."
				emptyTitle={m["common.No Results"]()}
			/>
		</div>

		<div class="mt-4">
			<Pagination {total} {limit} {offset} onPageChange={handlePageChange} />
		</div>
	{/if}
</div>

<!-- URL Form / Edit Modal -->
<Modal bind:open={urlModalOpen} title={editingDocument ? m["documents.Edit Document"]() : m["documents.Add URL Document"]()}>
	<form onsubmit={handleUrlSubmit} class="space-y-4">
		{#if formError}
			<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
				{formError}
			</div>
		{/if}
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["documents.Title"]()} *</label>
			<input bind:value={formTitle} required
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none" />
		</div>
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["documents.URL"]()} *</label>
			<input bind:value={formUrl} required type="url" placeholder="https://..."
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none font-mono" />
		</div>
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["documents.Description"]()}</label>
			<textarea bind:value={formDescription} rows="3"
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none resize-none"></textarea>
		</div>
		<div class="flex gap-3 pt-2">
			<button type="submit" disabled={formLoading}
				class="px-6 py-2 bg-primary text-text-inverse font-semibold rounded-lg
					hover:bg-primary-hover disabled:opacity-50 text-sm">
				{formLoading ? '...' : m["common.Save"]()}
			</button>
			<button type="button" onclick={() => { urlModalOpen = false; editingDocument = null; }}
				class="px-6 py-2 border border-border text-text-muted rounded-lg
					hover:border-primary text-sm">
				{m["common.Cancel"]()}
			</button>
		</div>
	</form>
</Modal>

<!-- File Upload Modal -->
<Modal bind:open={fileModalOpen} title={m['documents.Upload']() + ' ' + m['documents.File']()}>
	<form onsubmit={handleFileSubmit} class="space-y-4">
		{#if formError}
			<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
				{formError}
			</div>
		{/if}
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["documents.Title"]()} *</label>
			<input bind:value={formFileTitle} required
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none" />
		</div>
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["documents.File"]()} *</label>
			<input type="file" onchange={(e) => { const el = (e.target as HTMLInputElement); formFile = el.files?.[0] || null; }} required
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none" />
		</div>
		<div>
			<label class="block text-xs text-text-muted mb-1">{m["documents.Description"]()}</label>
			<textarea bind:value={formFileDescription} rows="3"
				class="w-full px-3 py-2 bg-bg border border-border rounded-lg text-sm text-text
					focus:border-primary focus:outline-none resize-none"></textarea>
		</div>
		{#if uploading}
			<div class="mt-3">
				<div class="w-full bg-border rounded-full h-2">
					<div class="bg-primary h-2 rounded-full transition-all duration-300" style="width: {uploadProgress}%"></div>
				</div>
				<p class="text-xs text-text-muted mt-1">{m["common.Upload Progress"]()} {uploadProgress}%</p>
			</div>
		{/if}
		<div class="flex gap-3 pt-2">
			<button type="submit" disabled={formLoading}
				class="px-6 py-2 bg-primary text-text-inverse font-semibold rounded-lg
					hover:bg-primary-hover disabled:opacity-50 text-sm">
				{formLoading ? '...' : m["documents.Upload"]()}
			</button>
			<button type="button" onclick={() => { fileModalOpen = false; editingDocument = null; }}
				class="px-6 py-2 border border-border text-text-muted rounded-lg
					hover:border-primary text-sm">
				{m["common.Cancel"]()}
			</button>
		</div>
	</form>
</Modal>

<!-- File Preview Modal -->
<Modal bind:open={previewOpen} title={m["documents.Preview File"]()} maxWidth="48rem" onClose={() => { previewOpen = false; }}>
	{#if previewDoc}
		<div class="text-sm text-text-muted mb-3">{previewDoc.title}</div>
		{#if isImage(previewDoc)}
			<div class="flex justify-center">
				<img
					src="/api/v1/documents/{previewDoc.id}/download"
					alt={previewDoc.title}
					class="max-w-full max-h-[70vh] rounded-lg border border-border"
				/>
			</div>
		{:else if isPdf(previewDoc)}
			<iframe
				src="/api/v1/documents/{previewDoc.id}/download"
				class="w-full h-[70vh] rounded-lg border border-border"
				title={previewDoc.title}
			></iframe>
		{:else}
			<div class="text-center py-8 text-text-muted">
				{m["documents.Preview Not Available"]()}
			</div>
		{/if}
	{/if}
</Modal>

<!-- Delete confirmation -->
<ConfirmDialog
	bind:open={deleteOpen}
	title={m["documents.Delete Document"]()}
	message={deleteMessage}
	confirmLabel={m["common.Delete"]()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
	onCancel={() => { deleteTarget = null; }}
/>
