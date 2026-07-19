<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { goto } from '$app/navigation';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import { escapeHtml, escapeAttr } from '$lib/utils';
	import { deviceSchema, validateField, validateForm } from '$lib/utils/validation';
	import type { Device, LinkedDoc, Network } from '$lib/types';
	import { auth } from '$lib/stores/auth';
	import { ChevronDown, ChevronRight, Download, Upload, Plus } from '@lucide/svelte';

	import Modal from '$lib/components/Modal.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import HeartbeatExpandableRow from '$lib/components/HeartbeatExpandableRow.svelte';
	import ColumnPicker from '$lib/components/ColumnPicker.svelte';

interface Stats {
    by_status: Record<string, number>;
    by_type: Record<string, number>;
}

	// --- Core state ---
	let devices = $state<Device[]>([]);
	let stats = $state<Stats>({ by_status: {}, by_type: {} });
	let total = $state(0);
	let loading = $state(true);
	let error = $state('');

	// Request sequencing: every fetch (initial, poll, filter, page) bumps this
	// counter and captures its value. When a response returns, it's discarded
	// unless it's from the LATEST request. This kills the page-count flapping
	// caused by an in-flight background poll landing AFTER a newer user-triggered
	// fetch (search/page/filter change) and overwriting total with a stale value
	// computed for a different offset/filter. Plain boolean "loading" guards
	// don't help here because the poll intentionally runs without setting loading.
	let fetchSeq = 0;

	// --- Filters ---
	let statusFilter = $state('');
	let typeFilter = $state('');
	let dateFrom = $state('');
	let dateTo = $state('');
	// Network filter (distributed): empty = all networks. Populated from
	// GET /networks on mount.
	let networkFilter = $state('');
	let networks = $state<Network[]>([]);
	let offset = $state(0);
	// Per-page size is user-adjustable (was a const 20). Backed by the URL so a
	// page reload / shared link preserves the chosen density.
	let limit = $state(20);
	let showAdvanced = $state(false);
	// Server-side search term (name / ip / mac / serial). The previous page only
	// filtered the current 20-row slice client-side, so any device past page 1
	// was effectively unfindable. This is now pushed to the backend.
	let searchInput = $state('');
	let searchQuery = $state('');
	let searchTimer: ReturnType<typeof setTimeout> | null = null;
	// Server-side sort. empty sortKey ⇒ default server ordering (by id).
	let sortKey = $state('');
	let sortDir = $state<'asc' | 'desc'>('asc');

	// --- Form modal ---
	let formOpen = $state(false);
	let editingDevice = $state<Device | null>(null);
	let formError = $state('');
	let formLoading = $state(false);

	let formName = $state('');
	let formType = $state('pc');
	let formBrand = $state('');
	let formModel = $state('');
	let formLocation = $state('');
	let formPurpose = $state('');
	let formIpAddress = $state('');
	let formMacAddress = $state('');
	let formSerialNumber = $state('');
	let formPurchaseDate = $state('');
	let formWarrantyExpiry = $state('');
	let formTags = $state('');

	// --- Inline validation ---
	let fieldErrors = $state<Record<string, string>>({});

	// --- Delete confirmation ---
	let deleteOpen = $state(false);
	let deleteTarget = $state<Device | null>(null);

	// --- Expandable heartbeat row ---
	let expandedDeviceId = $state<number | null>(null);

	// --- Link document modal ---
	let linkOpen = $state(false);
	let linkDeviceId = $state<number | null>(null);
	let linkDeviceName = $state('');
	let linkedDocs = $state<LinkedDoc[]>([]);
	let allDocs = $state<LinkedDoc[]>([]);
	let selectedDocId = $state<number | null>(null);
	let linkLoading = $state(false);
	let linkError = $state('');

	// --- Bulk operations ---
	let selectedIds = $state<Set<number>>(new Set());
	let batchDeleteOpen = $state(false);
	let batchStatusOpen = $state(false);
	let batchStatusValue = $state('online');
	let batchLoading = $state(false);
	// Export dropdown — click-toggle (not hover) so keyboard/touch users can
	// reach it. group-hover:opacity-100 was invisible without a mouse.
	let exportOpen = $state(false);

	// --- CSV Import ---
	let importOpen = $state(false);
	let importLoading = $state(false);
	let csvFile = $state<File | null>(null);
	let csvPreviewRows = $state<{ ip: string; name: string; type: string }[]>([]);

	// --- Lifecycle ---
	// Polling: device online/offline status is driven by the heartbeat service
	// server-side; without polling the list is a snapshot at mount time and any
	// status transition during the visit is invisible. Background-refresh every
	// 30s without the loading skeleton (avoids flicker) and skips while the user
	// is mid-interaction (a modal/CSV/bulk dialog open) so their state isn't
	// clobbered.
	const POLL_MS = 30_000;
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	onMount(() => {
		// Hydrate filter/sort/page state from the URL so links (e.g. the scan
		// results "View Device" deep link) and reloads land on the right view.
		hydrateFromUrl();
		fetchDevices();
		// Load the network registry for the filter dropdown (best-effort; a
		// failure just leaves the dropdown empty — the list still works).
		api.get<Network[]>('/networks').then((n) => { networks = n || []; }).catch(() => {});
		pollTimer = setInterval(() => {
			if (!formOpen && !deleteOpen && !batchDeleteOpen && !batchStatusOpen && !importOpen && !linkOpen) {
				void refreshDevicesSilent();
			}
		}, POLL_MS);
	});

	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
		if (searchTimer) clearTimeout(searchTimer);
	});

	// buildParams assembles the backend query for the current view state. Shared
	// by the initial fetch and the silent background poll so they never diverge.
	function buildParams(): URLSearchParams {
		const params = new URLSearchParams();
		if (statusFilter) params.set('status', statusFilter);
		if (typeFilter) params.set('type', typeFilter);
		if (networkFilter) params.set('network_id', networkFilter);
		if (searchQuery) params.set('search', searchQuery);
		if (dateFrom) params.set('created_from', dateFrom);
		if (dateTo) params.set('created_to', dateTo);
		if (sortKey) {
			params.set('sort', sortKey);
			params.set('order', sortDir);
		}
		params.set('limit', String(limit));
		params.set('offset', String(offset));
		return params;
	}

	// syncUrl replaces ?… on the address bar with the current view state, without
	// adding a history entry (replaceState). Enables shareable/reloadable views.
	function syncUrl() {
		const params = buildParams();
		const qs = params.toString();
		history.replaceState(null, '', qs ? `?${qs}` : '?');
	}

	// hydrateFromUrl reads filter/sort/page params back from location on mount.
	function hydrateFromUrl() {
		const sp = new URLSearchParams(window.location.search);
		if (sp.get('status')) statusFilter = sp.get('status')!;
		if (sp.get('type')) typeFilter = sp.get('type')!;
		if (sp.get('network_id')) networkFilter = sp.get('network_id')!;
		if (sp.get('search')) {
			searchQuery = sp.get('search')!;
			searchInput = searchQuery;
		}
		if (sp.get('sort')) sortKey = sp.get('sort')!;
		const ord = sp.get('order');
		if (ord === 'asc' || ord === 'desc') sortDir = ord;
		const lim = parseInt(sp.get('limit') ?? '', 10);
		if ([10, 20, 50, 100].includes(lim)) limit = lim;
		const off = parseInt(sp.get('offset') ?? '', 10);
		if (!Number.isNaN(off) && off >= 0) offset = off;
	}

	// onSearchInput debounces the search box: 400ms after the last keystroke the
	// term is committed to searchQuery and a backend fetch fires. Resetting to
	// empty fires immediately so "clear" feels responsive.
	function onSearchInput() {
		if (searchTimer) clearTimeout(searchTimer);
		const v = searchInput.trim();
		if (v === '') {
			searchQuery = '';
			offset = 0;
			fetchDevices();
			return;
		}
		searchTimer = setTimeout(() => {
			searchQuery = v;
			offset = 0;
			fetchDevices();
		}, 400);
	}

	// onSortChange is the DataTable's server-side sort callback: clicking a
	// sortable column header commits the new sort and refetches from page 0.
	function onSortChange(key: string, dir: 'asc' | 'desc') {
		sortKey = key;
		sortDir = dir;
		offset = 0;
		fetchDevices();
	}

	// Silent refresh: same fetch as fetchDevices but no loading skeleton and no
	// error toast — background polling failures shouldn't disrupt the user.
	async function refreshDevicesSilent() {
		// Tag this poll with a sequence number; discard the result if a newer
		// request (user search/page/filter change) has superseded it by the time
		// the response arrives. Without this, a slow poll landing after a fast
		// user fetch overwrites `total` with a value for the wrong filter/offset,
		// which is exactly the "page count flaps on refresh" symptom.
		const seq = ++fetchSeq;
		try {
			const res = await api.get<{ devices: Device[]; total: number }>(`/devices?${buildParams()}`);
			if (seq !== fetchSeq) return; // superseded — drop stale result
			devices = res.devices || [];
			total = res.total || 0;
			const s = await api.get<Stats>(`/devices/stats${networkFilter ? '?network_id=' + networkFilter : ''}`);
			if (seq !== fetchSeq) return;
			stats = s;
		} catch {
			// Swallow: background poll errors are not actionable for the user.
		}
	}

	// --- Data fetching ---
	async function fetchDevices() {
		loading = true;
		error = '';
		syncUrl();
		const seq = ++fetchSeq;
		try {
			const res = await api.get<{ devices: Device[]; total: number }>(`/devices?${buildParams()}`);
			if (seq !== fetchSeq) return; // superseded — a newer fetch owns the state
			devices = res.devices || [];
			total = res.total || 0;

		try {
			const s = await api.get<Stats>(`/devices/stats${networkFilter ? '?network_id=' + networkFilter : ''}`);
			if (seq !== fetchSeq) return;
			stats = s;
		} catch (err: unknown) {
			if (seq !== fetchSeq) return;
			addToast('error', getErrorMessage(err));
			// Fallback: compute stats from device list
			const by_status: Record<string, number> = {};
			const by_type: Record<string, number> = {};
			devices.forEach((d) => {
				by_status[d.status] = (by_status[d.status] || 0) + 1;
				by_type[d.type] = (by_type[d.type] || 0) + 1;
			});
			stats = { by_status, by_type };
		}
		} catch (err: unknown) {
			if (seq === fetchSeq) error = getErrorMessage(err);
		} finally {
			if (seq === fetchSeq) loading = false;
		}
	}

	function applyFilters() {
		offset = 0;
		expandedDeviceId = null;
		selectedIds = new Set();
		fetchDevices();
	}

	// Changing page size resets to page 0 (offset N of a larger page no longer
	// maps cleanly) and refetches.
	function onPageSizeChange(newLimit: number) {
		limit = newLimit;
		offset = 0;
		expandedDeviceId = null;
		selectedIds = new Set();
		fetchDevices();
	}

	// --- Export ---
	async function exportDevices(format: string) {
		try {
			let token: string | null = null;
			const unsub = auth.subscribe((s) => { token = s.token; });
			unsub();
			const res = await fetch(`/api/v1/devices/export?format=${format}`, {
				headers: { 'Authorization': `Bearer ${token}` },
				credentials: 'include'
			});
			if (!res.ok) throw new Error(`Export failed: HTTP ${res.status}`);
			const blob = await res.blob();
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `devices.${format}`;
			document.body.appendChild(a);
			a.click();
			document.body.removeChild(a);
			URL.revokeObjectURL(url);
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Bulk operations ---
	function toggleSelect(id: number) {
		const next = new Set(selectedIds);
		if (next.has(id)) {
			next.delete(id);
		} else {
			next.add(id);
		}
		selectedIds = next;
	}

	function toggleSelectAll() {
		if (selectedIds.size === devices.length) {
			selectedIds = new Set();
		} else {
			selectedIds = new Set(devices.map((d) => d.id));
		}
	}

	async function confirmBatchDelete() {
		if (selectedIds.size === 0) return;
		batchLoading = true;
		try {
			await api.post('/devices/batch-delete', { ids: Array.from(selectedIds) });
			addToast('success', m['devices.Batch Delete Success']().replace('{count}', String(selectedIds.size)));
			selectedIds = new Set();
			fetchDevices();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			batchLoading = false;
			batchDeleteOpen = false;
		}
	}

	async function confirmBatchStatus() {
		if (selectedIds.size === 0) return;
		batchLoading = true;
		try {
			await api.post('/devices/batch-update-status', { ids: Array.from(selectedIds), status: batchStatusValue });
			addToast('success', m['devices.Batch Status Success']().replace('{count}', String(selectedIds.size)));
			selectedIds = new Set();
			fetchDevices();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			batchLoading = false;
			batchStatusOpen = false;
		}
	}

	// --- CSV Import ---
	function handleCsvFileSelect(e: Event) {
		const el = e.target as HTMLInputElement;
		csvFile = el.files?.[0] || null;
		csvPreviewRows = [];
		if (!csvFile) return;
		const reader = new FileReader();
		reader.onload = () => {
			const text = reader.result as string;
			csvPreviewRows = parseCsv(text);
		};
		reader.readAsText(csvFile);
	}

	function parseCsv(text: string): { ip: string; name: string; type: string }[] {
		const lines = text.split(/\r?\n/).filter((l) => l.trim());
		if (lines.length < 2) return [];
		// Skip header row, parse remaining
		const results: { ip: string; name: string; type: string }[] = [];
		for (let i = 1; i < lines.length; i++) {
			const cols = splitCsvLine(lines[i]);
			if (cols.length < 2) continue;
			results.push({
				ip: (cols[0] || '').trim(),
				name: (cols[1] || '').trim(),
				type: (cols[2] || 'other').trim().toLowerCase()
			});
		}
		return results;
	}

	function splitCsvLine(line: string): string[] {
		const result: string[] = [];
		let current = '';
		let inQuotes = false;
		for (let i = 0; i < line.length; i++) {
			const ch = line[i];
			if (inQuotes) {
				if (ch === '"') {
					if (i + 1 < line.length && line[i + 1] === '"') {
						current += '"';
						i++;
					} else {
						inQuotes = false;
					}
				} else {
					current += ch;
				}
			} else {
				if (ch === '"') {
					inQuotes = true;
				} else if (ch === ',') {
					result.push(current);
					current = '';
				} else {
					current += ch;
				}
			}
		}
		result.push(current);
		return result;
	}

	async function confirmImport() {
		if (csvPreviewRows.length === 0) return;
		importLoading = true;
		try {
			await api.post('/scanner/add-devices', { devices: csvPreviewRows });
			addToast('success', m['scanner.Added N Devices']().replace('{count}', String(csvPreviewRows.length)));
			importOpen = false;
			csvFile = null;
			csvPreviewRows = [];
			fetchDevices();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			importLoading = false;
		}
	}

	// --- Form helpers ---
	function resetForm() {
		formName = '';
		formType = 'pc';
		formBrand = '';
		formModel = '';
		formLocation = '';
		formPurpose = '';
		formIpAddress = '';
		formMacAddress = '';
		formSerialNumber = '';
		formPurchaseDate = '';
		formWarrantyExpiry = '';
		formTags = '';
		formError = '';
		fieldErrors = {};
		editingDevice = null;
	}

	function openCreate() {
		resetForm();
		formOpen = true;
	}

	function openEdit(device: Device) {
		editingDevice = device;
		formName = device.name;
		formType = device.type || 'pc';
		formBrand = device.brand || '';
		formModel = device.model || '';
		formLocation = device.location || '';
		formPurpose = device.purpose || '';
		formIpAddress = device.ip_address || '';
		formMacAddress = device.mac_address || '';
		formSerialNumber = device.serial_number || '';
		formPurchaseDate = device.purchase_date || '';
		formWarrantyExpiry = device.warranty_expiry || '';
		formTags = device.tags || '';
		formError = '';
		fieldErrors = {};
		formOpen = true;
	}

	function handleBlur(field: string, value: string) {
		const result = validateField(deviceSchema, field as keyof typeof deviceSchema._type, value);
		if (result.valid) {
			const { [field]: _, ...rest } = fieldErrors;
			fieldErrors = rest;
		} else {
			fieldErrors = { ...fieldErrors, [field]: result.error! };
		}
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		formLoading = true;
		formError = '';

		const body = {
			name: formName,
			type: formType,
			brand: formBrand,
			model: formModel,
			location: formLocation,
			purpose: formPurpose,
			ip_address: formIpAddress,
			mac_address: formMacAddress,
			serial_number: formSerialNumber,
			purchase_date: formPurchaseDate,
			warranty_expiry: formWarrantyExpiry,
			tags: formTags
		};

		const validation = validateForm(deviceSchema, body);
		if (!validation.valid) {
			fieldErrors = validation.errors;
			formLoading = false;
			return;
		}

		try {
			if (editingDevice) {
				await api.put(`/devices/${editingDevice.id}`, body);
				addToast('success', m['devices.Updated']());
			} else {
				await api.post('/devices', body);
				addToast('success', m['devices.Created']());
			}
			formOpen = false;
			resetForm();
			fetchDevices();
		} catch (err: unknown) {
			const msg = getErrorMessage(err);
			formError = msg;
			addToast('error', msg);
		} finally {
			formLoading = false;
		}
	}

	// --- Delete ---
	function openDelete(device: Device) {
		deleteTarget = device;
		deleteOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/devices/${deleteTarget.id}`);
			addToast('success', m['devices.Deleted']());
			deleteTarget = null;
			fetchDevices();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Document linking ---
	async function openLinkModal(device: Device) {
		linkDeviceId = device.id;
		linkDeviceName = device.name;
		linkError = '';
		selectedDocId = null;
		linkLoading = false;
		linkOpen = true;
		await Promise.all([fetchLinkedDocs(device.id), fetchAllDocs()]);
	}

	async function fetchLinkedDocs(deviceId: number) {
		try {
			const res = await api.get<{ documents: LinkedDoc[] }>(`/devices/${deviceId}/documents`);
			linkedDocs = res.documents || [];
		} catch (err: unknown) {
			console.error('devices: fetch linked docs failed', err);
			linkedDocs = [];
		}
	}

	async function fetchAllDocs() {
		try {
			const res = await api.get<{ documents: LinkedDoc[] }>('/documents?limit=200');
			allDocs = res.documents || [];
		} catch (err: unknown) {
			console.error('devices: fetch all docs failed', err);
			allDocs = [];
		}
	}

	async function linkDoc() {
		if (!linkDeviceId || !selectedDocId) return;
		linkLoading = true;
		linkError = '';
		try {
			await api.post(`/devices/${linkDeviceId}/documents`, { document_id: selectedDocId });
			selectedDocId = null;
			await fetchLinkedDocs(linkDeviceId);
		} catch (err: unknown) {
			linkError = getErrorMessage(err);
		} finally {
			linkLoading = false;
		}
	}

	async function unlinkDoc(docId: number) {
		if (!linkDeviceId) return;
		try {
			await api.delete(`/devices/${linkDeviceId}/documents/${docId}`);
			await fetchLinkedDocs(linkDeviceId);
		} catch (err: unknown) {
			linkError = getErrorMessage(err);
		}
	}

	// --- DataTable columns ---
	const typeLabel: Record<string, string> = {
		pc: m['devices.PC'](),
		embedded: m['devices.Embedded'](),
		iot: m['devices.IoT'](),
		server: m['devices.Server'](),
		switch: m['devices.Switch'](),
		router: m['devices.Router'](),
		firewall: m['devices.Firewall'](),
		nas: m['devices.NAS'](),
		camera: m['devices.Camera'](),
		other: m['devices.Other']()
	};

	function statusDotClass(status: string): string {
		if (status === 'online') return 'bg-success animate-pulse-green';
		if (status === 'offline') return 'bg-error animate-pulse-red';
		return 'bg-muted';
	}

	// --- Optional columns (user-toggleable via ColumnPicker) ---
	// Keys are persisted to localStorage; NEVER rename them. New columns
	// default ON so existing users see the improvement (they can opt out).
	const optionalColumns = [
		{ key: 'vendor', label: () => m['devices.Vendor']() },
		{ key: 'mac', label: () => m['devices.MAC Address']() },
		{ key: 'hostname', label: () => m['devices.Hostname']() },
		{ key: 'location', label: () => m['devices.Location']() },
		{ key: 'network_name', label: () => m['devices.Network']() },
		{ key: 'last_scanned_at', label: () => m['devices.Last Scanned']() },
		{ key: 'last_scan_rtt_ms', label: () => m['devices.RTT']() },
		{ key: 'inferred_type', label: () => m['devices.Inferred Type']() },
		{ key: 'os', label: () => m['devices.OS']() },
		{ key: 'serial_number', label: () => m['devices.Serial Number']() },
		{ key: 'purchase_date', label: () => m['devices.Purchase Date']() },
		{ key: 'purpose', label: () => m['devices.Purpose']() }
	];
	const defaultColumns = ['vendor', 'mac', 'hostname', 'location', 'network_name'];
	let selectedColumnKeys = $state(new Set<string>(defaultColumns));

	// Render functions for each optional column (read from scan_attributes
	// where the engine writes the rich data, falling back to top-level fields).
	function renderOptionalColumn(key: string, row: Record<string, unknown>): string {
		const sa = row.scan_attributes as Record<string, unknown> | undefined;
		switch (key) {
			case 'vendor': {
				const v = (sa?.vendor as string) || (row.brand ? String(row.brand) : '');
				return v ? `<span class="text-text">${escapeHtml(v)}</span>` : '-';
			}
			case 'mac': {
				const mac = (sa?.mac as string) || (row.mac_address ? String(row.mac_address) : '');
				return mac ? `<span class="font-mono text-xs">${escapeHtml(mac)}</span>` : '-';
			}
			case 'hostname': {
				const h = sa?.hostname as string | undefined;
				return h ? `<span class="font-mono text-xs">${escapeHtml(h)}</span>` : '-';
			}
			case 'location':
				return row.location ? escapeHtml(String(row.location)) : '-';
			case 'network_name':
				return row.network_name ? escapeHtml(String(row.network_name)) : '-';
			case 'last_scanned_at': {
				const t = (sa?.last_scanned_at as string) || row.last_scanned_at;
				return t ? escapeHtml(new Date(String(t)).toLocaleString()) : '-';
			}
			case 'last_scan_rtt_ms': {
				const rtt = (sa?.last_scan_rtt_ms as number) ?? row.last_scan_rtt_ms;
				return rtt != null ? `<span class="font-mono text-xs">${Number(rtt)}</span>` : '-';
			}
			case 'inferred_type': {
				const t = (sa?.inferred_type as string) || (row.scan_attributes as { inferred_type?: string } | undefined)?.inferred_type;
				return t ? `<span class="text-text">${escapeHtml(t)}</span>` : '-';
			}
			case 'os': {
				const os = sa?.os as string | undefined;
				return os ? escapeHtml(os) : '-';
			}
			case 'serial_number':
				return row.serial_number ? `<span class="font-mono text-xs">${escapeHtml(String(row.serial_number))}</span>` : '-';
			case 'purchase_date':
				return row.purchase_date ? escapeHtml(String(row.purchase_date)) : '-';
			case 'purpose':
				return row.purpose ? escapeHtml(String(row.purpose)) : '-';
			default:
				return '-';
		}
	}

	let columns = $derived([
		{
			key: '_select',
			label: '',
			sortable: false,
			render: (row: Record<string, unknown>) => {
				const id = row.id as number;
				const checked = selectedIds.has(id);
				return `<input type="checkbox" data-action="select" data-id="${id}" ${checked ? 'checked' : ''}
					class="w-4 h-4 rounded border-border text-primary focus:ring-primary cursor-pointer" />`;
			}
		},
		{
			key: '_expand',
			label: '',
			sortable: false,
			render: (row: Record<string, unknown>) => {
				const id = row.id;
				const isExpanded = expandedDeviceId === id;
				return `<button data-action="expand" data-id="${id}" class="p-1 rounded hover:bg-primary/10 transition-colors text-muted">`
					+ `<svg class="w-3.5 h-3.5 transition-transform duration-200 ${isExpanded ? 'rotate-90' : ''}" fill="none" stroke="currentColor" viewBox="0 0 24 24">`
					+ `<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg></button>`;
			}
		},
		{
			key: 'status',
			label: m['devices.Status'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const s = String(row.status ?? 'unknown');
				return `<span class="inline-block w-2.5 h-2.5 rounded-full ${statusDotClass(s)}"></span>`;
			}
		},
		{
			// Device name is a link to the full detail page — the detail page is
			// where every scan_attributes field lives, so this is the primary entry.
			key: 'name',
			label: m['devices.Device Name'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const id = row.id;
				const name = escapeHtml(String(row.name ?? ''));
				return `<button data-action="detail" data-id="${id}" class="text-left font-medium text-primary hover:underline" title="${m['devices.View Details']()}">${name}</button>`;
			}
		},
		{
			key: 'type',
			label: m['devices.Type'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const t = String(row.type ?? 'other');
				return typeLabel[t] || typeLabel['other']!;
			}
		},
		{
			key: 'ip_address',
			label: m['devices.IP Address'](),
			render: (row: Record<string, unknown>) =>
				row.ip_address ? `<span class="font-mono">${escapeHtml(String(row.ip_address))}</span>` : '-'
		},
		// Optional (user-toggleable) columns — included only if selected in the
		// ColumnPicker. Order follows the optionalColumns definition so toggling
		// keeps a stable, predictable column layout.
		...optionalColumns
			.filter((c) => selectedColumnKeys.has(c.key))
			.map((c) => ({
				key: c.key,
				label: c.label(),
				render: (row: Record<string, unknown>) => renderOptionalColumn(c.key, row)
			})),
		{
			key: 'actions',
			label: m['common.Actions'](),
			render: (row: Record<string, unknown>) => {
				const id = row.id;
				const name = escapeAttr(String(row.name ?? ''));
				return `<div class="flex gap-2">`
					+ `<button data-action="detail" data-id="${id}" class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10">${m['devices.Details']()}</button>`
					+ `<button data-action="edit" data-id="${id}" class="text-xs px-2 py-1 rounded text-accent hover:bg-accent/10">${m['common.Edit']()}</button>`
					+ `<button data-action="link" data-id="${id}" data-name="${name}" class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10">${m['documents.Link Document']()}</button>`
					+ `<button data-action="delete" data-id="${id}" data-name="${name}" class="text-xs px-2 py-1 rounded text-error hover:bg-error/10">${m['common.Delete']()}</button>`
					+ `</div>`;
			}
		}
	]);

	function handleTableClick(e: MouseEvent) {
		const target = e.target as HTMLElement;
		// Handle checkbox clicks
		const checkbox = target.closest('input[data-action="select"]') as HTMLInputElement | null;
		if (checkbox) {
			e.stopPropagation();
			const id = Number(checkbox.dataset.id);
			toggleSelect(id);
			return;
		}
		const btn = target.closest('button[data-action]') as HTMLElement | null;
		if (!btn) return;
		const action = btn.dataset.action;
		const id = Number(btn.dataset.id);
		const name = btn.dataset.name ?? '';
		if (action === 'expand') {
			expandedDeviceId = expandedDeviceId === id ? null : id;
			return;
		}
		if (action === 'detail') {
			// Navigate to the full detail page — the only place every device
			// field (scan_attributes, SNMP, services, monitoring, extras) is shown.
			goto(`/devices/detail/${id}`);
			return;
		}
		if (action === 'edit') {
			const device = devices.find((d) => d.id === id);
			if (device) openEdit(device);
		} else if (action === 'link') {
			const device = devices.find((d) => d.id === id);
			if (device) openLinkModal(device);
		} else if (action === 'delete') {
			const device = devices.find((d) => d.id === id) ?? { id, name } as Device;
			openDelete(device);
		}
	}
</script>

<div class="p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6">
		<h2 class="text-2xl font-bold text-primary">{m['devices.Device List']()}</h2>
		<div class="flex gap-2">
			<button onclick={openCreate} class="btn btn-primary">
				<Plus class="w-4 h-4" />
				{m['devices.Create Device']()}
			</button>
		</div>
	</div>

	<!-- Stats bar (responsive) -->
	<div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
		<div class="stat-card">
			<p class="stat-label">{m['common.Total']()}</p>
			<p class="stat-value text-primary">{Object.values(stats.by_status).reduce((a, b) => a + b, 0)}</p>
		</div>
		<div class="stat-card">
			<p class="stat-label">{m['devices.Online']()}</p>
			<p class="stat-value text-success">{stats.by_status?.online ?? 0}</p>
		</div>
		<div class="stat-card">
			<p class="stat-label">{m['devices.Offline']()}</p>
			<p class="stat-value text-error">{stats.by_status?.offline ?? 0}</p>
		</div>
		<div class="stat-card">
			<p class="stat-label">{m['devices.Unknown']()}</p>
			<p class="stat-value text-muted">{stats.by_status?.unknown ?? 0}</p>
		</div>
	</div>

	<!-- Filters + Actions bar -->
	<div class="flex flex-wrap gap-3 mb-4 items-center">
		<select
			bind:value={statusFilter}
			onchange={applyFilters}
			class="input"
		>
			<option value="">{m['devices.All Status']()}</option>
			<option value="online">{m['devices.Online']()}</option>
			<option value="offline">{m['devices.Offline']()}</option>
			<option value="unknown">{m['devices.Unknown']()}</option>
		</select>
		<select
			bind:value={typeFilter}
			onchange={applyFilters}
			class="input"
		>
			<option value="">{m['devices.All Types']()}</option>
			<option value="pc">{m['devices.PC']()}</option>
			<option value="embedded">{m['devices.Embedded']()}</option>
			<option value="iot">{m['devices.IoT']()}</option>
			<option value="server">{m['devices.Server']()}</option>
			<option value="switch">{m['devices.Switch']()}</option>
			<option value="router">{m['devices.Router']()}</option>
			<option value="firewall">{m['devices.Firewall']()}</option>
			<option value="nas">{m['devices.NAS']()}</option>
			<option value="camera">{m['devices.Camera']()}</option>
			<option value="other">{m['devices.Other']()}</option>
		</select>
		{#if networks.length > 0}
			<select
				bind:value={networkFilter}
				onchange={applyFilters}
				class="input"
			>
				<option value="">{m['devices.All Networks']()}</option>
				{#each networks as net}
					<option value={net.id}>{net.name}{net.cidr ? ` (${net.cidr})` : ''}</option>
				{/each}
			</select>
		{/if}

		<!-- Server-side search (name / ip / mac / serial). 400ms debounce. -->
		<div class="relative flex-1 min-w-[180px] max-w-xs">
			<input
				type="text"
				bind:value={searchInput}
				oninput={onSearchInput}
				placeholder={m['devices.Search placeholder']()}
				class="input pr-9"
			/>
			{#if searchInput}
				<button
					onclick={() => { searchInput = ''; onSearchInput(); }}
					class="absolute right-3 top-1/2 -translate-y-1/2 text-muted hover:text-text transition-colors"
					aria-label={m['common.Clear']()}
				>✕</button>
			{:else}
				<span class="absolute right-3 top-1/2 -translate-y-1/2 text-muted pointer-events-none text-sm">⌕</span>
			{/if}
		</div>

		<!-- Advanced filters toggle -->
		<button
			onclick={() => (showAdvanced = !showAdvanced)}
			class="btn btn-secondary"
		>
			{m['devices.Advanced Filters']()}
			<ChevronDown class="w-3 h-3 transition-transform {showAdvanced ? 'rotate-180' : ''}" />
		</button>

		<ColumnPicker
			columns={optionalColumns.map((c) => ({ key: c.key, label: c.label() }))}
			bind:selected={selectedColumnKeys}
			storageKey="device-columns"
			defaults={defaultColumns}
			label={m['devices.Columns']()}
		/>

		<div class="flex-1"></div>

		<!-- Export dropdown (click-toggle — accessible to keyboard/touch) -->
		<div class="relative">
			<button
				onclick={() => (exportOpen = !exportOpen)}
				class="btn btn-secondary"
				aria-expanded={exportOpen}
				aria-haspopup="menu"
			>
				<Download class="w-4 h-4" />
				{m['devices.Export']()}
			</button>
			{#if exportOpen}
				<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
				<div class="fixed inset-0 z-10" onclick={() => (exportOpen = false)} role="presentation"></div>
				<div
					class="absolute right-0 top-full mt-1 bg-surface border border-border rounded-lg z-20 min-w-[120px]"
					style="box-shadow: var(--shadow-md);"
					role="menu"
				>
					<button
						onclick={() => { exportDevices('csv'); exportOpen = false; }}
						role="menuitem"
						class="w-full text-left px-4 py-2 text-sm text-text hover:bg-surface-2 rounded-t-lg">
						{m['devices.Export CSV']()}
					</button>
					<button
						onclick={() => { exportDevices('json'); exportOpen = false; }}
						role="menuitem"
						class="w-full text-left px-4 py-2 text-sm text-text hover:bg-surface-2 rounded-b-lg">
						{m['devices.Export JSON']()}
					</button>
				</div>
			{/if}
		</div>

		<!-- Import CSV button -->
		<button
			onclick={() => { csvFile = null; csvPreviewRows = []; importOpen = true; }}
			class="btn btn-secondary"
		>
			<Upload class="w-4 h-4" />
			{m['devices.Import CSV']()}
		</button>
	</div>

	<!-- Advanced filters panel -->
	{#if showAdvanced}
		<div class="mb-4 p-4 bg-surface border border-border rounded-lg">
			<div class="flex flex-wrap gap-3 items-end">
				<div>
					<label class="block text-xs text-muted mb-1">{m['devices.Date From']()}</label>
					<input type="date" bind:value={dateFrom}
						class="input" />
				</div>
				<div>
					<label class="block text-xs text-muted mb-1">{m['devices.Date To']()}</label>
					<input type="date" bind:value={dateTo}
						class="input" />
				</div>
				<button onclick={applyFilters} class="btn btn-primary">
					{m['common.Filter']()}
				</button>
			</div>
		</div>
	{/if}

	<!-- Bulk action bar -->
	{#if selectedIds.size > 0}
		<div class="mb-4 px-4 py-3 bg-primary/10 border border-primary/30 rounded-lg flex items-center gap-3">
			<div class="flex items-center gap-2">
				<input type="checkbox" checked onchange={toggleSelectAll}
					class="w-4 h-4 rounded border-border text-primary focus:ring-primary cursor-pointer" />
				<span class="text-sm font-medium text-primary">
					{m['devices.Selected Count']().replace('{count}', String(selectedIds.size))}
				</span>
			</div>
			<div class="flex-1"></div>
			<button
				onclick={() => (batchDeleteOpen = true)}
				class="btn btn-danger text-xs py-1.5"
			>
				{m['devices.Batch Delete']()}
			</button>
			<div class="relative">
				<button
					onclick={() => (batchStatusOpen = !batchStatusOpen)}
					class="btn btn-primary text-xs py-1.5"
				>
					{m['devices.Batch Update Status']()}
					<ChevronDown class="w-3 h-3" />
				</button>
				{#if batchStatusOpen}
					<div class="absolute right-0 top-full mt-1 bg-surface border border-border rounded-lg z-10 min-w-[140px]" style="box-shadow: var(--shadow-md);">
						{#each ['online', 'offline', 'unknown'] as status}
							<button
								onclick={() => { batchStatusValue = status; batchStatusOpen = false; confirmBatchStatus(); }}
								class="w-full text-left px-4 py-2 text-sm text-text hover:bg-surface-2 last:rounded-b-lg first:rounded-t-lg"
							>
								<span class="inline-block w-2 h-2 rounded-full mr-2 {statusDotClass(status)}"></span>
								{status === 'online' ? m['devices.Online']() : status === 'offline' ? m['devices.Offline']() : m['devices.Unknown']()}
							</button>
						{/each}
					</div>
				{/if}
			</div>
		</div>
	{/if}

	<!-- Error -->
	{#if error}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error" aria-live="polite">
			{error}
		</div>
	{/if}

	{#snippet expandedRow(row)}
		{@const device = devices.find((d) => d.id === row.id)}
		<div class="border-t border-border bg-bg/50">
			{#if device}
				<div class="flex items-center gap-2 px-4 py-2 bg-surface/50 border-b border-border">
					<button
						onclick={() => (expandedDeviceId = null)}
						class="p-1 rounded hover:bg-surface-2 transition-colors text-muted"
						aria-label="Collapse row"
					>
						<ChevronRight class="w-3.5 h-3.5 rotate-90" />
					</button>
					<span class="text-sm font-medium text-primary">{device.name}</span>
					<span class="text-xs text-muted">— Heartbeat</span>
				</div>
			{/if}
			<HeartbeatExpandableRow deviceId={row.id as number} expanded={true} />
		</div>
	{/snippet}

	<!-- Loading skeleton -->
	{#if loading}
		<PageSkeleton type="table" />
	{:else}
		<!-- Device table with expandable heartbeat rows -->
		<div onclick={handleTableClick}>
			<DataTable
				{columns}
				rows={devices as unknown as Record<string, unknown>[]}
				emptyTitle={m['devices.No Devices']()}
				emptyDescription={m['devices.No Devices Desc']()}
				emptyAction={openCreate}
				emptyActionLabel={m['devices.Create Device']()}
				expandedRowId={expandedDeviceId}
				expandedContent={expandedRow}
				externalSortKey={sortKey || null}
				externalSortDirection={sortKey ? sortDir : 'none'}
				onSortChange={onSortChange}
			/>
		</div>

		<!-- Pagination -->
		<Pagination {total} {limit} {offset} onPageChange={(o) => { offset = o; expandedDeviceId = null; selectedIds = new Set(); fetchDevices(); }} onPageSizeChange={onPageSizeChange} />
	{/if}
</div>

<!-- Create/Edit Modal -->
<Modal bind:open={formOpen} title={editingDevice ? m['devices.Edit Device']() : m['devices.Create Device']()} maxWidth="42rem" onClose={resetForm}>
	{#if formError}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{formError}
		</div>
	{/if}

	<form onsubmit={handleSubmit} class="grid grid-cols-2 gap-4">
		<!-- Name -->
		<div class="col-span-2">
			<label class="block text-xs text-muted mb-1">{m['devices.Device Name']()} *</label>
			<input
				bind:value={formName}
				onblur={() => handleBlur('name', formName)}
				required
				class="input {fieldErrors.name ? '!border-error' : ''}"
			/>
			{#if fieldErrors.name}
				<p class="text-xs text-error mt-1">{fieldErrors.name}</p>
			{/if}
		</div>

		<!-- Type -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Type']()} *</label>
			<select
				bind:value={formType}
				onblur={() => handleBlur('type', formType)}
				class="input"
			>
				<option value="pc">{m['devices.PC']()}</option>
				<option value="embedded">{m['devices.Embedded']()}</option>
				<option value="iot">{m['devices.IoT']()}</option>
				<option value="other">{m['devices.Other']()}</option>
			</select>
			{#if fieldErrors.type}
				<p class="text-xs text-error mt-1">{fieldErrors.type}</p>
			{/if}
		</div>

		<!-- Brand -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Brand']()}</label>
			<input bind:value={formBrand}
				class="input" />
		</div>

		<!-- Model -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Model']()}</label>
			<input bind:value={formModel}
				class="input" />
		</div>

		<!-- Location -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Location']()}</label>
			<input bind:value={formLocation}
				class="input" />
		</div>

		<!-- Purpose -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Purpose']()}</label>
			<input bind:value={formPurpose}
				class="input" />
		</div>

		<!-- IP Address -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.IP Address']()}</label>
			<input
				bind:value={formIpAddress}
				onblur={() => handleBlur('ip_address', formIpAddress)}
				placeholder="192.168.1.100"
				class="input font-mono {fieldErrors.ip_address ? '!border-error' : ''}"
			/>
			{#if fieldErrors.ip_address}
				<p class="text-xs text-error mt-1">{fieldErrors.ip_address}</p>
			{/if}
		</div>

		<!-- MAC Address -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.MAC Address']()}</label>
			<input
				bind:value={formMacAddress}
				onblur={() => handleBlur('mac_address', formMacAddress)}
				placeholder="AA:BB:CC:DD:EE:FF"
				class="input font-mono {fieldErrors.mac_address ? '!border-error' : ''}"
			/>
			{#if fieldErrors.mac_address}
				<p class="text-xs text-error mt-1">{fieldErrors.mac_address}</p>
			{/if}
		</div>

		<!-- Serial Number -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Serial Number']()}</label>
			<input bind:value={formSerialNumber}
				class="input font-mono" />
		</div>

		<!-- Purchase Date -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Purchase Date']()}</label>
			<input type="date" bind:value={formPurchaseDate}
				class="input" />
		</div>

		<!-- Warranty Expiry -->
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Warranty Expiry']()}</label>
			<input type="date" bind:value={formWarrantyExpiry}
				class="input" />
		</div>

		<!-- Tags -->
		<div class="col-span-2">
			<label class="block text-xs text-muted mb-1">{m['devices.Tags']()}</label>
			<input bind:value={formTags} placeholder="server,production,rack-a"
				class="input" />
		</div>

		<!-- Submit -->
		<div class="col-span-2 flex gap-3 pt-2">
		<LoadingButton type="submit" loading={formLoading} variant="primary" label={m['common.Save']()} />
			<button type="button" onclick={() => { formOpen = false; resetForm(); }} class="btn btn-secondary">
				{m['common.Cancel']()}
			</button>
		</div>
	</form>
</Modal>

<!-- Delete confirmation -->
<ConfirmDialog
	bind:open={deleteOpen}
	title={m['devices.Delete Device']()}
	message={`${m['common.Are you sure?']()} "${deleteTarget?.name ?? ''}"`}
	confirmLabel={m['common.Delete']()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
	onCancel={() => { deleteTarget = null; }}
/>

<!-- Batch Delete confirmation -->
<ConfirmDialog
	bind:open={batchDeleteOpen}
	title={m['devices.Batch Delete']()}
	message={m['devices.Batch Delete Confirm']()}
	confirmLabel={m['common.Delete']()}
	confirmVariant="danger"
	onConfirm={confirmBatchDelete}
	onCancel={() => { batchDeleteOpen = false; }}
/>

<!-- CSV Import Modal -->
<Modal bind:open={importOpen} title={m['devices.Import Devices']()} maxWidth="48rem" onClose={() => { importOpen = false; }}>
	<div class="space-y-4">
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Import CSV']()}</label>
			<input type="file" accept=".csv" onchange={handleCsvFileSelect}
				class="input" />
			<p class="text-xs text-muted mt-1">CSV format: ip,name,type (header row required)</p>
		</div>

		{#if csvPreviewRows.length > 0}
			<div>
				<h4 class="text-sm font-medium text-text mb-2">{m['devices.Import Preview']()} ({csvPreviewRows.length} rows)</h4>
				<div class="overflow-x-auto border border-border rounded-lg max-h-60">
					<table class="w-full text-sm">
						<thead>
							<tr class="bg-surface border-b border-border text-left text-xs text-muted">
								<th class="px-3 py-2">IP</th>
								<th class="px-3 py-2">{m['devices.Device Name']()}</th>
								<th class="px-3 py-2">{m['devices.Type']()}</th>
							</tr>
						</thead>
						<tbody>
							{#each csvPreviewRows as row, i}
								<tr class="border-b border-border last:border-b-0 hover:bg-border/30">
									<td class="px-3 py-2 font-mono">{row.ip}</td>
									<td class="px-3 py-2">{row.name}</td>
									<td class="px-3 py-2">{row.type}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			</div>
			<div class="flex justify-end gap-3">
				<button onclick={() => { importOpen = false; }} class="btn btn-secondary">
					{m['common.Cancel']()}
				</button>
				<LoadingButton onclick={confirmImport} loading={importLoading} variant="primary" label={m['devices.Import Confirm']()} />
			</div>
		{/if}
	</div>
</Modal>

<!-- Link Document Modal -->
<Modal bind:open={linkOpen} title={m['documents.Link Document']()} maxWidth="32rem" onClose={() => { linkOpen = false; }}>
	<p class="text-xs text-muted mb-4">{linkDeviceName}</p>

	{#if linkError}
		<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
			{linkError}
		</div>
	{/if}

	<!-- Linked documents -->
	<div class="mb-4">
		<h4 class="text-xs font-semibold text-muted uppercase tracking-wider mb-2">
			{m['documents.Linked Documents']()}
		</h4>
		{#if linkedDocs.length === 0}
			<p class="text-xs text-muted">{m['documents.No Documents Linked']()}</p>
		{:else}
			<div class="space-y-2">
				{#each linkedDocs as doc}
					<div class="flex items-center justify-between px-3 py-2 bg-bg border border-border rounded-lg">
						<div class="flex items-center gap-2 min-w-0">
							<span class="text-xs px-1.5 py-0.5 rounded
								{doc.type === 'url' ? 'bg-accent/10 text-accent' : 'bg-primary/10 text-primary'}">
								{doc.type === 'url' ? 'URL' : 'File'}
							</span>
							<span class="text-sm text-text truncate">{doc.title}</span>
						</div>
						<button onclick={() => unlinkDoc(doc.id)}
							class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 shrink-0">
							{m['common.Unlink']()}
						</button>
					</div>
				{/each}
			</div>
		{/if}
	</div>

	<!-- Add new link -->
	<div class="border-t border-border pt-4">
		<h4 class="text-xs font-semibold text-muted uppercase tracking-wider mb-2">
			{m['documents.Select Document']()}
		</h4>
		<div class="flex gap-2">
			<select bind:value={selectedDocId} class="input flex-1">
				<option value={null}>-- {m['documents.Select Document']()} --</option>
				{#each allDocs.filter((d) => !linkedDocs.some((ld) => ld.id === d.id)) as doc}
					<option value={doc.id}>{doc.title} ({doc.type})</option>
				{/each}
			</select>
			<LoadingButton onclick={linkDoc} loading={linkLoading} disabled={!selectedDocId} variant="primary" label={m['common.Link']()} class="shrink-0" />
		</div>
	</div>

	<div class="flex justify-end mt-4 pt-3 border-t border-border">
		<button onclick={() => (linkOpen = false)} class="btn btn-secondary">
			{m['common.Close']()}
		</button>
	</div>
</Modal>
