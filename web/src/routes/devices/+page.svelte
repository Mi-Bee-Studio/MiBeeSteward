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
	import { acquireStream, changeStream, releaseStream } from '$lib/stores/changes';
	import { goto } from '$app/navigation';
	import { addToast } from '$lib/stores/toast';
	import { getErrorMessage } from '$lib/utils/error';
	import { escapeHtml, escapeAttr, formatDateTime } from '$lib/utils';
	import { isValidIP } from '$lib/utils/validation';
	import { defaultRange } from '$lib/utils/dateRange';
	import type { Device, LinkedDoc, Network , NetworkWithMirror } from '$lib/types';
	import { ChevronDown, ChevronRight, Download, Upload, Plus, List, Share2 } from '@lucide/svelte';

	import Modal from '$lib/components/Modal.svelte';
	import LoadingButton from '$lib/components/LoadingButton.svelte';
	import DeviceEditModal from '$lib/components/DeviceEditModal.svelte';
	import DeviceTopologyView from '$lib/components/DeviceTopologyView.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import Pagination from '$lib/components/Pagination.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import HeartbeatExpandableRow from '$lib/components/HeartbeatExpandableRow.svelte';
	import ColumnPicker from '$lib/components/ColumnPicker.svelte';
	import { tagDisplayName } from '$lib/api/archiveTags';

interface Stats {
    by_status: Record<string, number>;
    by_type: Record<string, number>;
}

// AddDevicesResponse mirrors backend domain.AddDevicesResponse: the CSV import
// must read {added, errors} from it rather than assuming every preview row
// succeeded (#58: partial failures used to be silently miscounted).
interface AddDevicesResponse {
	added: number;
	errors: string[];
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
	// Lifecycle filter (#669): '' = all states; exact server-side match.
	let lifecycleFilter = $state('');
	let dateFrom = $state('');
	let dateTo = $state('');
	// Network filter (distributed): empty = all networks. Populated from
	// GET /networks on mount.
	let networkFilter = $state('');
	let networks = $state<NetworkWithMirror[]>([]);
	// Tag filter (#665): dictionary tag id as string; '' = all tags.
	let tagFilter = $state('');
	let tagDictionary = $state<{ id: number; key: string; name: string; color: string; builtin: boolean }[]>([]);
	// Batch tagging (#665): assign one dictionary tag to every selected row.
	let batchTagOpen = $state(false);
	let batchTagID = $state('');
	let batchTagBusy = $state(false);
	// #379: a device in a network with agent_id set is a mirror (distributed
	// agent or federated peer) - read-only here, hide its edit/delete actions.
	const remoteNetworkIDs = $derived(new Set(networks.filter((n) => n.agent_id).map((n) => n.id)));
	// Mirror freshness (#557): agent/peer-managed networks whose owning agent
	// hasn't reported within the server's fresh window. Derived per fetch —
	// an agent recovery un-grays the segment on the next load.
	const staleNetworkIDs = $derived(new Set(networks.filter((n) => n.agent_stale).map((n) => n.id)));
	const agentLastUsedByID = $derived(new Map(networks.filter((n) => n.agent_last_used_at).map((n) => [n.id, n.agent_last_used_at as string])));
	const isStaleDevice = (d: Pick<Device, 'network_id'>) => d.network_id !== null && d.network_id !== undefined && staleNetworkIDs.has(d.network_id);
	const isRemoteDevice = (d: Pick<Device, 'network_id'>) => d.network_id !== null && d.network_id !== undefined && remoteNetworkIDs.has(d.network_id);
	// networksError tracks a /networks fetch failure so the network-filter
	// dropdown shows a small "failed to load" indicator instead of silently
	// vanishing (which a user could mistake for "no networks configured").
	let networksError = $state(false);
	let offset = $state(0);
	// Per-page size is user-adjustable (was a const 20). Backed by the URL so a
	// page reload / shared link preserves the chosen density.
	let limit = $state(20);
	let showAdvanced = $state(false);
	// Compact filter bar (#UI-compact): the four secondary axes (type /
	// lifecycle / network / tag) live in one popover instead of four stacked
	// full-width selects — the bar drops from ~240px to one ~48px row and the
	// device table starts in the first viewport.
	let filterMenuOpen = $state(false);
	// View toggle: 'list' (device table) vs 'topology' (radial L2 graph).
	// /topology used to be a separate top-level route; it's now a view here
	// because list/subnet views were just alternate groupings of this same
	// table: only the radial graph (needs /topology API edges) is unique.
	let viewMode = $state<'list' | 'topology'>('list');
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
	// The device create/edit form lives in <DeviceEditModal> (shared with the
	// detail page). This page just toggles `editOpen` and supplies the device to
	// edit (null ⇒ create mode). onSaved refreshes the list after a save.
	let editOpen = $state(false);
	let editTarget = $state<Device | null>(null);


	// --- Delete confirmation ---
	let deleteOpen = $state(false);
	let deleteTarget = $state<Pick<Device, 'id' | 'name'> | null>(null);

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
	// Batch status confirmation: the dropdown no longer fires the mutation
	// directly: it stages the chosen status here, then a ConfirmDialog gates
	// the actual API call. Prevents an accidental click from bulk-flipping
	// dozens of devices to "offline" with no undo (#150).
	let pendingBatchStatus = $state<string | null>(null);
	let batchStatusConfirmOpen = $state(false);
	let batchLoading = $state(false);
	// Export dropdown: click-toggle (not hover) so keyboard/touch users can
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

	// --- Live updates via the change stream (#272) ----------------------------
	// Events trigger a debounced SILENT refresh (batched: a scan touching 37
	// devices fires many events within a second: one refetch covers them).
	// device_added / device_lost / device_recovered also toast, so a scan
	// running in another tab (or on the server) is visible here immediately.
	let streamUnsub: (() => void) | null = null;
	let sseRefreshTimer: ReturnType<typeof setTimeout> | null = null;
	let sseToastGuard = 0;

	function onChangeEvent(changeType: string, entityId: number | null | undefined) {
		// One toast per burst per kind (max ~1/s): cap the guard.
		if (entityId && Date.now() - sseToastGuard > 900) {
			sseToastGuard = Date.now();
			if (changeType === 'device_added') addToast('success', m['devices.Sse Device Added']());
			else if (changeType === 'device_lost') addToast('warning', m['devices.Sse Device Lost']());
			else if (changeType === 'device_recovered') addToast('info', m['devices.Sse Device Recovered']());
		}
		if (sseRefreshTimer) clearTimeout(sseRefreshTimer);
		sseRefreshTimer = setTimeout(() => {
			sseRefreshTimer = null;
			if (!editOpen && !deleteOpen && !batchDeleteOpen && !batchStatusOpen && !batchStatusConfirmOpen && !importOpen && !linkOpen) {
				void refreshDevicesSilent();
			}
		}, 1500);
	}

	onMount(() => {
		// Hydrate filter/sort/page state from the URL so links (e.g. the scan
		// results "View Device" deep link) and reloads land on the right view.
		hydrateFromUrl();
		fetchDevices();
		acquireStream();
		streamUnsub = changeStream().subscribe((st) => {
			if (st.lastEvent) onChangeEvent(st.lastEvent.change_type, st.lastEvent.entity_id);
		});
		// Load the network registry for the filter dropdown (best-effort; a
		// failure just leaves the dropdown empty: the list still works).
		api.get<{ networks: NetworkWithMirror[]; total: number }>('/networks').then((r) => { networks = r.networks || []; networksError = false; }).catch(() => { networksError = true; });
		// Tag dictionary for the filter dropdown + batch tagging (#665, best-effort).
		api.get<{ tags: { id: number; key: string; name: string; color: string; builtin: number }[] }>('/tags')
			.then((r) => {
				tagDictionary = (r.tags ?? []).map((t) => ({ id: t.id, key: t.key, name: tagDisplayName(t), color: t.color, builtin: t.builtin === 1 }));
			})
			.catch(() => {});
		pollTimer = setInterval(() => {
			if (!editOpen && !deleteOpen && !batchDeleteOpen && !batchStatusOpen && !batchStatusConfirmOpen && !importOpen && !linkOpen) {
				void refreshDevicesSilent();
			}
		}, POLL_MS);
	});

	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
		if (searchTimer) clearTimeout(searchTimer);
		if (sseRefreshTimer) clearTimeout(sseRefreshTimer);
		streamUnsub?.();
		streamUnsub = null;
		releaseStream();
	});

	// Esc closes any open dropdown menu (Export / batch-status). The global
	// +layout.svelte Escape handler only targets .modal-backdrop, so these
	// click-toggle menus need their own listener. Click-outside is already
	// handled by each menu's fixed inset-0 overlay.
	$effect(() => {
		function onKeydown(e: KeyboardEvent) {
			if (e.key !== 'Escape') return;
			// The batch-status ConfirmDialog manages its own Escape via Modal; let
			// it through (it sits on top of the dropdown) so the confirm closes
			// before the dropdown does.
			if (batchStatusConfirmOpen) return;
			if (exportOpen) { exportOpen = false; e.stopPropagation(); }
			else if (batchStatusOpen) { batchStatusOpen = false; e.stopPropagation(); }
		}
		window.addEventListener('keydown', onKeydown);
		return () => window.removeEventListener('keydown', onKeydown);
	});

	// buildParams assembles the backend query for the current view state. Shared
	// by the initial fetch and the silent background poll so they never diverge.
	function buildParams(): URLSearchParams {
		const params = new URLSearchParams();
		if (statusFilter) params.set('status', statusFilter);
		if (typeFilter) params.set('type', typeFilter);
		if (lifecycleFilter) params.set('lifecycle_state', lifecycleFilter);
		if (networkFilter) params.set('network_id', networkFilter);
		if (tagFilter) params.set('tag_id', tagFilter);
		if (searchQuery) params.set('search', searchQuery);
		if (dateFrom) params.set('created_from', dateFrom);
		if (dateTo) params.set('created_to', dateTo);
		if (sortKey) {
			params.set('sort', sortKey);
			params.set('order', sortDir);
		}
		params.set('limit', String(limit));
		params.set('offset', String(offset));
		if (viewMode === 'topology') params.set('view', 'topology');
		return params;
	}

	// syncUrl replaces ?… on the address bar with the current view state, without
	// adding a history entry (replaceState). Enables shareable/reloadable views.
	function syncUrl() {
		const params = buildParams();
		// Foreign params this page doesn't own must survive the rewrite —
		// building the query from scratch used to strip them (the topology
		// view's dim=3d deep link, #635, vanished on the first sync).
		const owned = new Set([
			'status', 'type', 'network_id', 'search', 'created_from', 'created_to', 'sort', 'order', 'limit', 'offset', 'view'
		]);
		const current = new URLSearchParams(window.location.search);
		for (const [k, v] of current) {
			if (!owned.has(k)) params.set(k, v);
		}
		const qs = params.toString();
		history.replaceState(null, '', qs ? `?${qs}` : '?');
	}

	// hydrateFromUrl reads filter/sort/page params back from location on mount.
	function hydrateFromUrl() {
		const sp = new URLSearchParams(window.location.search);
		if (sp.get('status')) statusFilter = sp.get('status')!;
		if (sp.get('type')) typeFilter = sp.get('type')!;
		if (sp.get('lifecycle_state')) lifecycleFilter = sp.get('lifecycle_state')!;
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
		if (sp.get('view') === 'topology') viewMode = 'topology';
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
	// error toast: background polling failures shouldn't disrupt the user.
	async function refreshDevicesSilent() {
		// Tag this poll with a sequence number; discard the result if a newer
		// request (user search/page/filter change) has superseded it by the time
		// the response arrives. Without this, a slow poll landing after a fast
		// user fetch overwrites `total` with a value for the wrong filter/offset,
		// which is exactly the "page count flaps on refresh" symptom.
		const seq = ++fetchSeq;
		try {
			const res = await api.get<{ devices: Device[]; total: number }>(`/devices?${buildParams()}`);
			if (seq !== fetchSeq) return; // superseded: drop stale result
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
			if (seq !== fetchSeq) return; // superseded: a newer fetch owns the state
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

	// --- Compact filter bar helpers (#UI-compact) ---------------------------
	// Chip labels reuse the EXISTING maps below (typeLabel Record ~line 750,
	// lifecycleLabel fn ~line 836) so a chip and its DataTable/ledger row
	// can never disagree.
	interface ActiveSecondaryFilter {
		key: 'type' | 'lifecycle' | 'network' | 'tag';
		label: string;
		clear: () => void;
	}
	const activeSecondaryFilters = $derived.by<ActiveSecondaryFilter[]>(() => {
		const out: ActiveSecondaryFilter[] = [];
		if (typeFilter) out.push({ key: 'type', label: typeLabel[typeFilter] ?? typeFilter, clear: () => { typeFilter = ''; applyFilters(); } });
		if (lifecycleFilter) out.push({ key: 'lifecycle', label: lifecycleLabel(lifecycleFilter), clear: () => { lifecycleFilter = ''; applyFilters(); } });
		// (lifecycleLabel/typeLabel are declared further down; both run before
		// this derived is first read, so the references resolve fine.)
		if (networkFilter) {
			const net = networks.find((n) => String(n.id) === String(networkFilter));
			out.push({ key: 'network', label: net ? net.name : String(networkFilter), clear: () => { networkFilter = ''; applyFilters(); } });
		}
		if (tagFilter) {
			const tag = tagDictionary.find((t) => String(t.id) === String(tagFilter));
			out.push({ key: 'tag', label: tag ? tag.name : String(tagFilter), clear: () => { tagFilter = ''; applyFilters(); } });
		}
		return out;
	});
	// The popover button's badge: how many secondary axes are active.
	const secondaryActiveCount = $derived(activeSecondaryFilters.length);
	function setStatusFilter(v: string) {
		statusFilter = v;
		applyFilters();
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

	// View toggle (list vs topology). Syncs to the URL so a topology view is
	// shareable/reloadable. No refetch: list data is already loaded, and the
	// topology component fetches /topology itself on mount.
	function switchView(mode: 'list' | 'topology') {
		viewMode = mode;
		syncUrl();
	}

	// --- Export ---
	async function exportDevices(format: string) {
		try {
			// Go through api.download() so CSRF + cookie auth + 401 handling
			// match every other request. The previous raw fetch() bypass dropped
			// the X-CSRF-Token header and manually extracted a Bearer token;
			// both deviations from the client contract.
			const blob = await api.download(`/devices/export?format=${format}`);
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
			addToast('success', m['devices.Batch Delete Success']({ count: selectedIds.size }));
			selectedIds = new Set();
			fetchDevices();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			batchLoading = false;
		}
	}

	// Batch tagging (#665): assign one dictionary tag to every selected row.
	async function confirmBatchTag() {
		if (selectedIds.size === 0 || !batchTagID) return;
		batchTagBusy = true;
		try {
			const resp = await api.post<{ applied: number }>(`/tags/${batchTagID}/devices`, {
				device_ids: Array.from(selectedIds)
			});
			addToast('success', m['devices.Batch Tag Success']({ count: resp.applied ?? selectedIds.size }));
			batchTagOpen = false;
			fetchDevices();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			batchTagBusy = false;
		}
	}

	async function confirmBatchStatus() {
		if (selectedIds.size === 0 || !pendingBatchStatus) return;
		batchLoading = true;
		try {
			await api.post('/devices/batch-update-status', { ids: Array.from(selectedIds), status: pendingBatchStatus });
			addToast('success', m['devices.Batch Status Success']({ count: selectedIds.size }));
			selectedIds = new Set();
			fetchDevices();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			batchLoading = false;
			batchStatusOpen = false;
			batchStatusConfirmOpen = false;
			pendingBatchStatus = null;
		}
	}

	// Map a status key to its localized display label, for the confirm dialog's
	// human-readable message ("mark as offline": not "mark as 'offline'").
	function statusLabel(status: string): string {
		if (status === 'online') return m['devices.Online']();
		if (status === 'offline') return m['devices.Offline']();
		return m['devices.Unknown']();
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
			// Read the backend's {added, errors} instead of assuming every preview
			// row succeeded: partial failures (duplicate IP, bad format) used to be
			// silently miscounted as successes (#58).
			const res = await api.post<AddDevicesResponse>('/scanner/add-devices', { devices: csvPreviewRows });
			if (res.errors && res.errors.length > 0) {
				// Summary warning with the first error reason, rather than a toast
				// per failure (noisy when many rows fail).
				addToast('warning', m['scanner.Import N Failed']({ count: res.errors.length, reason: res.errors[0] }));
			}
			if (res.added > 0) {
				addToast('success', m['scanner.Added N Devices']({ count: res.added }));
				importOpen = false;
				csvFile = null;
				csvPreviewRows = [];
				fetchDevices();
			}
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			importLoading = false;
		}
	}

	// --- Form helpers ---
	// The form state/validation/submit moved into <DeviceEditModal>. These two
	// wrappers keep the existing call sites (openCreate/openEdit) unchanged:
	// they just toggle the shared modal open with the right target.
	function openCreate() {
		editTarget = null;
		editOpen = true;
	}

	function openEdit(device: Device) {
		editTarget = device;
		editOpen = true;
	}


	// --- Delete ---
	function openDelete(device: Pick<Device, 'id' | 'name'>) {
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
		phone: m['devices.Phone'](),
		printer: m['devices.Printer'](),
		other: m['devices.Other']()
	};

	function statusDotClass(status: string): string {
		if (status === 'online') return 'bg-success animate-pulse-green';
		if (status === 'offline') return 'bg-error animate-pulse-red';
		return 'bg-muted';
	}

	// formatOfflineDuration renders "Nd Nh" / "Nh Nm" / "Nm" from an offline_since
	// timestamp: the status-dot hover text so an operator can tell at a glance
	// how long a device has been down (and how close it is to the retention
	// prune threshold). offline_since is a column on devices and is already in
	// the LIST payload, so this needs no extra fetch.
	function formatOfflineDuration(offlineSince?: string | null): string {
		if (!offlineSince) return '';
		const then = Date.parse(offlineSince);
		if (Number.isNaN(then)) return '';
		const ms = Date.now() - then;
		if (ms < 0) return ''; // clock skew / future timestamp: don't mislead
		const min = Math.floor(ms / 60000);
		const days = Math.floor(min / 1440);
		const hours = Math.floor((min % 1440) / 60);
		const mins = min % 60;
		if (days > 0) return `${days}d ${hours}h`;
		if (hours > 0) return `${hours}h ${mins}m`;
		return `${mins}m`;
	}

	// statusDotTitle returns the hover title for the status dot. Online/unknown
	// get a plain label; offline gets "已离线 Nd Nh" (the actionable bit).
	function statusDotTitle(status: string, row: Record<string, unknown>): string {
		if (status === 'offline') {
			const dur = formatOfflineDuration((row.offline_since as string | null | undefined) ?? null);
			return dur ? m['devices.Offline For']({ duration: dur }) : m['devices.Offline']();
		}
		if (status === 'online') return m['devices.Online']();
		return m['devices.Unknown']();
	}

	// --- Optional columns (user-toggleable via ColumnPicker) ---
	// Keys are persisted to localStorage; NEVER rename them. New columns
	// default ON so existing users see the improvement (they can opt out).
	const optionalColumns = [
		// `sortable` opts a column into server-side sort (the backend sortWhitelist
		// must accept the key). vendor/hostname/network_name/last_scanned_at are now
		// backend-supported; the rest are display-only.
		{ key: 'vendor', label: () => m['devices.Vendor'](), sortable: true },
		{ key: 'mac', label: () => m['devices.MAC Address']() },
		{ key: 'hostname', label: () => m['devices.Hostname'](), sortable: true },
		{ key: 'location', label: () => m['devices.Location']() },
		{ key: 'network_name', label: () => m['devices.Network'](), sortable: true },
		{ key: 'last_scanned_at', label: () => m['devices.Last Scanned'](), sortable: true },
		{ key: 'last_scan_rtt_ms', label: () => m['devices.RTT']() },
		{ key: 'inferred_type', label: () => m['devices.Inferred Type']() },
		{ key: 'os', label: () => m['devices.OS']() },
		{ key: 'serial_number', label: () => m['devices.Serial Number']() },
		{ key: 'purchase_date', label: () => m['devices.Purchase Date']() },
		{ key: 'purpose', label: () => m['devices.Purpose']() }
	];
	// The list defaults to a lean row (status/name/type/IP are fixed columns, plus
	// network here). Vendor/hostname/location moved into the expand-panel's device
	// summary: they're still available as columns via the ColumnPicker for users
	// who want them back in the row.
	const defaultColumns = ['network_name'];
	let selectedColumnKeys = $state(new Set<string>(defaultColumns));

	// lifecycleLabel / lifecycleBadge (#669): the ledger state's localized
	// label + a muted chip. Literal m[] calls per key (paraglide's m is typed
	// per key, same convention as presetLabel in scan-tasks).
	function lifecycleLabel(state: string): string {
		switch (state) {
			case 'in_use': return m['devices.Lifecycle In Use']();
			case 'spare': return m['devices.Lifecycle Spare']();
			case 'repair': return m['devices.Lifecycle Repair']();
			case 'lent': return m['devices.Lifecycle Lent']();
			case 'retired': return m['devices.Lifecycle Retired']();
			default: return state;
		}
	}
	// Badge only for the NON-default states: in_use is the population norm,
	// a chip on every row would be noise. Colors stay in the muted/neutral
	// family so they don't fight the tag chips.
	function lifecycleBadge(state: unknown): string {
		const s = String(state ?? '');
		if (!s || s === 'in_use') return '';
		const cls =
			s === 'repair' ? 'text-warning bg-warning/10' :
			s === 'retired' ? 'text-text-muted bg-border' :
			s === 'lent' ? 'text-accent bg-accent/10' :
			'text-success bg-success/10'; // spare
		return `<span class="ml-1 inline-block rounded-full px-1.5 py-0.5 text-[10px] font-medium align-middle ${cls}" title="${m['devices.Lifecycle']()}">${escapeHtml(lifecycleLabel(s))}</span>`;
	}

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
				if (!mac) return '-';
				// A locally-administered (U/L bit set) MAC was assigned locally,
				// not drawn from an IEEE OUI block. The bit is neutral fact: it
				// cannot tell privacy randomization from a locally fixed setting;
				// so this is an observability badge, not an identity verdict.
				// Mirrors the heuristic-type "?" inline marker.
				const laa = sa?.mac_is_locally_administered === true;
				const laaBadge = laa
					? `<span class="ml-0.5 text-warning/80" title="${m['devices.Locally Administered MAC Hint']()}">⚠</span>`
					: '';
				return `<span class="font-mono text-xs">${escapeHtml(mac)}</span>${laaBadge}`;
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
				const t = ((sa as { last_scanned_at?: string } | undefined)?.last_scanned_at) || (row.last_scanned_at as string | null);
				return escapeHtml(formatDateTime(t));
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
				// title carries the offline duration (offline_since → "Nd Nh") so
				// hovering the dot shows how long the device has been down without
				// a round-trip: offline_since is already in the list payload.
				const title = escapeAttr(statusDotTitle(s, row));
				return `<span class="inline-block w-2.5 h-2.5 rounded-full ${statusDotClass(s)}" title="${title}"></span>`;
			}
		},
		{
			// Device name is a link to the full detail page: the detail page is
			// where every scan_attributes field lives, so this is the primary entry.
			key: 'name',
			label: m['devices.Device Name'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const id = row.id;
				const name = escapeHtml(String(row.name ?? ''));
				// Dictionary tag chips (#665) ride under the name.
				const tags = (row.dictionary_tags as { key: string; name: string; color: string; builtin: boolean }[] | undefined) ?? [];
				const tagHtml = tags
					.map((t) => {
						const color = /^#[0-9a-fA-F]{3,8}$/.test(t.color || '') ? t.color : '#2563eb';
						return `<span class="ml-1 inline-block rounded-full px-1.5 py-0.5 text-[10px] font-medium align-middle" style="background:${color}22;color:${color}">${escapeHtml(tagDisplayName(t))}</span>`;
					})
					.join('');
				const lcHtml = lifecycleBadge(row.lifecycle_state);
				return `<button data-action="detail" data-id="${id}" class="text-left font-medium text-primary hover:underline" title="${m['devices.View Details']()}">${name}</button>${lcHtml}${tagHtml}`;
			}
		},
		{
			key: 'type',
			label: m['devices.Type'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const t = String(row.type ?? 'other');
				const label = typeLabel[t] || typeLabel['other']!;
				// A device's type is only as trustworthy as its evidence. Types
				// derived from protocol evidence (SNMP sysObjectID, RTSP/ONVIF,
				// mDNS) are authoritative; types inferred from a hostname keyword
				// (device_types.yaml) are guesses that any DHCP client could
				// spoof. Mark heuristic-confidence types with a dimmed "?" so the
				// user can tell which classifications to trust. scan_attributes
				// rides in row.scan_attributes; legacy rows have no source key.
				const sa = row.scan_attributes as { inferred_type_source?: string } | undefined;
				if (sa?.inferred_type_source === 'heuristic') {
					return `<span class="text-muted" title="${m['devices.Inferred Type Hint']()}">${escapeHtml(label)}<span class="ml-0.5 text-muted/60">?</span></span>`;
				}
				return escapeHtml(label);
			}
		},
		{
			key: 'ip_address',
			label: m['devices.IP Address'](),
			sortable: true,
			render: (row: Record<string, unknown>) => {
				const ip = row.ip_address ? String(row.ip_address) : '';
				// #737 presentation: a parked row (its address was claimed by
				// another device, e.g. a randomized-MAC client) has no live IP —
				// the raw '#park:<id>' sentinel told the user nothing.
				if (ip.startsWith('#park:')) {
					return `<span class="text-xs text-muted" title="${m['devices.Parked Hint']()}">${m['devices.Parked Badge']()}</span>`;
				}
				return ip
					? `<span class="font-mono">${escapeHtml(ip)}</span>`
					: '-';
			}
		},
		// Optional (user-toggleable) columns: included only if selected in the
		// ColumnPicker. Order follows the optionalColumns definition so toggling
		// keeps a stable, predictable column layout. sortable (where present) is
		// forwarded so the header renders the sort affordance and the click routes
		// through the server-side sort callback.
		...optionalColumns
			.filter((c) => selectedColumnKeys.has(c.key))
			.map((c) => ({
				key: c.key,
				label: c.label(),
				sortable: c.sortable ?? false,
				render: (row: Record<string, unknown>) => renderOptionalColumn(c.key, row)
			})),
		{
			key: 'actions',
			label: m['common.Actions'](),
			render: (row: Record<string, unknown>) => {
				const id = row.id;
				const name = escapeAttr(String(row.name ?? ''));
				// #379 read-only fence: mirrored devices (agent/peer network)
				// hide edit/link/delete - writes are rejected server-side anyway,
				// the UI just doesn't offer them.
				if (isRemoteDevice(row as Pick<Device, 'network_id'>)) {
					// Mirror freshness (#557): an agent/peer segment whose owner
					// stopped reporting swaps the neutral Remote badge for a
					// stale one (amber, last report in the tooltip).
					const stale = isStaleDevice(row as Pick<Device, 'network_id'>);
					const staleTitle = stale && (row as { network_id?: number | null }).network_id != null
						? m['devices.Mirror Stale Desc']({ t: formatDateTime(agentLastUsedByID.get((row as { network_id: number }).network_id) ?? null) })
						: m['devices.Remote Network Desc']();
					const badge = stale
						? `<span class="text-xs px-1.5 py-0.5 rounded bg-warning/15 text-warning" title="${escapeAttr(staleTitle)}">${m['devices.Mirror Stale']()}</span>`
						: `<span class="text-xs px-1.5 py-0.5 rounded bg-bg-hover text-text-muted" title="${m['devices.Remote Network Desc']()}">${m['devices.Remote Network']()}</span>`;
					return `<div class="flex gap-2 items-center">`
						+ `<button data-action="detail" data-id="${id}" class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10">${m['devices.Details']()}</button>`
						+ badge
						+ `</div>`;
				}
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
			// Navigate to the full detail page: the only place every device
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
			const device = devices.find((d) => d.id === id) ?? { id, name };
			openDelete(device);
		}
	}

	// Keyboard equivalent for the event-delegation wrapper. The rendered
	// <button>/<input> elements are natively focusable + Enter/Space fires a
	// click that bubbles to handleTableClick: but the wrapper div itself also
	// needs to forward Enter/Space so keyboard-only users can activate actions
	// without a mouse. (#167 / #174: devices page uses real <button> elements
	// via {@html} render, unlike the 8 pages migrated to cell snippets; this
	// keyboard handler closes the remaining a11y gap without the cell snippet
	// that triggered the Svelte 5 flush stall.)
	function handleTableKeydown(e: KeyboardEvent) {
		if (e.key !== 'Enter' && e.key !== ' ') return;
		const target = e.target as HTMLElement;
		const interactive = target.closest('[data-action]') as HTMLElement | null;
		if (!interactive) return;
		e.preventDefault();
		handleTableClick({ target: interactive } as unknown as MouseEvent);
	}
</script>

<div class="p-6">
	<!-- Header -->
	<div class="flex items-center justify-between mb-6 gap-4 flex-wrap">
		<div class="flex items-center gap-3 flex-wrap">
			<h2 class="text-2xl font-bold text-primary">{m['devices.Device List']()}</h2>
			<!-- View toggle: list (table) vs topology (radial graph). Pill style to
			     distinguish from the route-level sub-tab bar above (which is
			     underline-style). Topology view reuses the same network filter. -->
			<div class="flex border border-border rounded-lg overflow-hidden text-sm" role="group" aria-label={m['navigation.Topology']()}>
				<button
					onclick={() => switchView('list')}
					aria-pressed={viewMode === 'list'}
					class="px-3 py-1.5 flex items-center gap-1.5 transition-colors
						{viewMode === 'list' ? 'bg-primary text-text-inverse' : 'text-text-muted hover:text-text hover:bg-surface-2'}"
				>
					<List class="w-4 h-4" />
					<span class="hidden sm:inline">{m['devices.View List']()}</span>
				</button>
				<button
					onclick={() => switchView('topology')}
					aria-pressed={viewMode === 'topology'}
					class="px-3 py-1.5 flex items-center gap-1.5 border-l border-border transition-colors
						{viewMode === 'topology' ? 'bg-primary text-text-inverse' : 'text-text-muted hover:text-text hover:bg-surface-2'}"
				>
					<Share2 class="w-4 h-4" />
					<span class="hidden sm:inline">{m['devices.View Topology']()}</span>
				</button>
			</div>
		</div>
		{#if viewMode === 'list'}
			<div class="flex gap-2">
				<button onclick={openCreate} class="btn btn-primary">
					<Plus class="w-4 h-4" />
					{m['devices.Create Device']()}
				</button>
			</div>
		{/if}
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

	{#if viewMode === 'list'}
	<!-- Compact filter bar (#UI-compact): status pills (the primary
	     troubleshooting axis, with live counts) + one popover holding the four
	     secondary axes + removable chips for whatever is active + search +
	     actions. One ~48px row replaces ~240px of stacked full-width selects,
	     so the device table starts in the first viewport. -->
	<div class="flex flex-wrap gap-2 mb-4 items-center" data-filter-bar>
		<div class="flex items-center gap-1" role="group" aria-label={m['devices.All Status']()} data-status-pills>
			{#each [
				{ v: '', label: m['devices.All Status'](), n: Object.values(stats.by_status).reduce((a, b) => a + b, 0) },
				{ v: 'online', label: m['devices.Online'](), n: stats.by_status?.online ?? 0 },
				{ v: 'offline', label: m['devices.Offline'](), n: stats.by_status?.offline ?? 0 },
				{ v: 'unknown', label: m['devices.Unknown'](), n: stats.by_status?.unknown ?? 0 }
			] as s (s.v)}
				<button
					type="button"
					onclick={() => setStatusFilter(s.v)}
					aria-pressed={statusFilter === s.v}
					class="rounded-full border px-2.5 py-1 text-xs transition-colors {statusFilter === s.v
						? s.v === 'offline'
							? 'border-error/50 bg-error/10 text-error'
							: s.v === 'online'
								? 'border-success/50 bg-success/10 text-success'
								: 'border-primary/50 bg-primary/10 text-primary'
						: 'border-border text-text-muted hover:text-text'}"
				>{s.label}{#if s.v !== ''} · {s.n}{/if}</button>
			{/each}
		</div>

		<!-- Secondary axes (type / lifecycle / network / tag) in one popover. -->
		<div class="relative">
			<button
				type="button"
				onclick={() => (filterMenuOpen = !filterMenuOpen)}
				aria-expanded={filterMenuOpen}
				aria-haspopup="menu"
				data-filter-menu-btn
				class="inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs transition-colors {filterMenuOpen || secondaryActiveCount > 0
					? 'border-primary/50 bg-primary/10 text-primary'
					: 'border-border text-text-muted hover:text-text'}"
			>
				{m['devices.Filter Menu']()}{#if secondaryActiveCount > 0} · {secondaryActiveCount}{/if}
				<ChevronDown class="w-3 h-3 transition-transform {filterMenuOpen ? 'rotate-180' : ''}" />
			</button>
			{#if filterMenuOpen}
				<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
				<div class="fixed inset-0 z-10" onclick={() => (filterMenuOpen = false)} role="presentation"></div>
				<div
					class="absolute left-0 top-full mt-1 z-20 w-72 max-w-[85vw] rounded-lg border border-border bg-surface p-3 space-y-2.5"
					style="box-shadow: var(--shadow-md);"
					role="menu"
					data-filter-menu
				>
					<div>
						<label class="block text-xs text-muted mb-1">{m['devices.All Types']()}</label>
						<select bind:value={typeFilter} onchange={applyFilters} class="input !w-full">
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
							<option value="phone">{m['devices.Phone']()}</option>
							<option value="printer">{m['devices.Printer']()}</option>
							<option value="other">{m['devices.Other']()}</option>
						</select>
					</div>
					<div>
						<!-- Lifecycle filter (#669): exact server-side match. -->
						<label class="block text-xs text-muted mb-1">{m['devices.All Lifecycles']()}</label>
						<select bind:value={lifecycleFilter} onchange={applyFilters} class="input !w-full">
							<option value="">{m['devices.All Lifecycles']()}</option>
							<option value="in_use">{m['devices.Lifecycle In Use']()}</option>
							<option value="spare">{m['devices.Lifecycle Spare']()}</option>
							<option value="repair">{m['devices.Lifecycle Repair']()}</option>
							<option value="lent">{m['devices.Lifecycle Lent']()}</option>
							<option value="retired">{m['devices.Lifecycle Retired']()}</option>
						</select>
					</div>
					<div>
						<label class="block text-xs text-muted mb-1">{m['devices.All Networks']()}</label>
						{#if networks.length > 0}
							<select bind:value={networkFilter} onchange={applyFilters} class="input !w-full">
								<option value="">{m['devices.All Networks']()}</option>
								{#each networks as net}
									<option value={net.id}>{net.name}{net.cidr ? ` (${net.cidr})` : ''}</option>
								{/each}
							</select>
							<!-- Filtering into a stale agent/peer segment (#557): say so
							     inside the popover, or frozen data reads like a bug. -->
							{#if networkFilter && staleNetworkIDs.has(Number(networkFilter))}
								<p
									class="mt-1 text-xs text-warning"
									title={m['devices.Mirror Stale Desc']({ t: formatDateTime(agentLastUsedByID.get(Number(networkFilter)) ?? null) })}
								>⚠ {m['devices.Mirror Stale']()}</p>
							{/if}
						{:else if networksError}
							<!-- The /networks fetch failed: show a small indicator instead of
							     silently dropping the filter (which would look like "no networks"). -->
							<p class="text-xs text-warning" title={m['devices.Networks Load Failed']()}>
								{m['devices.Networks Load Failed']()}
							</p>
						{:else}
							<p class="text-xs text-muted">…</p>
						{/if}
					</div>
					{#if tagDictionary.length > 0}
						<!-- Tag filter (#665): dictionary-driven, server-side. -->
						<div>
							<label class="block text-xs text-muted mb-1">{m['devices.All Tags']()}</label>
							<select bind:value={tagFilter} onchange={applyFilters} class="input !w-full">
								<option value="">{m['devices.All Tags']()}</option>
								{#each tagDictionary as tag (tag.id)}
									<option value={tag.id}>{tag.name}</option>
								{/each}
							</select>
						</div>
					{/if}
				</div>
			{/if}
		</div>

		<!-- Active secondary filters as removable chips (one per axis). -->
		{#each activeSecondaryFilters as f (f.key)}
			<button
				type="button"
				onclick={f.clear}
				data-active-filter-chip="{f.key}"
				class="inline-flex items-center gap-1 rounded-full border border-primary/40 bg-primary/5 px-2.5 py-1 text-xs text-primary hover:bg-primary/10 transition-colors"
				title={m['common.Clear']()}
			>{f.label} ✕</button>
		{/each}

		<!-- Server-side search (name / ip / mac / serial). 400ms debounce. -->
		<div class="relative flex-1 min-w-[160px] max-w-xs">
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
			onclick={() => {
				// #UI-dates: opening the advanced panel prefills the created-range
				// inputs with today (last-hour default on date granularity) — no
				// bare yyyy/mm/dd placeholders. Display-only: the list changes
				// only when the explicit 筛选 click applies them, and inputs stay
				// consistent with what the list then shows.
				showAdvanced = !showAdvanced;
				if (showAdvanced && !dateFrom && !dateTo) {
					const r = defaultRange('date', 3600_000);
					dateFrom = r.from;
					dateTo = r.to;
				}
			}}
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

		<!-- Export dropdown (click-toggle: accessible to keyboard/touch) -->
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
					{m['devices.Selected Count']({ count: selectedIds.size })}
				</span>
			</div>
			<div class="flex-1"></div>
			{#if tagDictionary.length > 0}
				<button
					onclick={() => { batchTagID = String(tagDictionary[0].id); batchTagOpen = true; }}
					class="btn btn-secondary text-xs py-1.5"
				>
					{m['devices.Batch Tag']()}
				</button>
			{/if}
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
					aria-expanded={batchStatusOpen}
					aria-haspopup="menu"
				>
					{m['devices.Batch Update Status']()}
					<ChevronDown class="w-3 h-3" />
				</button>
				{#if batchStatusOpen}
					<!-- svelte-ignore a11y_no_static_element_interactions a11y_click_events_have_key_events -->
					<div class="fixed inset-0 z-10" onclick={() => (batchStatusOpen = false)} role="presentation"></div>
					<div class="absolute right-0 top-full mt-1 bg-surface border border-border rounded-lg z-20 min-w-[140px]" style="box-shadow: var(--shadow-md);" role="menu">
						{#each ['online', 'offline', 'unknown'] as status}
							<button
								onclick={() => { pendingBatchStatus = status; batchStatusValue = status; batchStatusOpen = false; batchStatusConfirmOpen = true; }}
								role="menuitem"
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

	{#snippet expandedRow(row: Record<string, unknown>)}
		{@const device = devices.find((d) => d.id === row.id)}
		{@const sa = device?.scan_attributes}
		<div class="border-t border-border bg-bg/50">
			{#if device}
				{@const t = String(device.type ?? 'other')}
				{@const statusStr = String(device.status ?? 'unknown')}
				<!-- Header: lean context strip. The row already shows the name, so the
				     expand header surfaces the OTHER dimensions: IP, type badge,
				     status badge: instead of repeating the name. -->
				<div class="flex items-center gap-3 px-4 py-2 bg-surface/50 border-b border-border flex-wrap">
					<button
						onclick={() => (expandedDeviceId = null)}
						class="p-1 rounded hover:bg-surface-2 transition-colors text-muted"
						aria-label={m['devices.Collapse Row']()}
					>
						<ChevronRight class="w-3.5 h-3.5 rotate-90" />
					</button>
					{#if device.ip_address && !String(device.ip_address).startsWith('#park:')}
						<span class="font-mono text-xs text-muted">{device.ip_address}</span>
					{/if}
					<span class="text-xs px-1.5 py-0.5 rounded bg-accent/10 text-accent">{typeLabel[t] || typeLabel['other']!}</span>
					<span class="text-xs inline-flex items-center gap-1.5 text-muted">
						<span class="inline-block w-2 h-2 rounded-full {statusDotClass(statusStr)}"></span>
						{statusStr === 'online' ? m['devices.Online']() : statusStr === 'offline' ? m['devices.Offline']() : m['devices.Unknown']()}
					</span>
				</div>

				<!-- Device summary: the identity fields that used to crowd the list row
				     (vendor/hostname/location/model/mac/os/inferred type/last scanned).
				     Drawn from scan_attributes where the engine writes the rich data,
				     falling back to top-level fields. Missing fields are omitted so a
				     sparse device doesn't show a wall of '-'. One glance here spares a
				     trip to the detail page for routine "what is this?" questions. -->
				<div class="px-4 py-3 border-b border-border">
					<div class="text-xs font-medium text-muted uppercase tracking-wide mb-2">{m['devices.Device Summary']()}</div>
					<div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-x-4 gap-y-2 text-xs">
						{#if (sa?.vendor || device.brand)}
							<summary class="flex flex-col gap-0.5 min-w-0">
								<span class="text-muted">{m['devices.Vendor']()}</span>
								<span class="text-text truncate">{sa?.vendor || device.brand}</span>
							</summary>
						{/if}
						{#if sa?.oui_vendor}
							<summary class="flex flex-col gap-0.5 min-w-0" title={sa?.oui_prefix ? `IEEE block ${sa.oui_prefix}` : ''}>
								<span class="text-muted">{m['devices.OUI Vendor']()}</span>
								<span class="font-mono text-text truncate">{sa?.oui_vendor}</span>
							</summary>
						{/if}
						{#if device.model}
							<summary class="flex flex-col gap-0.5 min-w-0">
								<span class="text-muted">{m['devices.Model']()}</span>
								<span class="text-text truncate">{device.model}</span>
							</summary>
						{/if}
						{#if sa?.hostname}
							<summary class="flex flex-col gap-0.5 min-w-0">
								<span class="text-muted">{m['devices.Hostname']()}</span>
								<span class="font-mono text-text truncate">{sa.hostname}</span>
							</summary>
						{/if}
						{#if (sa?.mac || device.mac_address)}
							<summary class="flex flex-col gap-0.5 min-w-0">
								<span class="text-muted">{m['devices.MAC Address']()}</span>
								<span class="font-mono text-text truncate inline-flex items-center gap-1.5">
									{sa?.mac || device.mac_address}
									{#if sa?.mac_is_locally_administered}
										<span class="badge badge-warning shrink-0" title={m['devices.Locally Administered MAC Hint']()}>{m['scanfields.Locally Administered MAC']()}</span>
									{/if}
								</span>
							</summary>
						{/if}
						{#if sa?.os}
							<summary class="flex flex-col gap-0.5 min-w-0">
								<span class="text-muted">{m['devices.OS']()}</span>
								<span class="text-text truncate">{sa.os}</span>
							</summary>
						{/if}
						{#if device.location}
							<summary class="flex flex-col gap-0.5 min-w-0">
								<span class="text-muted">{m['devices.Location']()}</span>
								<span class="text-text truncate">{device.location}</span>
							</summary>
						{/if}
						{#if sa?.inferred_type}
							<summary class="flex flex-col gap-0.5 min-w-0">
								<span class="text-muted">{m['devices.Inferred Type']()}</span>
								<span class="text-text truncate inline-flex items-center gap-1">
									{sa.inferred_type}
									{#if sa.inferred_type_source === 'heuristic'}
										<span class="text-muted/60" title={m['devices.Inferred Type Hint']()}>?</span>
									{:else if sa.inferred_type_source === 'protocol'}
										<span class="text-success text-[0.65rem] font-medium uppercase">{m['devices.Inferred Type Protocol']()}</span>
									{/if}
								</span>
							</summary>
						{/if}
						{#if (sa?.last_scanned_at || device.last_scanned_at)}
							<summary class="flex flex-col gap-0.5 min-w-0">
								<span class="text-muted">{m['devices.Last Scanned']()}</span>
								<span class="text-text truncate">{formatDateTime(sa?.last_scanned_at || device.last_scanned_at)}</span>
							</summary>
						{/if}
					</div>
				</div>

				<!-- Heartbeat section. -->
				<div class="px-4 py-2 flex items-center gap-2 border-b border-border">
					<span class="text-xs font-medium text-muted uppercase tracking-wide">{m['heartbeat.Heartbeat']()}</span>
				</div>
			{/if}
			<HeartbeatExpandableRow deviceId={row.id as number} expanded={true} />
		</div>
	{/snippet}

	<!-- Loading skeleton -->
	{#if loading}
		<PageSkeleton type="table" />
	{:else}
		<!-- Device table with expandable heartbeat rows.
		     svelte-ignore a11y_no_static_element_interactions -- event delegation wrapper; keyboard handled by onkeydown + native <button> focus -->
		<div onclick={handleTableClick} onkeydown={handleTableKeydown}>
			<DataTable
				{columns}
				rows={devices as unknown as Record<string, unknown>[]}
				rowClassName={(row) => isStaleDevice(row as Pick<Device, 'network_id'>) ? 'opacity-60' : ''}
			emptyTitle={m['devices.No Devices']()}
			emptyDescription={m['devices.No Devices Desc']()}
			emptyAction={() => goto('/devices/scan-tasks')}
			emptyActionLabel={m['devices.Scan Network']()}
				expandedRowId={expandedDeviceId}
				expandedContent={expandedRow}
				externalSortKey={sortKey || null}
				externalSortDirection={sortKey ? sortDir : 'none'}
				onSortChange={onSortChange}
				serverFilterQuery={searchQuery}
			/>
		</div>

		<!-- Pagination -->
		<Pagination {total} {limit} {offset} onPageChange={(o) => { offset = o; expandedDeviceId = null; selectedIds = new Set(); fetchDevices(); }} onPageSizeChange={onPageSizeChange} />
	{/if}
	{:else}
		<!-- Topology view: radial L2 graph. Shares the network filter (above
		     in the stats row) so picking a network scopes the graph too. -->
		<DeviceTopologyView networkId={networkFilter} />
	{/if}
</div>

<!-- Create/Edit Modal: the form lives in the shared DeviceEditModal component
     (also used by the device detail page). This page toggles it open with a
     target device (null ⇒ create) and refreshes the list on save. -->
<DeviceEditModal bind:open={editOpen} device={editTarget} onSaved={fetchDevices} />

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

<!-- Batch tagging (#665): pick a dictionary tag, apply to all selected. -->
<Modal bind:open={batchTagOpen} title={m['devices.Batch Tag']()} onClose={() => { batchTagOpen = false; }}>
	<div class="space-y-4">
		<p class="text-sm text-muted">{m['devices.Batch Tag Desc']({ count: selectedIds.size })}</p>
		<select bind:value={batchTagID} class="input">
			{#each tagDictionary as tag (tag.id)}
				<option value={tag.id}>{tag.name}</option>
			{/each}
		</select>
		<div class="flex justify-end gap-2">
			<button class="btn btn-secondary" onclick={() => { batchTagOpen = false; }}>{m['common.Cancel']()}</button>
			<button class="btn btn-primary" disabled={batchTagBusy || !batchTagID} onclick={confirmBatchTag}>
				{m['common.Confirm']()}
			</button>
		</div>
	</div>
</Modal>

<!-- Batch status-update confirmation: the dropdown stages the chosen status
     here, and only this confirm fires the mutation. Stops an accidental
     click from bulk-flipping the selected devices (#150). -->
<ConfirmDialog
	bind:open={batchStatusConfirmOpen}
	title={m['devices.Batch Update Status']()}
	message={m['devices.Batch Update Status Confirm']({ count: selectedIds.size, status: pendingBatchStatus ? statusLabel(pendingBatchStatus) : '' })}
	confirmLabel={m['common.Confirm']()}
	onConfirm={confirmBatchStatus}
	onCancel={() => { pendingBatchStatus = null; }}
/>

<!-- CSV Import Modal -->
<Modal bind:open={importOpen} title={m['devices.Import Devices']()} maxWidth="48rem" onClose={() => { importOpen = false; }}>
	<div class="space-y-4">
		<div>
			<label class="block text-xs text-muted mb-1">{m['devices.Import CSV']()}</label>
			<input type="file" accept=".csv" onchange={handleCsvFileSelect}
				class="input" />
			<p class="text-xs text-muted mt-1">{m['devices.CSV Format Help']()}</p>
		</div>

		{#if csvPreviewRows.length > 0}
			{@const invalidIpCount = csvPreviewRows.filter((r) => !isValidIP(r.ip)).length}
			<div>
				<h4 class="text-sm font-medium text-text mb-2">{m['devices.Import Preview']()} ({csvPreviewRows.length} rows)</h4>
				{#if invalidIpCount > 0}
					<p class="text-xs text-error mb-2">
						{m['devices.Invalid IP Format']()}: {invalidIpCount}
					</p>
				{/if}
				<div class="overflow-x-auto border border-border rounded-lg max-h-60">
					<table class="w-full text-sm">
						<thead>
							<tr class="bg-surface border-b border-border text-left text-xs text-muted">
								<th class="px-3 py-2">{m['devices.CSV Col IP']()}</th>
								<th class="px-3 py-2">{m['devices.Device Name']()}</th>
								<th class="px-3 py-2">{m['devices.Type']()}</th>
							</tr>
						</thead>
						<tbody>
							{#each csvPreviewRows as row, i (i)}
								<tr class="border-b border-border last:border-b-0 hover:bg-border/30">
									<td class="px-3 py-2 font-mono {isValidIP(row.ip) ? '' : 'text-error'}" title={isValidIP(row.ip) ? undefined : m['devices.Invalid IP Format']()}>
										{row.ip}
									</td>
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
								{doc.type === 'url' ? m['documents.URL']() : m['common.File']()}
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
