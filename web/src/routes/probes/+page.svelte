<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later; see LICENSE for the full text. A commercial
  license is available for use cases the AGPL does not accommodate; see
  LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { api } from '$lib/api/client';
	import { auth } from '$lib/stores/auth';
	import { m } from '$lib/i18n-paraglide';
	import { onMount, onDestroy } from 'svelte';
	import { getErrorMessage } from '$lib/utils/error';
	import { html, escapeAttr, formatDateTime as formatTime } from '$lib/utils/index';
	import { probeTargetSchema, validateField, validateForm } from '$lib/utils/validation';
	import { addToast } from '$lib/stores/toast';

	import Modal from '$lib/components/Modal.svelte';
	import ConfirmDialog from '$lib/components/ConfirmDialog.svelte';
	import DataTable from '$lib/components/DataTable.svelte';
	import PageSkeleton from '$lib/components/PageSkeleton.svelte';
	import EmptyState from '$lib/components/EmptyState.svelte';
	import CertificateModal from '$lib/components/CertificateModal.svelte';
	import Chart from '$lib/components/Chart.svelte';
	import type { EChartsOption } from '$lib/charts/echarts';
	import { Activity as ActivityIcon, ChevronDown, Info, Search } from '@lucide/svelte';

	import type {
		ProbeTarget,
		ProbeTargetListResponse,
		ProbeResult,
		ProbeResultListResponse,
		ProbeTriggerResponse,
		ProbeVantageLatest,
		ProbeOptions,
		ProbeQualityReport,
		ProbeQualityCategory,
		ProbeQualityGroup,
		ProbeQualityVantage,
		ProbeQualityTrack,
		TLSPortCerts,
		DeviceCertificatesResponse,
		Network
	} from '$lib/types';
	import { certDayDelta } from '$lib/utils/certs';
	import { probeCategory, PROBE_CATEGORIES } from '$lib/utils/probes';
	import type { ProbeCategory } from '$lib/utils/probes';

	// --- State ---
	let targets = $state<ProbeTarget[]>([]);
	let loading = $state(true);
	let error = $state('');
	// Registered agent ids (networks.agent_id): options for the vantage
	// selector (#277). Fetched best-effort; empty = center-only deployment.
	let agentIds = $state<string[]>([]);
	// Leaf-cert expiry per target id (for the table's certificate badge). Fetched
	// from /certificates after each list refresh: only tls/http targets have any.
	let certExpiry = $state<Record<number, string>>({});

	// --- Batch operations (#276): multi-select + toolbar actions -------------
	let selectedIds = $state<Set<number>>(new Set());
	let batchBusy = $state(false);

	function toggleSelected(id: number) {
		const next = new Set(selectedIds);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		selectedIds = next;
	}

	// Per-section select-all (#613): each category header's checkbox works on
	// that section's visible rows only; the global batch toolbar above keeps
	// operating on the combined selection across sections.
	function sectionAllSelected(sec: CategorySection): boolean {
		return sec.rows.length > 0 && sec.rows.every((t) => selectedIds.has(t.id));
	}

	function toggleSelectSection(sec: CategorySection) {
		const ids = sec.rows.map((t) => t.id);
		if (ids.length === 0) return;
		const clear = ids.every((id) => selectedIds.has(id));
		const next = new Set(selectedIds);
		for (const id of ids) {
			if (clear) next.delete(id);
			else next.add(id);
		}
		selectedIds = next;
	}

	async function runBatch(op: (t: ProbeTarget) => Promise<unknown>, label: string) {
		const list = targets.filter((t) => selectedIds.has(t.id));
		if (list.length === 0) return;
		batchBusy = true;
		let ok = 0;
		await Promise.all(
			list.map(async (t) => {
				try {
					await op(t);
					ok++;
				} catch (err) {
					addToast('error', `${t.name}: ${getErrorMessage(err)}`);
				}
			})
		);
		batchBusy = false;
		selectedIds = new Set();
		addToast(ok === list.length ? 'success' : 'warning', `${label}: ${ok}/${list.length}`);
		fetchTargets();
	}

	const batchEnable = () => runBatch((t) => api.put(`/probe-targets/${t.id}`, { enabled: true }), m['probes.Batch Enable']());
	const batchDisable = () => runBatch((t) => api.put(`/probe-targets/${t.id}`, { enabled: false }), m['probes.Batch Disable']());

	function batchInterval() {
		const v = prompt(m['probes.Batch Interval Prompt'](), '60');
		const n = Number(v);
		if (!v || !Number.isFinite(n) || n < 10 || n > 86400) {
			if (v !== null) addToast('error', m['probes.Batch Interval Invalid']());
			return;
		}
		runBatch((t) => api.put(`/probe-targets/${t.id}`, { interval_seconds: n }), `${m['probes.Batch Interval']()}=${n}s`);
	}

	function batchDelete() {
		if (!confirm(m['probes.Batch Delete Confirm']({ count: selectedIds.size }))) return;
		runBatch((t) => api.delete(`/probe-targets/${t.id}`), m['common.Delete']());
	}

	// --- Module overview cards (#276): per-module success rate + avg latency --
	interface ModuleStat {
		module: string;
		total: number;
		enabled: number;
		successRate: number | null;
		avgLatency: number | null;
	}
	// All selectable modules (#605 adds dns). Drives both the overview cards
	// and the create/edit form's module select.
	const MODULES = ['http', 'tls', 'tcp', 'icmp', 'dns'] as const;
	type ProbeModule = (typeof MODULES)[number];
	// A target's effective latest outcome: the newest row across vantage
	// tracks when any exist (agent-vantage plans never write last_*), else the
	// denormalized center fields. Ties on checked_at prefer the center track.
	function latestOverall(t: ProbeTarget): { status: string; latency_ms: number } | null {
		const tracks = t.vantage_latest ?? [];
		if (tracks.length > 0) {
			let best = tracks[0];
			for (const tr of tracks) {
				if (tr.checked_at > best.checked_at || (tr.checked_at === best.checked_at && tr.vantage === 'center')) {
					best = tr;
				}
			}
			return { status: best.status, latency_ms: best.latency_ms };
		}
		if (!t.last_status) return null;
		return { status: t.last_status, latency_ms: t.last_latency_ms };
	}
	const moduleStats = $derived.by<ModuleStat[]>(() => {
		return MODULES.map((mod) => {
			const rows = targets.filter((t) => t.module === mod);
			const ran = rows
				.map(latestOverall)
				.filter((v): v is { status: string; latency_ms: number } => v !== null);
			const ok = ran.filter((v) => v.status === 'success');
			const lat = ok.map((v) => v.latency_ms).filter((v) => v > 0);
			return {
				module: mod,
				total: rows.length,
				enabled: rows.filter((t) => t.enabled).length,
				successRate: ran.length ? Math.round((ok.length / ran.length) * 100) : null,
				avgLatency: lat.length ? lat.reduce((a, b) => a + b, 0) / lat.length : null
			};
		});
	});

	// --- Category sections (#613): the list groups into three collapsible
	// sections in a fixed order — LAN (device-bound / auto targets), external
	// business (manual, unbound), egress quality (source=system matrix). The
	// derivation lives in $lib/utils/probes so it stays aligned with the
	// backend's TargetCategory.
	interface CategorySection {
		key: ProbeCategory;
		label: string;
		// Rows visible in this section after the page-level search; the
		// summary always describes the WHOLE category so a filter can't mask
		// its health.
		rows: ProbeTarget[];
		summary: { enabled: number; ok: number; bad: number };
	}

	// One page-level search box (replaces the single table's built-in one):
	// it applies within every section; a section with no match hides itself.
	let searchQuery = $state('');

	function matchesSearch(t: ProbeTarget): boolean {
		if (!searchQuery) return true;
		const q = searchQuery.toLowerCase();
		return t.name.toLowerCase().includes(q) || t.target.toLowerCase().includes(q);
	}

	function categoryLabel(key: ProbeCategory): string {
		switch (key) {
			case 'lan':
				return m['probes.Category LAN']();
			case 'external':
				return m['probes.Category External']();
			default:
				return m['probes.Category Quality']();
		}
	}

	function categoryEmptyHint(key: ProbeCategory): string {
		switch (key) {
			case 'lan':
				return m['probes.Section Empty LAN']();
			case 'external':
				return m['probes.Section Empty External']();
			default:
				return m['probes.Section Empty Quality']();
		}
	}

	const sections = $derived.by<CategorySection[]>(() => {
		return PROBE_CATEGORIES.map((key) => {
			const all = targets.filter((t) => probeCategory(t) === key);
			let ok = 0;
			let bad = 0;
			for (const t of all) {
				const latest = latestOverall(t);
				if (!latest) continue;
				if (latest.status === 'success') ok++;
				else bad++;
			}
			return {
				key,
				label: categoryLabel(key),
				rows: all.filter(matchesSearch),
				summary: { enabled: all.filter((t) => t.enabled).length, ok, bad }
			};
		});
	});

	// Collapsed/expanded per section, persisted so the choice survives reloads
	// (same localStorage pattern as ColumnPicker). Default: all expanded.
	const SECTIONS_STORAGE_KEY = 'mibee.probes.sections';
	const SECTIONS_DEFAULT: Record<ProbeCategory, boolean> = { lan: true, external: true, quality: true };

	function loadSectionToggles(): Record<ProbeCategory, boolean> {
		if (typeof localStorage === 'undefined') return { ...SECTIONS_DEFAULT };
		try {
			const raw = localStorage.getItem(SECTIONS_STORAGE_KEY);
			if (raw) return { ...SECTIONS_DEFAULT, ...(JSON.parse(raw) as Partial<Record<ProbeCategory, boolean>>) };
		} catch {
			// Corrupt entry: fall through to the default (all expanded).
		}
		return { ...SECTIONS_DEFAULT };
	}

	let sectionsOpen = $state<Record<ProbeCategory, boolean>>(loadSectionToggles());

	function toggleSection(key: ProbeCategory) {
		sectionsOpen = { ...sectionsOpen, [key]: !sectionsOpen[key] };
		if (typeof localStorage === 'undefined') return;
		try {
			localStorage.setItem(SECTIONS_STORAGE_KEY, JSON.stringify(sectionsOpen));
		} catch {
			// Storage unavailable: the toggle still holds for this session.
		}
	}

	// --- Egress quality report (#608): GET /probe-quality, fetched once on
	// mount + manual refresh. The report is computed read-time server-side, no
	// point polling it on the 10s target cadence.
	let quality = $state<ProbeQualityReport | null>(null);
	let qualityLoading = $state(false);
	let qualityError = $state('');

	async function fetchQuality() {
		qualityLoading = true;
		qualityError = '';
		try {
			quality = await api.get<ProbeQualityReport>('/probe-quality');
		} catch (err: unknown) {
			qualityError = getErrorMessage(err);
		} finally {
			qualityLoading = false;
		}
	}

	// --- Category view of the report (#613): the payload carries lan,
	// external and quality. The panel renders quality (verdict-chain groups)
	// then external — #615 removed the lan matrix from the panel; the lan
	// category's per-vantage health is the quiet strip inside the lan list
	// section. The category-level vantages of quality mirror the primary
	// group, so the panel renders the nested groups directly.
	function qualityCat(name: ProbeCategory): ProbeQualityCategory {
		return quality?.categories?.find((c) => c.category === name) ?? { category: name, vantages: [], targets: [] };
	}

	// External is the panel's one simple category: a compact matrix whose
	// verdicts are plain window health (ok/degraded/insufficient).
	const externalCat = $derived(qualityCat('external'));
	// LAN health strip (#615): the lan category's per-vantage verdicts feed
	// the single badge row at the top of the lan list section — same one
	// /probe-quality fetch the panel consumes.
	const lanVantages = $derived(qualityCat('lan').vantages ?? []);
	// Column cap for the compact matrix so it stays compact; the overflow is
	// noted under the table ("+N more").
	const MATRIX_MAX_TARGETS = 8;

	function simpleCatEmpty(cat: ProbeQualityCategory): boolean {
		return (cat.targets ?? []).length === 0 && (cat.vantages ?? []).length === 0;
	}

	// Primary group first, reference groups after it (by name) so the network
	// verdict leads and the comparison groups read as context.
	const qualityGroups = $derived.by<ProbeQualityGroup[]>(() => {
		const groups = qualityCat('quality').groups ?? [];
		return [...groups].sort((a, b) => {
			const rank = (g: ProbeQualityGroup) => (g.role === 'primary' ? 0 : 1);
			return rank(a) - rank(b) || a.name.localeCompare(b.name);
		});
	});
	// Quality category empty = no groups at all, or none with a single
	// observed vantage yet.
	const qualityEmpty = $derived.by(() => {
		if (quality === null) return false;
		const groups = qualityCat('quality').groups ?? [];
		return groups.length === 0 || groups.every((g) => (g.vantages ?? []).length === 0);
	});

	// Row label: the human network name when the vantage maps to one, else the
	// raw vantage token; center renders with its friendly name.
	function vantageLabel(v: ProbeQualityVantage): string {
		if (v.network_name) return v.network_name;
		if (v.vantage === 'center') return m['probes.Vantage Center']();
		return v.vantage;
	}

	function verdictLabel(verdict: string): string {
		switch (verdict) {
			case 'ok':
				return m['probes.Verdict Ok']();
			case 'degraded':
				return m['probes.Verdict Degraded']();
			case 'egress_down':
				return m['probes.Verdict Egress Down']();
			case 'dns_fault':
				return m['probes.Verdict Dns Fault']();
			case 'upstream_resolver':
				return m['probes.Verdict Upstream Resolver']();
			default:
				return m['probes.Verdict Insufficient']();
		}
	}

	// ok=green, degraded=amber, dns_fault/egress_down=red, upstream_resolver
	// =orange (distinct from degraded's amber), insufficient=gray (the bare
	// .badge default). Orange has no theme token; the inline style pins it
	// like the chart palette does.
	function verdictCls(verdict: string): string {
		switch (verdict) {
			case 'ok':
				return 'badge-success';
			case 'degraded':
				return 'badge-warning';
			case 'dns_fault':
			case 'egress_down':
				return 'badge-error';
			default:
				return '';
		}
	}
	function verdictStyle(verdict: string): string {
		return verdict === 'upstream_resolver'
			? 'color:#fb923c;background:color-mix(in srgb, #fb923c 14%, transparent)'
			: '';
	}

	// Stable reason codes (#608 quality.go) → localized chips.
	// upstream_resolver.failing:<name> carries the failing target's name.
	function reasonLabel(code: string): string {
		if (code === 'egress_down.all_paths_failing') return m['probes.Reason Egress Down']();
		if (code === 'dns_fault.direct_ok_name_resolution_dead') return m['probes.Reason Dns Fault']();
		if (code === 'ok_rate_low') return m['probes.Reason Ok Rate Low']();
		if (code === 'latency_high') return m['probes.Reason Latency High']();
		if (code === 'insufficient_data') return m['probes.Reason Insufficient']();
		const prefix = 'upstream_resolver.failing:';
		if (code.startsWith(prefix)) {
			return m['probes.Reason Upstream Resolver']({ name: code.slice(prefix.length) });
		}
		return code;
	}

	// Cell state from a track: the newest status leads; when the window has
	// samples but no last_status, the ok_rate band decides.
	function trackState(tr: ProbeQualityTrack | undefined): 'ok' | 'warn' | 'err' | 'none' {
		if (!tr || !tr.samples) return 'none';
		if (tr.last_status === 'success') return 'ok';
		if (tr.last_status === 'timeout') return 'warn';
		if (tr.last_status) return 'err';
		if (tr.ok_rate >= 0.9) return 'ok';
		if (tr.ok_rate >= 0.5) return 'warn';
		return 'err';
	}
	const trackDotCls: Record<'ok' | 'warn' | 'err' | 'none', string> = {
		ok: 'bg-success',
		warn: 'bg-warning',
		err: 'bg-error',
		none: 'bg-border'
	};
	const trackTextCls: Record<'ok' | 'warn' | 'err' | 'none', string> = {
		ok: 'text-success',
		warn: 'text-warning',
		err: 'text-error',
		none: 'text-text-muted'
	};

	// --- Cert expiry timeline (#276): TLS/http targets on a 0..90d+ scale -----
	interface TimelineEntry {
		t: ProbeTarget;
		days: number;
		notAfter: string;
	}
	const certTimeline = $derived.by<TimelineEntry[]>(() => {
		const entries: TimelineEntry[] = [];
		for (const t of targets) {
			if (t.module !== 'tls' && t.module !== 'http') continue;
			const notAfter = certExpiry[t.id];
			if (!notAfter) continue;
			entries.push({ t, days: certDayDelta(notAfter), notAfter });
		}
		return entries.sort((a, b) => a.days - b.days);
	});
	// Expiry warning threshold (days): persisted per browser (#276 goal: configurable).
	let expiryWarnDays = $state<number>(
		Number(localStorage.getItem('probes.expiryWarnDays')) || 30
	);
	function setExpiryWarn(n: number) {
		expiryWarnDays = n;
		localStorage.setItem('probes.expiryWarnDays', String(n));
	}
	let pollTimer: ReturnType<typeof setInterval> | null = null;

	// --- Create/Edit modal ---
	let editModalOpen = $state(false);
	let editingId = $state<number | null>(null); // null = create
	let formName = $state('');
	let formModule = $state<ProbeModule>('http');
	let formTarget = $state('');
	let formInterval = $state(60);
	let formTimeout = $state(10);
	let formNotes = $state('');
	let formEnabled = $state(true);
	let formVantage = $state('center');
	// Optional device binding (#606): prefilled from ?device_id= (device detail
	// page's per-service create button) or the edited target's existing value.
	let formDeviceId = $state<number | null>(null);
	let formLoading = $state(false);
	let fieldErrors = $state<Record<string, string>>({});

	// --- Per-module options (#605) ---
	// Text inputs for list fields (expected_status / expected_ips) hold
	// comma-separated values; buildFormOptions() turns them into arrays and
	// drops empty values so the payload only carries what the user set.
	let optMethod = $state<'GET' | 'HEAD'>('GET');
	let optExpectedStatus = $state('');
	let optKeyword = $state('');
	let optKeywordMode = $state<'contains' | 'not_contains' | 'regex'>('contains');
	let optIgnoreTls = $state(false);
	let optRecord = $state<'A' | 'AAAA' | 'CNAME' | 'TXT'>('A');
	let optResolver = $state('');
	let optExpectedIps = $state('');
	let optSend = $state('');
	let optExpect = $state('');
	let optExpectMode = $state<'contains' | 'regex'>('contains');

	function resetOptionFields() {
		optMethod = 'GET';
		optExpectedStatus = '';
		optKeyword = '';
		optKeywordMode = 'contains';
		optIgnoreTls = false;
		optRecord = 'A';
		optResolver = '';
		optExpectedIps = '';
		optSend = '';
		optExpect = '';
		optExpectMode = 'contains';
	}

	// Build the module's options object from the form fields, omitting empty
	// values and defaults (server omitempty semantics). Returns undefined when
	// nothing is set (create then omits the key entirely).
	function buildFormOptions(): ProbeOptions | undefined {
		const o: ProbeOptions = {};
		if (formModule === 'http') {
			if (optMethod !== 'GET') o.method = optMethod;
			const codes = optExpectedStatus
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean)
				.map(Number);
			if (codes.length) o.expected_status = codes;
			if (optKeyword.trim()) {
				o.keyword = optKeyword.trim();
				if (optKeywordMode !== 'contains') o.keyword_mode = optKeywordMode;
			}
			if (optIgnoreTls) o.ignore_tls_errors = true;
		} else if (formModule === 'dns') {
			if (optRecord !== 'A') o.record = optRecord;
			if (optResolver.trim()) o.resolver = optResolver.trim();
			const ips = optExpectedIps
				.split(',')
				.map((s) => s.trim())
				.filter(Boolean);
			if (ips.length) o.expected_ips = ips;
		} else if (formModule === 'tcp') {
			if (optSend) o.send = optSend;
			if (optExpect) {
				o.expect = optExpect;
				if (optExpectMode !== 'contains') o.expect_mode = optExpectMode;
			}
		}
		return Object.keys(o).length ? o : undefined;
	}

	// --- Trigger (per-row, in-flight marker disables just that row's button) ---
	let triggeringId = $state<number | null>(null);

	// --- Delete confirm ---
	let deleteDialogOpen = $state(false);
	let deleteTarget: ProbeTarget | null = null;

	// --- Results history modal ---
	let resultsModalOpen = $state(false);
	let resultsTarget = $state<ProbeTarget | null>(null);
	let results = $state<ProbeResult[]>([]);
	let resultsTotal = $state(0);
	let resultsLoading = $state(false);
	// Chart is the default view (#277 follow-up); the raw rows stay one tab away.
	let resultsTab = $state<'chart' | 'detail'>('chart');

	// --- Certificate modal (reuses the shared component: same DTO shape) ---
	let certModalOpen = $state(false);
	let certPortCerts = $state<TLSPortCerts | null>(null);

	onMount(() => {
		fetchTargets();
		fetchAgents();
		fetchQuality();
		pollTimer = setInterval(fetchTargets, 10000);
		// Deep-link prefill from the device detail page's per-service create
		// button (#606): ?create=1&module=…&target=…&device_id=… opens the
		// create modal prefilled. Read once from window.location (the page is
		// an SPA route; no server-side load involved).
		const sp = new URLSearchParams(window.location.search);
		if (sp.get('create') === '1') {
			openCreate();
			const mod = sp.get('module');
			if (mod === 'http' || mod === 'tls' || mod === 'tcp' || mod === 'icmp' || mod === 'dns') {
				formModule = mod;
			}
			const tgt = sp.get('target');
			if (tgt) formTarget = tgt;
			const dev = Number(sp.get('device_id'));
			if (Number.isFinite(dev) && dev > 0) formDeviceId = dev;
		}
	});
	onDestroy(() => {
		if (pollTimer) clearInterval(pollTimer);
	});

	async function fetchTargets() {
		try {
			const res = await api.get<ProbeTargetListResponse>('/probe-targets/?limit=100');
			targets = res.targets || [];
			error = '';
			fetchCertSummaries();
		} catch (err: unknown) {
			// Only surface the error banner on the first load; later poll
			// failures would flash the banner every 10s.
			if (loading) error = getErrorMessage(err);
		} finally {
			loading = false;
		}
	}

	// Registered agents for the vantage selector: the same population the
	// probe dispatcher routes plans to (networks.agent_id). Best-effort: the
	// form degrades to center/all options when this fails.
	async function fetchAgents() {
		try {
			const netsRes = await api.get<{ networks: Network[]; total: number }>('/networks');
			const ids = new Set<string>();
			for (const n of netsRes.networks || []) {
				if (n.agent_id) ids.add(n.agent_id);
			}
			agentIds = [...ids].sort();
		} catch {
			agentIds = [];
		}
	}

	// Per-target certificate leaf expiry for the table badge. N small requests
	// (one per tls/http target): the list endpoint doesn't carry cert state and
	// the target count is user-configured-small by nature.
	async function fetchCertSummaries() {
		const tlsLike = targets.filter((t) => t.module === 'tls' || t.module === 'http');
		const entries = await Promise.all(
			tlsLike.map(async (t) => {
				try {
					const res = await api.get<DeviceCertificatesResponse>(`/probe-targets/${t.id}/certificates`);
					const leaf = res.certificates?.[0]?.leaf;
					return [t.id, leaf ? leaf.not_after : ''] as const;
				} catch {
					return [t.id, ''] as const;
				}
			})
		);
		const map: Record<number, string> = {};
		for (const [id, notAfter] of entries) {
			if (notAfter) map[id] = notAfter;
		}
		certExpiry = map;
	}

	// --- Create / Edit ---
	function openCreate() {
		editingId = null;
		formName = '';
		formModule = 'http';
		formTarget = '';
		formInterval = 60;
		formTimeout = 10;
		formNotes = '';
		formEnabled = true;
		formVantage = 'center';
		formDeviceId = null;
		resetOptionFields();
		fieldErrors = {};
		editModalOpen = true;
	}

	function openEdit(t: ProbeTarget) {
		editingId = t.id;
		formName = t.name;
		formModule = t.module;
		formTarget = t.target;
		formInterval = t.interval_seconds;
		formTimeout = t.timeout_seconds;
		formNotes = t.notes || '';
		formEnabled = t.enabled;
		formVantage = t.vantage || 'center';
		// Keep the existing device binding on edit (no unbind UI; deleting the
		// binding is a device-page/probes-list concern, not this form's).
		formDeviceId = t.device_id ?? null;
		resetOptionFields();
		const o = t.options;
		if (o) {
			if (o.method === 'HEAD') optMethod = 'HEAD';
			if (o.expected_status?.length) optExpectedStatus = o.expected_status.join(',');
			if (o.keyword) optKeyword = o.keyword;
			if (o.keyword_mode === 'not_contains' || o.keyword_mode === 'regex') optKeywordMode = o.keyword_mode;
			if (o.ignore_tls_errors) optIgnoreTls = true;
			if (o.record === 'AAAA' || o.record === 'CNAME' || o.record === 'TXT') optRecord = o.record;
			if (o.resolver) optResolver = o.resolver;
			if (o.expected_ips?.length) optExpectedIps = o.expected_ips.join(',');
			if (o.send) optSend = o.send;
			if (o.expect) optExpect = o.expect;
			if (o.expect_mode === 'regex') optExpectMode = 'regex';
		}
		fieldErrors = {};
		editModalOpen = true;
	}

	// Vantage selector options (#277). An agent-specific value whose agent is
	// no longer registered still round-trips (marked unregistered) so an edit
	// can't silently rewrite the plan to something else.
	const vantageOptions = $derived.by<{ value: string; label: string }[]>(() => {
		const opts = [
			{ value: 'center', label: m['probes.Vantage Center']() },
			{ value: 'all', label: m['probes.Vantage All']() }
		];
		for (const id of agentIds) opts.push({ value: `agent:${id}`, label: m['probes.Vantage Agent']({ id }) });
		if (formVantage.startsWith('agent:') && !agentIds.includes(formVantage.slice('agent:'.length))) {
			opts.push({
				value: formVantage,
				label: m['probes.Vantage Agent Missing']({ id: formVantage.slice('agent:'.length) })
			});
		}
		return opts;
	});

	const moduleHelpKeys: Record<string, string> = {
		http: 'probes.Module http Help',
		tls: 'probes.Module tls Help',
		tcp: 'probes.Module tcp Help',
		icmp: 'probes.Module icmp Help',
		dns: 'probes.Module dns Help'
	};

	function moduleHelp(mod: string): string {
		switch (mod) {
			case 'tls':
				return m['probes.Module tls Help']();
			case 'tcp':
				return m['probes.Module tcp Help']();
			case 'icmp':
				return m['probes.Module icmp Help']();
			case 'dns':
				return m['probes.Module dns Help']();
			default:
				return m['probes.Module http Help']();
		}
	}

	function targetPlaceholder(mod: string): string {
		switch (mod) {
			case 'http':
				return 'https://example.com/healthz';
			case 'tls':
				return 'example.com:443';
			case 'tcp':
				return 'example.com:80';
			case 'dns':
				return 'www.example.com';
			default:
				return 'example.com';
		}
	}

	function validate(field: string, value: unknown) {
		const res = validateField(probeTargetSchema, field as never, value);
		if (!res.valid) fieldErrors[field] = res.error || '';
		else delete fieldErrors[field];
	}

	async function handleSubmit(e: Event) {
		e.preventDefault();
		const options = buildFormOptions();
		const validation = validateForm(probeTargetSchema, {
			name: formName,
			module: formModule,
			target: formTarget.trim(),
			interval_seconds: formInterval,
			timeout_seconds: formTimeout,
			notes: formNotes,
			options
		});
		if (!validation.valid) {
			fieldErrors = validation.errors;
			return;
		}
		fieldErrors = {};
		formLoading = true;
		try {
			const body: Record<string, unknown> = {
				name: formName.trim(),
				module: formModule,
				target: formTarget.trim(),
				interval_seconds: formInterval,
				timeout_seconds: formTimeout,
				notes: formNotes,
				enabled: formEnabled,
				vantage: formVantage
			};
			if (formDeviceId) body.device_id = formDeviceId;
			if (editingId === null) {
				// Create: omit options entirely when nothing is set.
				if (options) body.options = options;
				await api.post('/probe-targets/', body);
				addToast('success', m['probes.Target Created']());
			} else {
				// Update is partial (nil keeps current): an explicit empty
				// object clears stale options so switching the module can't
				// leave another module's fields behind in the DB.
				body.options = options ?? {};
				await api.put(`/probe-targets/${editingId}`, body);
				addToast('success', m['probes.Target Updated']());
			}
			editModalOpen = false;
			fetchTargets();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			formLoading = false;
		}
	}

	// --- Enabled toggle (partial update) ---
	async function toggleEnabled(t: ProbeTarget) {
		try {
			await api.put(`/probe-targets/${t.id}`, { enabled: !t.enabled });
			fetchTargets();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Trigger now (synchronous: response carries the just-recorded result) ---
	async function triggerNow(t: ProbeTarget) {
		triggeringId = t.id;
		try {
			const res = await api.post<ProbeTriggerResponse>(`/probe-targets/${t.id}/trigger`, {});
			const status = res.status === 'success' ? '✓' : '✗';
			addToast(res.status === 'success' ? 'success' : 'error', `${status} ${m['probes.Trigger Done']({ status: res.status })}`);
			fetchTargets();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			triggeringId = null;
		}
	}

	// --- Delete ---
	function openDelete(t: ProbeTarget) {
		deleteTarget = t;
		deleteDialogOpen = true;
	}

	async function confirmDelete() {
		if (!deleteTarget) return;
		try {
			await api.delete(`/probe-targets/${deleteTarget.id}`);
			addToast('success', m['probes.Target Deleted']());
			deleteTarget = null;
			fetchTargets();
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Results history ---
	async function openResults(t: ProbeTarget) {
		resultsTarget = t;
		results = [];
		resultsTotal = 0;
		resultsTab = 'chart';
		resultsModalOpen = true;
		resultsLoading = true;
		try {
			const res = await api.get<ProbeResultListResponse>(`/probe-targets/${t.id}/results?limit=100`);
			results = res.results || [];
			resultsTotal = res.total || 0;
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		} finally {
			resultsLoading = false;
		}
	}

	// --- Certificate chain (shared CertificateModal; response DTO is the same
	// tlsPortCerts shape as the device endpoint) ---
	async function openCerts(t: ProbeTarget) {
		try {
			const res = await api.get<DeviceCertificatesResponse>(`/probe-targets/${t.id}/certificates`);
			certPortCerts = res.certificates?.[0] ?? null;
			certModalOpen = true;
		} catch (err: unknown) {
			addToast('error', getErrorMessage(err));
		}
	}

	// --- Table columns (render path uses the auto-escaping html helper) ---
	const statusBadge = (s: string) => {
		if (!s) return html`<span class="text-text-muted text-xs">${m['probes.Never Run']()}</span>`;
		const cls = s === 'success' ? 'badge-success' : s === 'timeout' ? 'badge-warning' : 'badge-error';
		return html`<span class="badge ${cls}">${s}</span>`;
	};

	const fmtLatency = (v: number) => (v < 1000 ? `${Math.round(v)}ms` : `${(v / 1000).toFixed(2)}s`);

	// Status cell: one line per vantage track so agent outcomes are visible at
	// a glance (last_* mirrors the center track only). A lone center track
	// renders as compactly as the old single badge. Lines are built as separate
	// html fragments and joined: interpolating an HtmlString into another
	// html` template would double-escape its markup.
	const vantageStatusCell = (row: Record<string, unknown>) => {
		const tracks = row.vantage_latest as ProbeVantageLatest[] | undefined;
		const plan = String(row.vantage || 'center');
		const agentExpected = plan === 'all' || plan.startsWith('agent:');
		if (!tracks || tracks.length === 0) {
			if (agentExpected) {
				return html`<div class="space-y-0.5"><div class="text-text-muted text-xs">${m['probes.Never Run']()}</div><div class="text-warning text-xs">${m['probes.Agent No Results']()}</div></div>`;
			}
			return html`<span class="text-text-muted text-xs">${m['probes.Never Run']()}</span>`;
		}
		if (tracks.length === 1 && tracks[0].vantage === 'center' && !agentExpected) {
			const t = tracks[0];
			if (t.latency_ms > 0) {
				return html`<div class="flex items-center gap-2"><span class="badge ${t.status === 'success' ? 'badge-success' : t.status === 'timeout' ? 'badge-warning' : 'badge-error'}">${t.status}</span><span class="text-xs font-mono">${fmtLatency(t.latency_ms)}</span></div>`;
			}
			return statusBadge(t.status);
		}
		const disagree = new Set(tracks.map((t) => t.status === 'success')).size > 1;
		const lines = tracks.map((t) => {
			const dot = t.status === 'success' ? 'bg-success' : t.status === 'timeout' ? 'bg-warning' : 'bg-error';
			return html`<div class="flex items-center gap-1.5"><span class="inline-block h-2 w-2 shrink-0 rounded-full ${dot}"></span><span class="max-w-[9rem] truncate font-mono text-xs text-text-muted" title="${t.vantage}">${t.vantage}</span><span class="text-xs font-mono text-text-muted">${t.latency_ms > 0 ? fmtLatency(t.latency_ms) : ''}</span></div>`;
		});
		if (agentExpected && !tracks.some((t) => t.vantage !== 'center')) {
			lines.push(html`<div class="text-warning text-xs">${m['probes.Agent No Results']()}</div>`);
		}
		const wrap = disagree
			? 'space-y-0.5 rounded-md border border-warning/40 bg-warning/5 px-2 py-1'
			: 'space-y-0.5';
		return `<div class="${wrap}">` + lines.join('') + '</div>';
	};

	// Vantage values are protocol tokens (center / all / agent:{id}): shown
	// raw, not localized. Center is the quiet default (plain text); plans that
	// involve agents get a badge so multi-vantage targets stand out.
	const vantageBadge = (v: string) => {
		const val = v || 'center';
		if (val === 'center') return html`<span class="text-xs text-text-muted">center</span>`;
		const cls = val === 'all' ? 'badge-info' : 'badge-primary';
		return html`<span class="badge ${cls} font-mono">${val}</span>`;
	};

	// An agent-only target cannot be triggered from the center (the engine
	// returns 409 ErrProbeVantageNotLocal): reflect that in the button state.
	const isAgentOnly = (t: ProbeTarget) => (t.vantage || 'center').startsWith('agent:');

	// Source badges (#606/#608): system = config-managed egress-quality matrix
	// (shield), auto = policy-generated from a discovered service (magic wand).
	// The table renders cells through the escaping html`` helper, so the icons
	// are static trusted markup concatenated onto the escaped name fragment
	// (interpolating markup through html`` would escape it).
	const SOURCE_SVG = {
		system:
			'<svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1 1 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/></svg>',
		auto: '<svg xmlns="http://www.w3.org/2000/svg" class="h-3 w-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.64 3.64-1.28-1.28a1.21 1.21 0 0 0-1.72 0L2.36 18.64a1.21 1.21 0 0 0 0 1.72l1.28 1.28a1.2 1.2 0 0 0 1.72 0L21.64 5.36a1.2 1.2 0 0 0 0-1.72Z"/><path d="m14 7 3 3"/><path d="M5 6v4"/><path d="M19 14v4"/><path d="M10 2v2"/><path d="M7 8H3"/><path d="M21 16h-4"/><path d="M11 3H9"/></svg>'
	};
	const sourceIcon = (row: Record<string, unknown>): string => {
		const src = String(row.source || 'manual');
		if (src === 'system') {
			return `<span class="ml-1 inline-flex items-center align-middle text-text-muted" title="${escapeAttr(m['probes.Source System']())}">${SOURCE_SVG.system}</span>`;
		}
		if (src === 'auto') {
			return `<span class="ml-1 inline-flex items-center align-middle text-text-muted" title="${escapeAttr(m['probes.Source Auto']())}">${SOURCE_SVG.auto}</span>`;
		}
		return '';
	};

	const columns = $derived([
		{ key: 'select', label: m['probes.Batch Select'](), interactive: true },
		{
			key: 'name',
			label: m['probes.Name'](),
			sortable: true,
			render: (row: Record<string, unknown>) => html`<span class="font-medium">${row.name}</span>` + sourceIcon(row)
		},
		{ key: 'module', label: m['probes.Module'](), render: (row: Record<string, unknown>) => html`<span class="badge badge-info uppercase">${row.module}</span>` },
		{ key: 'target', label: m['probes.Target'](), render: (row: Record<string, unknown>) => html`<span class="font-mono text-xs">${row.target}</span>` },
		{ key: 'vantage', label: m['probes.Vantage'](), render: (row: Record<string, unknown>) => vantageBadge(String(row.vantage || '')) },
		{ key: 'interval_seconds', label: m['probes.Interval'](), render: (row: Record<string, unknown>) => html`<span class="text-xs">${row.interval_seconds}s</span>` },
		{ key: 'last_status', label: m['probes.Vantage Status'](), sortable: true, render: (row: Record<string, unknown>) => vantageStatusCell(row) },
		{
			key: 'cert',
			label: m['probes.Cert Expiry'](),
			render: (row: Record<string, unknown>) => {
				const id = row.id as number;
				const mod = row.module as string;
				if (mod !== 'tls' && mod !== 'http') return html`<span class="text-text-muted text-xs">-</span>`;
				const notAfter = certExpiry[id];
				if (!notAfter) return html`<span class="text-text-muted text-xs">-</span>`;
				const days = certDayDelta(notAfter);
				const cls = days < 0 ? 'badge-error' : days < 15 ? 'badge-warning' : 'badge-success';
				return html`<span class="badge ${cls}" title="${notAfter}">${m['probes.Cert Days']({ days })}</span>`;
			}
		},
		{ key: 'enabled', label: m['probes.Enabled'](), interactive: true },
		{ key: 'actions', label: m['probes.Actions'](), interactive: true }
	]);

	// Per-vantage tracks for the results modal (#277): each executor's newest
	// row, side by side. `results` arrive newest-first from the API, so the
	// first row seen per vantage is that track's latest; `rows` is the same
	// set chronological for the chart and the status timeline.
	interface VantageTrack {
		vantage: string;
		latest?: ProbeResult;
		rows: ProbeResult[];
		samples: number;
		okCount: number;
	}
	const vantageTracks = $derived.by<VantageTrack[]>(() => {
		const map = new Map<string, VantageTrack>();
		for (const r of results) {
			const key = r.vantage || 'center';
			let track = map.get(key);
			if (!track) {
				track = { vantage: key, rows: [], samples: 0, okCount: 0 };
				map.set(key, track);
			}
			track.samples++;
			track.rows.unshift(r);
			if (r.status === 'success') track.okCount++;
			if (!track.latest) track.latest = r;
		}
		const order = (v: string) => (v === 'center' ? 0 : 1);
		return [...map.values()].sort(
			(a, b) => order(a.vantage) - order(b.vantage) || a.vantage.localeCompare(b.vantage)
		);
	});
	// Disagreement = ≥2 tracks whose LATEST verdicts differ on success: the
	// "reachable from A, not from B" case the multi-vantage view exists for.
	const vantageDisagree = $derived(
		vantageTracks.length >= 2 && new Set(vantageTracks.map((t) => t.latest?.status === 'success')).size > 1
	);

	// ECharts renders to canvas, which does NOT resolve CSS custom properties;
	// read the computed accent from :root (falls back to a literal so an unset
	// var still draws something). Agent tracks use a fixed readable palette.
	function cssVar(name: string, fallback: string): string {
		const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
		return v || fallback;
	}
	const TRACK_PALETTE = ['#34d399', '#fbbf24', '#38bdf8', '#f97316', '#c084fc'];
	const trackColors = $derived.by<Map<string, string>>(() => {
		const map = new Map<string, string>();
		let agentIdx = 0;
		for (const track of vantageTracks) {
			map.set(
				track.vantage,
				track.vantage === 'center'
					? cssVar('--color-accent', '#818cf8')
					: TRACK_PALETTE[agentIdx++ % TRACK_PALETTE.length]
			);
		}
		return map;
	});

	// Latency time series, one line per vantage. Failed probes map to null so
	// the line breaks there (connectNulls stays false); the status timeline
	// below the chart is the explicit record of those gaps. Tracks of the same
	// target usually sit within a few ms of each other, so agent tracks draw
	// dashed with their own symbol and hover focuses one series: solid lines
	// stacking on solid lines would read as a single line.
	const latencyChartOption = $derived.by<EChartsOption>(() => {
		const series = vantageTracks.map((track) => {
			const isCenter = track.vantage === 'center';
			const color = trackColors.get(track.vantage);
			return {
				name: track.vantage,
				type: 'line' as const,
				symbolSize: 5,
				showSymbol: true,
				symbol: isCenter ? 'circle' : 'triangle',
				emphasis: { focus: 'series' },
				data: track.rows.map((r) => [
					r.checked_at,
					r.status === 'success' && r.latency_ms > 0 ? Math.round(r.latency_ms) : null
				]),
				lineStyle: { width: 2, color, type: isCenter ? 'solid' : 'dashed' },
				itemStyle: { color }
			};
		});
		return {
			animation: false,
			grid: { left: 52, right: 12, top: 12, bottom: 44 },
			tooltip: { trigger: 'axis' },
			legend: { bottom: 0, type: 'scroll', textStyle: { fontSize: 10 } },
			xAxis: { type: 'time', axisLabel: { hideOverlap: true } },
			yAxis: { type: 'value', scale: true, axisLabel: { formatter: '{value} ms' } },
			series
		};
	});

	const statusStripCls = (s: string) =>
		s === 'success' ? 'bg-success' : s === 'timeout' ? 'bg-warning' : 'bg-error';

	const resultColumns = $derived([
		{ key: 'vantage', label: m['probes.Vantage'](), render: (row: Record<string, unknown>) => vantageBadge(String(row.vantage || '')) },
		{ key: 'checked_at', label: m['probes.Checked At'](), render: (row: Record<string, unknown>) => html`<span class="text-xs text-text-muted">${formatTime(String(row.checked_at))}</span>` },
		{ key: 'status', label: m['probes.Status'](), render: (row: Record<string, unknown>) => statusBadge(String(row.status)) },
		{
			key: 'latency_ms',
			label: m['probes.Latency'](),
			render: (row: Record<string, unknown>) => {
				const v = row.latency_ms as number;
				return html`<span class="text-xs font-mono">${fmtLatency(v)}</span>`;
			}
		},
		{
			key: 'status_code',
			label: m['probes.Status Code'](),
			render: (row: Record<string, unknown>) => {
				const v = row.status_code as number;
				return v ? html`<span class="text-xs font-mono">${v}</span>` : html`<span class="text-text-muted text-xs">-</span>`;
			}
		},
		{ key: 'tls_version', label: m['probes.TLS Version'](), render: (row: Record<string, unknown>) => html`<span class="text-xs">${row.tls_version || '-'}</span>` },
		{
			key: 'cert_not_after',
			label: m['probes.Cert Not After'](),
			render: (row: Record<string, unknown>) => {
				const v = row.cert_not_after as string | undefined;
				return v ? html`<span class="text-xs">${v.slice(0, 10)}</span>` : html`<span class="text-text-muted text-xs">-</span>`;
			}
		},
		{
			key: 'error_message',
			label: m['probes.Error'](),
			render: (row: Record<string, unknown>) => {
				const v = row.error_message as string | undefined;
				return v ? html`<span class="text-xs text-error" title="${v}">${v.length > 40 ? v.slice(0, 40) + '…' : v}</span>` : html`<span class="text-text-muted text-xs">-</span>`;
			}
		}
	]);
</script>

{#if !$auth.token}
	<div class="p-6 text-center text-text-muted">
		<p>{m['errors.Unauthorized Desc']()}</p>
		<a href="/login" class="text-primary hover:underline text-sm mt-2 inline-block">{m['navigation.Login']()}</a>
	</div>
{:else}
	<div class="p-6">
		<!-- Header -->
		<div class="flex items-center justify-between mb-1">
			<h2 class="text-2xl font-bold text-primary">{m['probes.Title']()}</h2>
			<button onclick={openCreate} class="btn btn-primary">
				+ {m['probes.Add Target']()}
			</button>
		</div>
		<p class="text-sm text-text-muted mb-6">{m['probes.Subtitle']()}</p>

		<!-- Quality matrix snippet (#608/#613): rows = vantages, columns =
		     targets, cells = ok% · p50 colored by ok-rate, trailing verdict
		     badge + score; reason chips for actionable verdicts. `more` counts
		     target columns omitted past the compact cap (0 = all shown). -->
		{#snippet qualityMatrix(vantages: ProbeQualityVantage[], cols: ProbeQualityTarget[], more: number)}
			<div class="overflow-x-auto">
				<table class="w-full text-xs">
					<thead>
						<tr class="text-left text-text-muted border-b border-border">
							<th class="py-1.5 pr-4 font-medium whitespace-nowrap">{m['probes.Quality Vantage']()}</th>
							{#each cols as t (t.name)}
								<th class="py-1.5 pr-4 font-medium font-mono whitespace-nowrap" title={t.target}>{t.name}</th>
							{/each}
							<th class="py-1.5 font-medium whitespace-nowrap">{m['probes.Quality Verdict']()}</th>
						</tr>
					</thead>
					<tbody>
						{#each vantages as v (v.vantage)}
							<tr class="border-b border-border/40 last:border-0">
								<td class="py-1.5 pr-4 whitespace-nowrap">
									<span class="truncate" title="{v.network_name ? v.vantage : ''}">{vantageLabel(v)}</span>
								</td>
								{#each cols as t (t.name)}
									{@const tr = t.per_vantage?.[v.vantage]}
									{@const st = trackState(tr)}
									<td class="py-1.5 pr-4 font-mono whitespace-nowrap"
										title={tr && tr.samples ? m['probes.Vantage Samples']({ count: tr.samples }) : ''}
									>
										{#if st === 'none'}
											<span class="text-text-muted">—</span>
										{:else}
											<span class="inline-flex items-center gap-1.5 {trackTextCls[st]}">
												<span class="inline-block h-2 w-2 shrink-0 rounded-full {trackDotCls[st]}"></span>
												{Math.round((tr?.ok_rate ?? 0) * 100)}% · {Math.round(tr?.p50_ms ?? 0)}ms
											</span>
										{/if}
									</td>
								{/each}
								<td class="py-1.5">
									<span class="badge {verdictCls(v.verdict)}" style={verdictStyle(v.verdict)}>
										{verdictLabel(v.verdict)} · {v.score}
									</span>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
			{#if more > 0}
				<p class="mt-1 text-xs text-text-muted">{m['probes.Quality More Targets']({ count: more })}</p>
			{/if}
			<!-- Reason chips: only for actionable verdicts (not ok /
			     insufficient, which carry no actionable detail). -->
			{#each vantages as v (v.vantage)}
				{#if v.verdict !== 'ok' && v.verdict !== 'insufficient' && (v.reasons ?? []).length > 0}
					<div class="mt-1.5 flex flex-wrap items-center gap-1.5">
						<span class="text-xs text-text-muted">{vantageLabel(v)}:</span>
						{#each v.reasons as r (r)}
							<span class="badge badge-warning !text-[0.625rem] !px-1.5 !py-0.5">{reasonLabel(r)}</span>
						{/each}
					</div>
				{/if}
			{/each}
		{/snippet}

		<!-- Egress quality (#608/#613): per-category vantage × target matrices
		     with verdicts — quality first (verdict-chain config groups; primary
		     group leads, reference groups render visually secondary), then
		     external as one compact matrix (window health only). #615: the lan
		     category does NOT render here; its per-vantage health is the strip
		     inside the lan list section below. -->
		<div class="bg-surface border border-border rounded-lg p-4 mb-6" data-quality-panel>
			<div class="flex items-center justify-between gap-4 mb-3">
				<div>
					<div class="flex items-center gap-1.5">
						<h3 class="text-sm font-semibold text-text">{m['probes.Quality Title']()}</h3>
						<!-- Help (#613): hover (or keyboard focus) reveals the verdict
						     formulas. Pure CSS reveal — the content always stays in the
						     DOM, so screen readers (and tests) see it either way. -->
						<div class="relative inline-flex group">
							<button
								type="button"
								class="inline-flex h-5 w-5 items-center justify-center rounded-full border border-border text-text-muted transition-colors hover:border-text-muted hover:text-text"
								aria-label={m['probes.Quality Help Title']()}
								aria-describedby="probes-quality-help"
							>
								<Info class="h-3.5 w-3.5" />
							</button>
							<div
								id="probes-quality-help"
								role="tooltip"
								data-quality-help
								class="invisible pointer-events-none absolute left-0 top-full z-40 mt-2 w-[26rem] max-w-[80vw] rounded-lg border border-border bg-surface p-3 shadow-lg transition-opacity opacity-0
									group-hover:visible group-hover:opacity-100 group-hover:pointer-events-auto
									group-focus-within:visible group-focus-within:opacity-100 group-focus-within:pointer-events-auto"
							>
								<p class="mb-2 text-xs font-semibold text-text">{m['probes.Quality Help Title']()}</p>
								<dl class="space-y-1.5">
									<div class="flex gap-2">
										<dt class="w-28 shrink-0 text-xs font-medium text-text">{m['probes.Quality Help Window Label']()}</dt>
										<dd class="min-w-0 flex-1 text-xs text-text-muted">{m['probes.Quality Help Window']({ window: quality?.window_minutes ?? 15 })}</dd>
									</div>
									<div class="flex gap-2">
										<dt class="w-28 shrink-0 text-xs font-medium text-text">{m['probes.Quality Help Cell Label']()}</dt>
										<dd class="min-w-0 flex-1 text-xs text-text-muted">{m['probes.Quality Help Cell']()}</dd>
									</div>
									<div class="flex gap-2">
										<dt class="w-28 shrink-0 text-xs font-medium text-text">{m['probes.Quality Help Simple Label']()}</dt>
										<dd class="min-w-0 flex-1 text-xs text-text-muted">{m['probes.Quality Help Simple']()}</dd>
									</div>
									<div class="flex gap-2">
										<dt class="w-28 shrink-0 text-xs font-medium text-text">{m['probes.Quality Help Chain Label']()}</dt>
										<dd class="min-w-0 flex-1 text-xs text-text-muted">{m['probes.Quality Help Chain']()}</dd>
									</div>
									<div class="flex gap-2">
										<dt class="w-28 shrink-0 text-xs font-medium text-text">{m['probes.Quality Help Thresholds Label']()}</dt>
										<dd class="min-w-0 flex-1 text-xs text-text-muted">{m['probes.Quality Help Thresholds']()}</dd>
									</div>
								</dl>
							</div>
						</div>
					</div>
					<p class="text-xs text-muted">{m['probes.Quality Desc']({ window: quality?.window_minutes ?? 15 })}</p>
				</div>
				<button onclick={fetchQuality} disabled={qualityLoading} class="btn btn-secondary !py-1 !px-3 text-xs shrink-0">
					{qualityLoading ? '…' : m['probes.Refresh']()}
				</button>
			</div>
			{#if qualityError}
				<p class="text-xs text-error mb-2">{m['probes.Quality Error']()}: {qualityError}</p>
			{/if}
			{#if quality === null && !qualityError}
				<p class="text-xs text-muted py-2">…</p>
			{:else}
				<!-- quality: the egress verdict-chain groups, as before (#608);
				     they lead the panel (#615). -->
				<div class="mb-3 last:mb-0">
					<div class="flex items-center gap-2 mb-1.5">
						<h4 class="text-xs font-semibold text-text">{categoryLabel('quality')}</h4>
					</div>
					{#if qualityEmpty}
						<p class="text-xs text-muted italic">{m['probes.Quality Empty']()}</p>
					{:else}
						{#each qualityGroups as g (g.name)}
							<div class="mb-3 last:mb-0 {g.role === 'reference' ? 'opacity-80' : ''}">
								<div class="flex items-center gap-2 mb-1.5">
									<h5 class="text-xs font-semibold {g.role === 'reference' ? 'text-text-muted' : 'text-text'}">{g.name}</h5>
									{#if g.role === 'reference'}
										<span class="badge badge-info !text-[0.625rem] !px-1.5">{m['probes.Quality Reference']()}</span>
									{/if}
								</div>
								{@render qualityMatrix(g.vantages ?? [], g.targets ?? [], 0)}
							</div>
						{/each}
					{/if}
				</div>
				<!-- external: its compact window-health matrix with verdict
				     badges + reason chips (#615: the lan matrix left the panel —
				     LAN health renders as the strip in the lan list section). -->
				<div class="mb-3 last:mb-0">
					<div class="flex items-center gap-2 mb-1.5">
						<h4 class="text-xs font-semibold text-text">{categoryLabel('external')}</h4>
					</div>
					{#if simpleCatEmpty(externalCat)}
						<p class="text-xs text-muted italic">{m['probes.Quality Cat Empty']()}</p>
					{:else}
						{@render qualityMatrix(
							externalCat.vantages ?? [],
							(externalCat.targets ?? []).slice(0, MATRIX_MAX_TARGETS),
							Math.max(0, (externalCat.targets ?? []).length - MATRIX_MAX_TARGETS)
						)}
					{/if}
				</div>
			{/if}
		</div>

		<!-- Module overview cards (#276): per-module success rate + avg latency -->
		<div class="grid grid-cols-2 md:grid-cols-5 gap-3 mb-6">
			{#each moduleStats as ms (ms.module)}
				<div class="bg-surface border border-border rounded-lg px-4 py-3">
					<div class="flex items-center justify-between">
						<span class="badge badge-info uppercase">{ms.module}</span>
						<span class="text-xs text-muted">{ms.enabled}/{ms.total}</span>
					</div>
					<p class="mt-2 text-lg font-semibold {ms.successRate === null ? 'text-muted' : ms.successRate >= 90 ? 'text-success' : ms.successRate >= 50 ? 'text-warning' : 'text-error'}">
						{ms.successRate === null ? '-' : ms.successRate + '%'}
					</p>
					<p class="text-xs text-muted">{m['probes.Avg Latency']()}: {ms.avgLatency === null ? '-' : ms.avgLatency < 1000 ? Math.round(ms.avgLatency) + 'ms' : (ms.avgLatency / 1000).toFixed(2) + 's'}</p>
				</div>
			{/each}
		</div>

		<!-- Cert expiry timeline (#276): TLS/http targets sorted by days-left -->
		{#if certTimeline.length > 0}
			<div class="bg-surface border border-border rounded-lg p-4 mb-6">
				<div class="flex items-center justify-between mb-3">
					<div>
						<h3 class="text-sm font-semibold text-text">{m['probes.Cert Timeline']()}</h3>
						<p class="text-xs text-muted">{m['probes.Cert Timeline Desc']()}</p>
					</div>
					<select
						value={expiryWarnDays}
						onchange={(e) => setExpiryWarn(Number((e.target as HTMLSelectElement).value))}
						class="input !w-auto text-xs"
						aria-label={m['probes.Expiry Threshold']()}
					>
						{#each [15, 30, 60, 90] as d (d)}
							<option value={d}>{m['probes.Expiry Threshold Option']({ days: d })}</option>
						{/each}
					</select>
				</div>
				<div class="space-y-1.5">
					{#each certTimeline as e (e.t.id)}
						{@const pct = Math.max(2, Math.min(100, (e.days / 90) * 100))}
						{@const cls = e.days < 0 ? 'bg-error' : e.days < expiryWarnDays ? 'bg-warning' : 'bg-success'}
						<button
							type="button"
							onclick={() => openCerts(e.t)}
							class="w-full flex items-center gap-3 group text-left"
							title={e.notAfter}
						>
							<span class="w-40 shrink-0 truncate text-xs font-medium group-hover:text-primary">{e.t.name}</span>
							<span class="flex-1 h-3 rounded-full bg-border/50 overflow-hidden">
								<span class="block h-full {cls} rounded-full transition-all" style="width: {pct}%"></span>
							</span>
							<span class="w-20 shrink-0 text-right text-xs font-mono {e.days < expiryWarnDays ? 'text-warning' : 'text-muted'}">
								{e.days < 0 ? m['probes.Cert Expired']() : m['probes.Cert Days']({ days: e.days })}
							</span>
						</button>
					{/each}
				</div>
				{#if certTimeline.some((e) => e.days >= 0 && e.days < expiryWarnDays)}
					<p class="mt-3 text-xs text-warning">
						{m['probes.Cert Expiring Hint']()}
						<a href="/settings/notifications" class="text-primary hover:underline">{m['probes.Cert Configure Rule']()}</a>
					</p>
				{/if}
			</div>
		{/if}

		<!-- Batch toolbar (#276) -->
		{#if selectedIds.size > 0}
			<div class="mb-4 flex flex-wrap items-center gap-2 px-4 py-2.5 bg-primary/5 border border-primary/20 rounded-lg">
				<span class="text-sm font-medium text-primary">{m['probes.Batch Selected']({ count: selectedIds.size })}</span>
				<div class="flex-1"></div>
				<button onclick={batchEnable} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs">{m['probes.Batch Enable']()}</button>
				<button onclick={batchDisable} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs">{m['probes.Batch Disable']()}</button>
				<button onclick={batchInterval} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs">{m['probes.Batch Interval']()}</button>
				<button onclick={batchDelete} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs !text-error !border-error/30">{m['common.Delete']()}</button>
				<button onclick={() => (selectedIds = new Set())} disabled={batchBusy} class="btn btn-secondary !py-1 !px-3 text-xs">{m['common.Cancel']()}</button>
			</div>
		{/if}

		{#if error}
			<div class="mb-4 px-4 py-3 bg-error/10 border border-error/30 rounded-lg text-sm text-error">
				{error}
			</div>
		{/if}

		{#if loading}
			<PageSkeleton type="table" />
		{:else if targets.length === 0}
			<EmptyState
				icon={ActivityIcon}
				title={m['probes.No Targets']()}
				description={m['probes.No Targets Desc']()}
				actionLabel={m['probes.Add Target']()}
				onAction={openCreate}
			/>
		{:else}
			<!-- Category sections (#613): three collapsible sub-tables — LAN,
			     external business, egress quality — one page-level search box
			     applying within each. An empty section keeps its header + hint;
			     a section with no SEARCH match hides itself entirely. -->
			<div class="bg-surface border border-border rounded-lg p-4">
				<div class="relative mb-4">
					<Search class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted pointer-events-none" />
					<input
						type="text"
						bind:value={searchQuery}
						placeholder={m['common.Search']() + '...'}
						aria-label={m['common.Search']()}
						class="input pl-10"
					/>
				</div>
				{#each sections as sec (sec.key)}
					{#if sec.rows.length > 0 || !searchQuery}
						<section class="mb-5 last:mb-0" data-category={sec.key}>
							<div class="flex items-center gap-3 border-b border-border pb-2 mb-3">
								<button
									type="button"
									class="flex min-w-0 flex-1 items-center gap-2 text-left"
									onclick={() => toggleSection(sec.key)}
									aria-expanded={sectionsOpen[sec.key]}
									aria-controls="probes-section-{sec.key}"
									aria-label={m['probes.Section Toggle']({ name: sec.label })}
								>
									<ChevronDown class="h-4 w-4 shrink-0 text-text-muted transition-transform {sectionsOpen[sec.key] ? '' : '-rotate-90'}" />
									<span class="whitespace-nowrap text-sm font-semibold text-text">{sec.label}</span>
									<span class="whitespace-nowrap text-xs text-text-muted">{sec.rows.length}</span>
									<span class="truncate text-xs text-text-muted">{m['probes.Section Summary']({ enabled: sec.summary.enabled, ok: sec.summary.ok, bad: sec.summary.bad })}</span>
								</button>
								<!-- Section select-all: works on this section's rows
								     only; the global batch toolbar merges selections. -->
								<input
									type="checkbox"
									class="checkbox shrink-0"
									checked={sectionAllSelected(sec)}
									onchange={() => toggleSelectSection(sec)}
									aria-label={m['probes.Select Section']({ name: sec.label })}
								/>
							</div>
							{#if sectionsOpen[sec.key]}
								<div id="probes-section-{sec.key}">
									<!-- LAN health strip (#615): one quiet row of per-vantage
									     verdict badges above the sub-table, fed by the same
									     /probe-quality fetch the egress panel uses. No lan
									     vantages → nothing renders. -->
									{#if sec.key === 'lan' && lanVantages.length > 0}
										<div class="mb-3 flex flex-wrap items-center gap-x-3 gap-y-1" data-lan-health>
											{#each lanVantages as v (v.vantage)}
												<span class="inline-flex items-center gap-1.5">
													<span class="text-xs text-text-muted" title="{v.network_name ? v.vantage : ''}">{vantageLabel(v)}</span>
													<span class="badge {verdictCls(v.verdict)}" style={verdictStyle(v.verdict)}>
														{verdictLabel(v.verdict)} · {v.score}
													</span>
												</span>
											{/each}
										</div>
									{/if}
									{#if sec.rows.length === 0}
										<p class="py-2 text-xs text-text-muted italic">{categoryEmptyHint(sec.key)}</p>
									{:else}
										<DataTable
											{columns}
											rows={sec.rows as unknown as Record<string, unknown>[]}
											searchableKeys={[]}
											emptyTitle={m['probes.No Targets']()}
										>
											{#snippet cell(row, col)}
												{#if col.key === 'select'}
													{@const t = targets.find((x) => x.id === row.id)}
													{#if t}
														<input
															type="checkbox"
															checked={selectedIds.has(t.id)}
															onchange={() => toggleSelected(t.id)}
															aria-label={m['probes.Batch Select Row']({ name: t.name })}
															class="checkbox"
														/>
													{/if}
												{:else if col.key === 'enabled'}
													{@const t = targets.find((x) => x.id === row.id)}
													{#if t}
														<button
															onclick={() => toggleEnabled(t)}
															role="switch"
															aria-checked={t.enabled}
															aria-label={t.enabled ? m['probes.Enabled']() : m['probes.Disabled']()}
															class="relative inline-flex h-5 w-9 items-center rounded-full transition-colors
																{t.enabled ? 'bg-success' : 'bg-border'}"
														>
															<span class="inline-block h-3.5 w-3.5 transform rounded-full bg-white shadow transition-transform
																{t.enabled ? 'translate-x-4.5' : 'translate-x-0.5'}"></span>
														</button>
													{/if}
												{:else if col.key === 'actions'}
													{@const t = targets.find((x) => x.id === row.id)}
													{#if t}
														<div class="flex items-center gap-2">
															<button
																onclick={() => triggerNow(t)}
																disabled={triggeringId !== null || isAgentOnly(t)}
																title={isAgentOnly(t) ? m['probes.Trigger Agent Only']() : ''}
																class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors disabled:opacity-50"
															>{triggeringId === t.id ? m['probes.Triggering']() : m['probes.Trigger']()}</button>
															{#if t.module === 'tls' || t.module === 'http'}
																<button
																	onclick={() => openCerts(t)}
																	class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
																>{m['probes.View Cert']()}</button>
															{/if}
															<button
																onclick={() => openResults(t)}
																class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
															>{m['probes.View Results']()}</button>
															<button
																onclick={() => openEdit(t)}
																class="text-xs px-2 py-1 rounded text-primary hover:bg-primary/10 transition-colors"
															>{m['common.Edit']()}</button>
															<button
																onclick={() => openDelete(t)}
																class="text-xs px-2 py-1 rounded text-error hover:bg-error/10 transition-colors"
															>{m['probes.Delete Target']()}</button>
														</div>
													{/if}
												{/if}
											{/snippet}
										</DataTable>
									{/if}
								</div>
							{/if}
						</section>
					{/if}
				{/each}
				{#if searchQuery && sections.every((s) => s.rows.length === 0)}
					<p class="py-6 text-center text-sm text-text-muted">{m['probes.No Match']()}</p>
				{/if}
			</div>
		{/if}
	</div>
{/if}

<!-- Create/Edit Modal -->
<Modal
	bind:open={editModalOpen}
	title={editingId === null ? m['probes.Add Target']() : m['probes.Edit Target']()}
>
	<form onsubmit={handleSubmit} class="space-y-4">
		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-name">{m['probes.Name']()}</label>
			<input
				id="probe-name"
				class="input"
				class:input-error={!!fieldErrors.name}
				bind:value={formName}
				onblur={() => validate('name', formName)}
				placeholder="github-tls"
			/>
			{#if fieldErrors.name}<p class="text-xs text-error mt-1">{fieldErrors.name}</p>{/if}
		</div>

		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-module">{m['probes.Module']()}</label>
			<select id="probe-module" class="input" bind:value={formModule}>
				<option value="http">http</option>
				<option value="tls">tls</option>
				<option value="tcp">tcp</option>
				<option value="icmp">icmp</option>
				<option value="dns">dns</option>
			</select>
			<p class="text-xs text-text-muted mt-1">{moduleHelp(formModule)}</p>
		</div>

		<!-- Per-module options (#605): only the selected module's fields render;
		     empty values are omitted from the payload on submit. -->
		{#if formModule === 'http'}
			<div class="rounded-md border border-border p-3 space-y-3">
				<p class="text-xs font-semibold text-text-muted">{m['probes.Options Title']()}</p>
				<div class="grid grid-cols-2 gap-3">
					<div>
						<label class="block text-xs text-text-muted mb-1" for="probe-opt-method">{m['probes.Opt Method']()}</label>
						<select id="probe-opt-method" class="input" bind:value={optMethod}>
							<option value="GET">GET</option>
							<option value="HEAD">HEAD</option>
						</select>
					</div>
					<div>
						<label class="block text-xs text-text-muted mb-1" for="probe-opt-status">{m['probes.Opt Expected Status']()}</label>
						<input id="probe-opt-status" class="input font-mono text-xs" bind:value={optExpectedStatus} placeholder="200,204" />
						{#if fieldErrors['options.expected_status']}
							<p class="text-xs text-error mt-1">{fieldErrors['options.expected_status']}</p>
						{/if}
					</div>
				</div>
				<div>
					<label class="block text-xs text-text-muted mb-1" for="probe-opt-keyword">{m['probes.Opt Keyword']()}</label>
					<input id="probe-opt-keyword" class="input" bind:value={optKeyword} placeholder="ok" />
				</div>
				<div class="flex items-end gap-3">
					<div class="flex-1">
						<label class="block text-xs text-text-muted mb-1" for="probe-opt-keyword-mode">{m['probes.Opt Keyword Mode']()}</label>
						<select id="probe-opt-keyword-mode" class="input" bind:value={optKeywordMode}>
							<option value="contains">contains</option>
							<option value="not_contains">not_contains</option>
							<option value="regex">regex</option>
						</select>
					</div>
					<label class="flex items-center gap-2 text-sm text-text pb-2">
						<input type="checkbox" bind:checked={optIgnoreTls} class="checkbox" />
						{m['probes.Opt Ignore Tls']()}
					</label>
				</div>
			</div>
		{:else if formModule === 'dns'}
			<div class="rounded-md border border-border p-3 space-y-3">
				<p class="text-xs font-semibold text-text-muted">{m['probes.Options Title']()}</p>
				<div class="grid grid-cols-2 gap-3">
					<div>
						<label class="block text-xs text-text-muted mb-1" for="probe-opt-record">{m['probes.Opt Record']()}</label>
						<select id="probe-opt-record" class="input" bind:value={optRecord}>
							<option value="A">A</option>
							<option value="AAAA">AAAA</option>
							<option value="CNAME">CNAME</option>
							<option value="TXT">TXT</option>
						</select>
					</div>
					<div>
						<label class="block text-xs text-text-muted mb-1" for="probe-opt-resolver">{m['probes.Opt Resolver']()}</label>
						<input id="probe-opt-resolver" class="input font-mono text-xs" bind:value={optResolver} placeholder="223.5.5.5" />
						{#if fieldErrors['options.resolver']}
							<p class="text-xs text-error mt-1">{fieldErrors['options.resolver']}</p>
						{/if}
					</div>
				</div>
				<div>
					<label class="block text-xs text-text-muted mb-1" for="probe-opt-ips">{m['probes.Opt Expected Ips']()}</label>
					<input id="probe-opt-ips" class="input font-mono text-xs" bind:value={optExpectedIps} placeholder="1.2.3.4,5.6.7.8" />
					{#if fieldErrors['options.expected_ips']}
						<p class="text-xs text-error mt-1">{fieldErrors['options.expected_ips']}</p>
					{/if}
				</div>
			</div>
		{:else if formModule === 'tcp'}
			<div class="rounded-md border border-border p-3 space-y-3">
				<p class="text-xs font-semibold text-text-muted">{m['probes.Options Title']()}</p>
				<div class="grid grid-cols-2 gap-3">
					<div>
						<label class="block text-xs text-text-muted mb-1" for="probe-opt-send">{m['probes.Opt Send']()}</label>
						<input id="probe-opt-send" class="input font-mono text-xs" bind:value={optSend} placeholder="GET / HTTP/1.0" />
					</div>
					<div>
						<label class="block text-xs text-text-muted mb-1" for="probe-opt-expect">{m['probes.Opt Expect']()}</label>
						<input id="probe-opt-expect" class="input font-mono text-xs" bind:value={optExpect} placeholder="220" />
					</div>
				</div>
				<div>
					<label class="block text-xs text-text-muted mb-1" for="probe-opt-expect-mode">{m['probes.Opt Expect Mode']()}</label>
					<select id="probe-opt-expect-mode" class="input" bind:value={optExpectMode}>
						<option value="contains">contains</option>
						<option value="regex">regex</option>
					</select>
				</div>
			</div>
		{/if}

		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-target">{m['probes.Target']()}</label>
			<input
				id="probe-target"
				class="input font-mono text-xs"
				class:input-error={!!fieldErrors.target}
				bind:value={formTarget}
				onblur={() => validate('target', formTarget.trim())}
				placeholder={targetPlaceholder(formModule)}
			/>
			{#if fieldErrors.target}<p class="text-xs text-error mt-1">{fieldErrors.target}</p>{/if}
			{#if formDeviceId}
				<p class="text-xs text-text-muted mt-1">{m['probes.Device Bound']({ id: formDeviceId })}</p>
			{/if}
		</div>

		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-vantage">{m['probes.Vantage']()}</label>
			<select id="probe-vantage" class="input" bind:value={formVantage}>
				{#each vantageOptions as opt (opt.value)}
					<option value={opt.value}>{opt.label}</option>
				{/each}
			</select>
			<p class="text-xs text-text-muted mt-1">{m['probes.Vantage Help']()}</p>
			{#if formVantage === 'all' && agentIds.length === 0}
				<p class="text-xs text-warning mt-1">{m['probes.Vantage All No Agents']()}</p>
			{/if}
		</div>

		<div class="grid grid-cols-2 gap-4">
			<div>
				<label class="block text-xs text-text-muted mb-1" for="probe-interval">{m['probes.Interval']()}</label>
				<input
					id="probe-interval"
					type="number"
					class="input"
					class:input-error={!!fieldErrors.interval_seconds}
					bind:value={formInterval}
					onblur={() => validate('interval_seconds', formInterval)}
					min="10"
					max="86400"
				/>
				{#if fieldErrors.interval_seconds}
					<p class="text-xs text-error mt-1">{fieldErrors.interval_seconds}</p>
				{:else}
					<p class="text-xs text-text-muted mt-1">{m['probes.Interval Help']()}</p>
				{/if}
			</div>
			<div>
				<label class="block text-xs text-text-muted mb-1" for="probe-timeout">{m['heartbeat.Timeout']()}</label>
				<input
					id="probe-timeout"
					type="number"
					class="input"
					class:input-error={!!fieldErrors.timeout_seconds}
					bind:value={formTimeout}
					onblur={() => validate('timeout_seconds', formTimeout)}
					min="1"
					max="60"
				/>
				{#if fieldErrors.timeout_seconds}
					<p class="text-xs text-error mt-1">{fieldErrors.timeout_seconds}</p>
				{:else}
					<p class="text-xs text-text-muted mt-1">{m['probes.Timeout Help']()}</p>
				{/if}
			</div>
		</div>

		<div>
			<label class="block text-xs text-text-muted mb-1" for="probe-notes">{m['probes.Notes']()}</label>
			<textarea id="probe-notes" class="input" rows="2" bind:value={formNotes} onblur={() => validate('notes', formNotes)}></textarea>
			{#if fieldErrors.notes}<p class="text-xs text-error mt-1">{fieldErrors.notes}</p>{/if}
		</div>

		<label class="flex items-center gap-2 text-sm text-text">
			<input type="checkbox" bind:checked={formEnabled} class="checkbox" />
			{m['probes.Enabled']()}
		</label>

		<div class="flex justify-end gap-2 pt-2">
			<button type="button" class="btn btn-secondary" onclick={() => (editModalOpen = false)}>{m['common.Cancel']()}</button>
			<button type="submit" class="btn btn-primary" disabled={formLoading}>
				{editingId === null ? m['probes.Add Target']() : m['common.Save']()}
			</button>
		</div>
	</form>
</Modal>

<!-- Results history Modal: chart first (latency lines per vantage + status
     timeline), raw rows one tab away. -->
<Modal
	bind:open={resultsModalOpen}
	title={m['probes.Results Title']({ name: resultsTarget?.name || '' })}
	maxWidth="56rem"
>
	{#if resultsLoading}
		<div class="py-8 text-center text-sm text-text-muted">…</div>
	{:else if results.length === 0}
		<div class="py-8 text-center">
			<p class="text-sm text-text-muted">{m['probes.No Results']()}</p>
			<p class="text-xs text-text-muted mt-1">{m['probes.No Results Desc']()}</p>
		</div>
	{:else}
		{#if vantageTracks.length >= 2}
			<!-- Latest-per-vantage panel (#277): the side-by-side "where is it
			     reachable from" view; highlighted when tracks disagree. -->
			<div class="mb-3 rounded-lg border p-3 {vantageDisagree ? 'border-warning/50 bg-warning/5' : 'border-border'}">
				<div class="flex items-center gap-2 mb-2">
					<span class="text-xs font-semibold text-text">{m['probes.Vantage Latest']()}</span>
					{#if vantageDisagree}
						<span class="badge badge-warning">{m['probes.Vantage Diff']()}</span>
					{/if}
				</div>
				<div class="grid grid-cols-1 sm:grid-cols-2 gap-2">
					{#each vantageTracks as track (track.vantage)}
						{@const s = track.latest?.status}
						<div class="flex items-center gap-2 rounded-md border border-border bg-surface px-2.5 py-1.5">
							<span class="text-xs font-mono text-text-muted shrink-0" title={track.vantage}>{track.vantage}</span>
							<span class="badge {s === 'success' ? 'badge-success' : s === 'timeout' ? 'badge-warning' : 'badge-error'}">{s || '—'}</span>
							{#if track.latest && track.latest.latency_ms > 0}
								<span class="text-xs font-mono text-text-muted">{fmtLatency(track.latest.latency_ms)}</span>
							{/if}
							<span class="flex-1"></span>
							<span class="text-xs text-text-muted shrink-0">{m['probes.Vantage Samples']({ count: track.samples })}</span>
						</div>
					{/each}
				</div>
			</div>
		{/if}
		<div class="flex items-center gap-1 mb-3 border-b border-border">
			<button
				type="button"
				onclick={() => (resultsTab = 'chart')}
				class="px-3 py-1.5 text-sm rounded-t-md transition-colors {resultsTab === 'chart' ? 'text-primary border-b-2 border-primary font-medium' : 'text-text-muted hover:text-text'}"
			>{m['probes.Tab Chart']()}</button>
			<button
				type="button"
				onclick={() => (resultsTab = 'detail')}
				class="px-3 py-1.5 text-sm rounded-t-md transition-colors {resultsTab === 'detail' ? 'text-primary border-b-2 border-primary font-medium' : 'text-text-muted hover:text-text'}"
			>{m['probes.Tab Detail']()}</button>
			<span class="flex-1"></span>
			<span class="text-xs text-text-muted">{m['probes.Vantage Samples']({ count: resultsTotal })}</span>
		</div>
		{#if resultsTab === 'chart'}
			<div class="text-xs font-semibold text-text mb-1">{m['probes.Latency Chart']()}</div>
			<Chart option={latencyChartOption} height="240px" />
			<div class="mt-4">
				<div class="text-xs font-semibold text-text mb-2">{m['probes.Status Timeline']()}</div>
				<div class="space-y-1.5">
					{#each vantageTracks as track (track.vantage)}
						{@const pct = track.samples > 0 ? Math.round((track.okCount / track.samples) * 100) : 0}
						<div class="flex items-center gap-2">
							<span class="w-36 shrink-0 truncate font-mono text-xs text-text-muted" title={track.vantage}>{track.vantage}</span>
							<div class="flex flex-1 gap-[2px] overflow-hidden" role="img"
								aria-label="{track.vantage}: {pct}% {m['probes.Success Rate']()}">
								{#each track.rows as r (r.id)}
									<span
										class="h-4 min-w-[3px] flex-1 rounded-sm {statusStripCls(r.status)}"
										title="{formatTime(r.checked_at)} · {r.status}{r.error_message ? ` · ${r.error_message}` : ''}"
									></span>
								{/each}
							</div>
							<span class="w-14 shrink-0 text-right text-xs font-mono {pct >= 100 ? 'text-success' : pct >= 50 ? 'text-warning' : 'text-error'}">{pct}%</span>
						</div>
					{/each}
				</div>
			</div>
		{:else}
			<p class="text-xs text-text-muted mb-2">{resultsTotal}</p>
			<div class="max-h-[45vh] overflow-y-auto">
				<DataTable
					columns={resultColumns}
					rows={results as unknown as Record<string, unknown>[]}
					searchableKeys={[]}
					emptyTitle={m['probes.No Results']()}
				/>
			</div>
		{/if}
	{/if}
</Modal>

<!-- Delete confirm -->
<ConfirmDialog
	bind:open={deleteDialogOpen}
	title={m['probes.Delete Title']()}
	message={m['probes.Delete Message']({ name: deleteTarget?.name || '' })}
	confirmLabel={m['common.Delete']()}
	confirmVariant="danger"
	onConfirm={confirmDelete}
/>

<!-- Certificate chain (shared component, same DTO as the device endpoint) -->
<CertificateModal bind:open={certModalOpen} portCerts={certPortCerts} />
