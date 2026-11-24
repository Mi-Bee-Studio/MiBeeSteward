<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero
  General Public License v3.0 or later. See LICENSE-COMMERCIAL.md.
-->
<script lang="ts">
	import { onMount } from 'svelte';
	import { api } from '$lib/api/client';
	import { m } from '$lib/i18n-paraglide';
	import {
		Network as NetworkIcon, Globe, Shield, Activity, Route, Server, Eye,
		ChevronRight, Info
	} from '@lucide/svelte';
	import { formatDateTime } from '$lib/utils';

	// Network-centric view (#772): networks are a first-class entity — an
	// overview of every network's egress/quality/routing/assets, drill-down
	// into one network, and an inter-network topology. Pure read model: every
	// byte comes from endpoints the UI already uses; no schema, no new API.
	// The lab networks here are an experimentable sample; the structure fits
	// any home/lab/multi-site network.

	type View = 'overview' | 'network' | 'topology' | 'assets';

	interface NetRow { id: number; name: string; cidr?: string; site?: string; agent_id?: string | null; agent_last_used_at?: string | null; agent_stale?: boolean }
	interface DeviceRow {
		id: number; name: string; ip_address?: string; mac_address?: string; type: string;
		status: string; network_id: number | null; scan_attributes?: Record<string, unknown> | null;
		dictionary_tags?: { key: string; name: string; color: string }[];
	}
	interface QualityVantage { vantage: string; network_name?: string; verdict: string; score: number; reasons?: string[] }
	interface QualityCategory { category: string; vantages?: QualityVantage[] }
	interface QualityReport { categories?: QualityCategory[] }
	interface EgressVantage {
		vantage: string; network_name?: string; ips?: { ip: string }[]; local_gateway?: string; local_iface?: string;
	}
	interface EgressReport { vantages?: EgressVantage[] }
	interface MatrixCell {
		source: string; destination: string; ok_rate: number; p50_ms: number; loss_pct?: number; jitter_ms?: number;
	}
	interface MatrixReport { cells?: MatrixCell[]; sources?: { id: string; label: string }[]; destinations?: { id: string; label: string }[] }
	interface FleetAgent { agent_id: string; version?: string; last_report_at?: string }

	interface Gateway { nat_mapping?: string; public_ip?: string; wan_ip?: string; stun_servers_seen?: number; upnp_available?: boolean }
	interface NetCard {
		id: number; name: string; cidr: string; site: string;
		agent: string; agentStale: boolean; agentLastUsed?: string;
		devices: number; online: number; offline: number;
		gateway: Gateway | null; nat: string | null; publicIp: string | null;
		egressIp: string | null; localGw: string | null; iface: string | null;
		quality: { ok: number; degraded: number; bad: number; vantages: QualityVantage[] };
		links: { to: string; rtt: number | null; loss: number | null }[];
		assets: DeviceRow[];
	}

	let view = $state<View>('overview');
	let selectedId = $state<number | null>(null);
	let loading = $state(true);
	let error = $state('');

	let networks = $state<NetRow[]>([]);
	let devices = $state<DeviceRow[]>([]);
	let quality = $state<QualityReport | null>(null);
	let egress = $state<EgressReport | null>(null);
	let matrix = $state<MatrixReport | null>(null);
	let fleet = $state<FleetAgent[]>([]);

	onMount(loadAll);

	async function loadAll() {
		loading = true; error = '';
		try {
			const nets = await api.get<{ networks: NetRow[] }>('/networks');
			networks = nets.networks || [];
			// Best-effort secondary sources: a blocked probe endpoint degrades only
			// its own panel, never the whole network list (the established posture).
			await Promise.all([
				api.get<{ devices: DeviceRow[]; total: number }>('/devices?limit=500')
					.then(r => { devices = r.devices || []; }).catch(() => {}),
				api.get<QualityReport>('/probe-quality?window=30').then(r => { quality = r; }).catch(() => {}),
				api.get<EgressReport>('/probe-egress').then(r => { egress = r; }).catch(() => {}),
				api.get<MatrixReport>('/probe-matrix?window=30').then(r => { matrix = r; }).catch(() => {}),
				api.get<{ agents: FleetAgent[] }>('/agents/status').then(r => { fleet = r.agents || []; }).catch(() => {})
			]);
		} catch (err) {
			error = err instanceof Error ? err.message : String(err);
		} finally {
			loading = false;
		}
	}

	function netName(id: number | null): string {
		if (id == null) return '—';
		return networks.find(n => n.id === id)?.name || `#${id}`;
	}

	function gatewayOf(device: DeviceRow): Gateway | null {
		const sa = device.scan_attributes as { gateway?: Gateway } | null | undefined;
		return sa?.gateway ?? null;
	}

	// Map a quality vantage id (e.g. "agent:nanopineo") to the network whose
	// collector it is — the same mapping the quality panel itself uses.
	function networkForVantage(v: string): string | null {
		const bare = v.startsWith('agent:') ? v.slice(6) : v;
		if (bare === 'center') return null;
		const net = networks.find(n => n.agent_id === bare || n.id.toString() === bare);
		if (net) return net.name;
		const vantageData = egress?.vantages?.find(e => e.vantage === v);
		return vantageData?.network_name || null;
	}

	function egressForNetwork(net: NetRow): { ip: string | null; gateway: string | null; iface: string | null } {
		const v = egress?.vantages?.find(e => e.vantage === `agent:${net.agent_id}` || e.network_name === net.name || e.vantage === net.agent_id);
		return { ip: v?.ips?.[0]?.ip ?? null, gateway: v?.local_gateway ?? null, iface: v?.local_iface ?? null };
	}

	// All networks as enriched cards, derived from the flat API responses.
	const cards = $derived.by<NetCard[]>(() => networks.map(n => {
		const own = devices.filter(d => d.network_id === n.id);
		const gwDev = own.find(d => gatewayOf(d));
		const gw = gwDev ? gatewayOf(gwDev) : null;
		const eg = egressForNetwork(n);
		const cats = quality?.categories || [];
		const vantes = cats.flatMap(c => c.vantages || []).filter(v => {
			const nn = networkForVantage(v.vantage);
			return nn === n.name || v.network_name === n.name;
		});
		// A cell belongs to a network when its source or destination agent maps here.
		const links = (matrix?.cells || [])
			.filter(c => {
				const src = c.source.replace(/^agent:/, '');
				const dst = c.destination.replace(/^agent:/, '');
				return src === n.agent_id || dst === n.agent_id;
			})
			.slice(0, 4)
			.map(c => {
				const peerId = c.source.replace(/^agent:/, '') === n.agent_id
					? c.destination.replace(/^agent:/, '')
					: c.source.replace(/^agent:/, '');
				return { to: peerId === 'center' ? 'center' : netName(networks.find(x => x.agent_id === peerId)?.id ?? -1), rtt: c.p50_ms ?? null, loss: c.loss_pct ?? null };
			});
		return {
			id: n.id, name: n.name, cidr: n.cidr || '', site: n.site || '',
			agent: n.agent_id || 'center', agentStale: !!n.agent_stale, agentLastUsed: n.agent_last_used_at || undefined,
			devices: own.length, online: own.filter(d => d.status === 'online').length,
			offline: own.filter(d => d.status === 'offline').length,
			gateway: gw, nat: gw?.nat_mapping || null,
			publicIp: gw?.public_ip || gw?.wan_ip || null,
			egressIp: eg.ip, localGw: eg.gateway, iface: eg.iface,
			quality: { ok: 100, degraded: 0, bad: 0, vantages: vantes },
			links, assets: own
		};
	}));

	const selected = $derived(cards.find(c => c.id === selectedId) || cards[0] || null);
	const avgQuality = $derived(cards.length ? Math.round(cards.reduce((a, c) => {
		const vs = c.quality.vantages;
		return a + (vs.length ? vs.reduce((s, v) => s + (v.score || 0), 0) / vs.length : 100);
	}, 0) / cards.length) : 100);
	const totalDevices = $derived(cards.reduce((a, c) => a + c.devices, 0));
	const totalOnline = $derived(cards.reduce((a, c) => a + c.online, 0));
	const gatewayCount = $derived(cards.filter(c => c.nat).length);

	function open(id: number) { selectedId = id; view = 'network'; }
	function nav(v: View) { view = v; }
</script>

<style>
	/* All colours come from themes.css tokens: the page must render correctly in
	   both light and dark without a local palette (it previously hardcoded a
	   GitHub-dark set behind undefined vars, which made light theme stay dark). */
	/* Page gutter. The view previously rendered flush against the sidebar and
	   the place tab bar, so the heading looked cut off and text ran to the
	   viewport edge; every other page in the app uses a 24px gutter. */
	.nc-page{padding:24px}
	.nc-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;flex-wrap:wrap;margin-bottom:24px}
		.nc-eyebrow{font-family:var(--font-mono);font-size:12px;letter-spacing:.12em;color:var(--color-accent-cyan);margin-bottom:8px}
	.nc-title{font-size:26px;font-weight:600;letter-spacing:-.02em;line-height:1.3;margin:0;color:var(--color-text)}
	.nc-sub{color:var(--color-text-muted);font-size:13px;max-width:68ch;margin-top:8px}
	.nc-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--color-border);border:1px solid var(--color-border);border-radius:var(--radius-lg);overflow:hidden;margin-bottom:24px}
	.nc-stat{background:var(--color-surface);padding:15px 18px}
	.nc-stat .k{color:var(--color-text-muted);font-size:12px;display:flex;align-items:center;gap:7px}
	.nc-stat .k :global(svg){width:14px;height:14px}
	.nc-stat .v{font-size:19px;font-weight:600;letter-spacing:-.02em;line-height:1.4;margin-top:4px;color:var(--color-text);font-variant-numeric:tabular-nums}
	.nc-stat .v small{font-size:12px;color:var(--color-text-muted);font-weight:400;margin-left:5px}
	.nc-sec{display:flex;align-items:center;gap:10px;margin:0 0 12px}
	.nc-sec h3{font-size:15px;font-weight:600;margin:0;color:var(--color-text)}
	.nc-sec .line{flex:1;height:1px;background:var(--color-border)}
	.nc-sec .note{color:var(--color-text-muted);font-size:12px;white-space:nowrap}
	.nc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:16px}
	.nc-card{background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius-lg);padding:18px;cursor:pointer;transition:.16s;position:relative;overflow:hidden}
	.nc-card::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:var(--color-accent-cyan);opacity:.5}
	.nc-card:hover{transform:translateY(-2px);border-color:var(--color-border-strong)}
	.nc-card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:10px}
	.nc-card-name{display:flex;align-items:center;gap:10px}
	.nc-ci{width:38px;height:38px;border-radius:9px;background:color-mix(in srgb, var(--color-info) 13%, transparent);color:var(--color-info);display:grid;place-items:center}
	.nc-ci :global(svg){width:20px;height:20px}
	.nc-card-name h4{font-size:17px;font-weight:600;margin:0;color:var(--color-text)}
	.nc-card-name .cidr{font-family:var(--font-mono);font-size:12px;color:var(--color-text-muted);margin-top:2px}
	/* A prose subtitle (the interconnect teaser) must not wear the address
	   style: no monospace, wraps inside the card instead of overflowing. */
	.nc-card-name .cidr.prose{font-family:inherit;line-height:1.5;margin-top:4px}
	/* 1.25fr for the address column: an IPv4 or IPv6 egress address is the
	   longest of the three values, and an ellipsised address is useless. Equal
	   columns made it read "121.8.49..." at 1440. */
	.nc-metrics{display:grid;grid-template-columns:1.25fr 1fr 1fr;gap:8px;margin:16px 0 12px}
	.nc-m{background:var(--color-bg);border:1px solid var(--color-border);border-radius:var(--radius-md);padding:9px 11px}
	.nc-m .k{color:var(--color-text-muted);font-size:12px}
	/* Addresses never wrap (a split IPv4 is unreadable and makes one card's
	   metric row taller than its neighbours'); they shrink a little instead.
	   clamp() holds the floor at 12px so it stays legible on narrow cards. */
	.nc-m .v{font-family:var(--font-mono);font-size:clamp(12px,1.05vw,13px);line-height:1.45;margin-top:4px;white-space:nowrap;color:var(--color-text)}
	.nc-q{display:flex;align-items:center;gap:10px;margin-bottom:12px}
	.nc-qbar{flex:1;height:6px;background:var(--color-surface-2);border-radius:6px;overflow:hidden}
	.nc-qbar i{display:block;height:100%}
	.nc-qbar i:first-child{border-radius:6px 0 0 6px}
	.nc-qbar i:last-child{border-radius:0 6px 6px 0}
	.nc-qbar i:only-child{border-radius:6px}
	.nc-card-foot{display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--color-border);padding-top:11px;color:var(--color-text-muted);font-size:12px}
	.nc-go{color:var(--color-accent-cyan);display:inline-flex;align-items:center;gap:4px}
	.nc-go :global(svg){width:13px;height:13px}
	.nc-badge{display:inline-flex;align-items:center;gap:5px;font-size:12px;padding:3px 9px;border-radius:20px;font-family:var(--font-mono);white-space:nowrap;line-height:1.5}
	.nc-badge .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
	.nc-b-ok{background:color-mix(in srgb, var(--color-success) 14%, transparent);color:var(--color-success)}
	.nc-b-warn{background:color-mix(in srgb, var(--color-warning) 14%, transparent);color:var(--color-warning)}
	.nc-b-neutral{background:var(--color-surface-2);color:var(--color-text-muted)}
	.nc-panel{background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius-lg);padding:18px}
	.nc-detail{display:grid;grid-template-columns:1fr 1fr;gap:16px}
	.nc-panel.full{grid-column:1/-1}
	.nc-ph{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
	.nc-ph h4{font-size:15px;font-weight:600;margin:0;display:flex;align-items:center;gap:8px;color:var(--color-text)}
	.nc-ph h4 :global(svg){width:16px;height:16px;color:var(--color-accent-cyan)}
	.nc-ph .hint{color:var(--color-text-muted);font-size:12px}
	.nc-kv{display:grid;grid-template-columns:1fr 1fr;gap:10px}
	.nc-kv .it{background:var(--color-bg);border:1px solid var(--color-border);border-radius:var(--radius-md);padding:11px 12px}
	.nc-kv .k{color:var(--color-text-muted);font-size:12px;display:flex;align-items:center;gap:6px}
	.nc-kv .k :global(svg){width:13px;height:13px}
	.nc-kv .v{font-size:17px;font-weight:600;margin-top:4px;color:var(--color-text)}
	.nc-kv .v.mono{font-family:var(--font-mono);font-size:13px;font-weight:400}
	.nc-note{color:var(--color-text-muted);font-size:12px;margin-top:12px;padding:9px 11px;background:color-mix(in srgb, var(--color-warning) 10%, transparent);border-radius:var(--radius-sm);display:flex;gap:8px;align-items:flex-start}
	.nc-note :global(svg){width:14px;height:14px;color:var(--color-warning);flex:none;margin-top:1px}
	.nc-vrow{display:flex;align-items:center;gap:9px;padding:7px 10px;background:var(--color-bg);border:1px solid var(--color-border);border-radius:var(--radius-sm);margin-bottom:5px;font-size:12px;color:var(--color-text)}
	.nc-vrow .vn{flex:1}
	.nc-table{width:100%;border-collapse:collapse;font-size:12px;color:var(--color-text)}
	.nc-table th{text-align:left;color:var(--color-text-muted);font-size:12px;font-weight:500;padding:8px 9px;border-bottom:1px solid var(--color-border)}
	.nc-table td{padding:8px 9px;border-bottom:1px solid var(--color-border)}
	.nc-table tr:last-child td{border-bottom:0}
	.nc-table tbody tr:hover{background:var(--color-surface-2)}
	.nc-table .mono{font-family:var(--font-mono);font-size:12px}
	.nc-sdot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:6px}
	.nc-on{background:var(--color-success)}.nc-off{background:var(--color-error)}
	.nc-chip{display:inline-block;font-size:12px;line-height:1.5;padding:1px 7px;border-radius:5px;background:var(--color-surface-2);color:var(--color-text-muted);margin-right:4px}
	.nc-map{height:400px;background:var(--color-bg);border:1px solid var(--color-border);border-radius:var(--radius-lg);overflow:hidden}
	.nc-map svg{width:100%;height:100%}
	.nc-node{cursor:pointer}
	.nc-node rect{fill:var(--color-surface-2);stroke:var(--color-border);stroke-width:1.2}
	.nc-node text{font-size:12px;fill:var(--color-text);pointer-events:none}
	.nc-node .sub{font-family:var(--font-mono);font-size:12px;fill:var(--color-text-muted)}
	.nc-edge{stroke:var(--color-text-muted);stroke-width:1.5;fill:none;opacity:.5}
	.nc-edge.hot{stroke:var(--color-accent-cyan);stroke-width:2;opacity:.9}
	.nc-elab{font-family:var(--font-mono);font-size:12px;fill:var(--color-text-muted);pointer-events:none}
	.nc-seg{display:inline-flex;background:var(--color-surface);border:1px solid var(--color-border);border-radius:var(--radius-lg);padding:3px}
	.nc-seg button{border:0;background:transparent;color:var(--color-text-muted);font:inherit;font-size:13px;padding:7px 13px;border-radius:var(--radius-sm);cursor:pointer;display:inline-flex;align-items:center;gap:6px;transition:color .15s ease,background-color .15s ease}
	.nc-seg button:hover{color:var(--color-text)}
	.nc-seg button.on{background:color-mix(in srgb,var(--color-primary) 16%,transparent);color:var(--color-primary);font-weight:600}
	.nc-seg button:focus-visible{outline:2px solid var(--color-primary);outline-offset:1px}
	.nc-seg button :global(svg){width:14px;height:14px}
	.nc-crumb{color:var(--color-text-muted);font-size:12px;margin-bottom:12px}
	.nc-crumb b{color:var(--color-text);font-weight:500}
	.nc-loading{padding:60px;text-align:center;color:var(--color-text-muted)}
	@media(max-width:760px){
		.nc-stats{grid-template-columns:repeat(2,1fr)}
		.nc-detail{grid-template-columns:1fr}
		.nc-grid{grid-template-columns:1fr}
		.nc-map{height:320px}
		/* One column of cards: the metric labels wrapped ("设备 / 在" / "线")
		   because the padding was tuned for a 3-across desktop card. */
		.nc-page{padding:16px}
		.nc-m{padding:8px 9px}
		.nc-m .k{font-size:12px;line-height:1.35}
	}
</style>

{#if loading}
	<div class="nc-loading">{m['common.Loading']()}</div>
{:else if error}
	<div class="nc-loading">{error}</div>
{:else}
<div class="nc-page">

	<div class="nc-head">
		<div>
			<div class="nc-eyebrow">{m['networkCenter.Eyebrow']()}</div>
			<h1 class="nc-title">{view === 'overview' ? m['networkCenter.Overview Title']() : view === 'topology' ? m['networkCenter.Topology Title']() : view === 'assets' ? m['networkCenter.Assets Title']() : selected?.name}</h1>
			<p class="nc-sub">{view === 'overview' ? m['networkCenter.Overview Desc']() : view === 'topology' ? m['networkCenter.Topology Desc']() : view === 'assets' ? m['networkCenter.Assets Desc']() : (selected ? `${selected.site} · ${selected.agent} · ${selected.devices} ${m['networkCenter.Stat Devices']()}` : '')}</p>
		</div>
		<div class="nc-seg">
			<button class:on={view === 'overview'} onclick={() => nav('overview')}><Eye />{m['networkCenter.Overview Title']()}</button>
			<button class:on={view === 'topology'} onclick={() => nav('topology')}><Route />{m['networkCenter.Topology Title']()}</button>
			<button class:on={view === 'assets'} onclick={() => nav('assets')}><Server />{m['networkCenter.Assets Title']()}</button>
		</div>
	</div>

	<div class="nc-stats">
		<div class="nc-stat"><div class="k"><NetworkIcon />{m['networkCenter.Stat Networks']()}</div><div class="v">{cards.length}<small>{m['networkCenter.Segments']()}</small></div></div>
		<div class="nc-stat"><div class="k"><Server />{m['networkCenter.Stat Devices']()}</div><div class="v">{totalDevices}<small>{m['networkCenter.Online']()} {totalOnline}</small></div></div>
		<div class="nc-stat"><div class="k"><Globe />{m['networkCenter.Stat Gateways']()}</div><div class="v">{gatewayCount}<small>{m['networkCenter.Stat Gateways']()}</small></div></div>
		<div class="nc-stat"><div class="k"><Activity />{m['networkCenter.Stat Avg Quality']()}</div><div class="v">{avgQuality}<small>/ 100</small></div></div>
	</div>

	<!-- ══ OVERVIEW ══ -->
	{#if view === 'overview'}
		<div class="nc-sec"><h3>{m['networkCenter.Stat Networks']()}</h3><div class="line"></div></div>
		<div class="nc-grid">
			{#each cards as c (c.id)}
			<div class="nc-card" role="button" tabindex="0" onclick={() => open(c.id)} onkeydown={(e) => e.key === 'Enter' && open(c.id)}>
				<div class="nc-card-top">
					<div class="nc-card-name"><div class="nc-ci"><NetworkIcon /></div><div><h4>{c.name}</h4><div class="cidr">{c.cidr || '—'} · {c.site}</div></div></div>
					{#if c.nat}
						<span class="nc-badge nc-b-warn"><span class="dot"></span>{c.nat === 'eim' ? 'EIM' : c.nat === 'edm' ? 'EDM' : c.nat}</span>
					{:else}
						<span class="nc-badge nc-b-neutral">{m['networkCenter.No Gateway']()}</span>
					{/if}
				</div>
				<div class="nc-metrics">
					<div class="nc-m"><div class="k">{m['networkCenter.Public IP']()}</div><div class="v">{c.egressIp || c.publicIp || '—'}</div></div>
					<div class="nc-m"><div class="k">{m['networkCenter.Devices Online']()}</div><div class="v">{c.devices} / {c.online}</div></div>
					<div class="nc-m"><div class="k">{m['networkCenter.Agent']()}</div><div class="v">{c.agent}</div></div>
				</div>
				<!-- Quality strip: from real vantage verdicts; neutral when none -->
				<div class="nc-q">
					<div class="nc-qbar">
						{#if c.quality.vantages.length}
							{#each c.quality.vantages as v}
								<i style="width:{100 / c.quality.vantages.length}%;background:{v.verdict === 'ok' ? 'var(--color-success)' : v.verdict === 'degraded' ? 'var(--color-warning)' : 'var(--color-error)'}"></i>
							{/each}
						{:else}
							<i style="width:100%;background:var(--color-surface-2)"></i>
						{/if}
					</div>
					<span style="font-size:12px;color:var(--color-text-muted)">{m['networkCenter.Quality']()} {c.quality.vantages.length ? Math.round(c.quality.vantages.reduce((a,v)=>a+(v.score||0),0)/c.quality.vantages.length) : '—'}</span>
				</div>
				<div class="nc-card-foot"><span>{c.agent}{c.agentStale ? ' · stale' : ''}</span><span class="nc-go">{m['networkCenter.Card Cta']()} <ChevronRight /></span></div>
			</div>
			{/each}

			<!-- interconnection teaser card -->
			<div class="nc-card" role="button" tabindex="0" onclick={() => nav('topology')} onkeydown={(e) => e.key === 'Enter' && nav('topology')} style="background:linear-gradient(150deg,color-mix(in srgb,var(--color-accent-cyan) 8%,transparent),var(--color-surface))">
				<div class="nc-card-top"><div class="nc-card-name"><div class="nc-ci" style="background:color-mix(in srgb,var(--color-accent-cyan) 13%,transparent);color:var(--color-accent-cyan)"><Route /></div><div><h4>{m['networkCenter.Interconnect']()}</h4><div class="cidr prose">{m['networkCenter.Interconnect Desc']()}</div></div></div></div>
				<div class="nc-metrics" style="margin-top:18px">
					{#each cards as c (c.id)}
						<div class="nc-m"><div class="k">{c.name}</div><div class="v" style="font-size:12px">{c.links.length} {m['networkCenter.Route Hint']()}</div></div>
					{/each}
				</div>
				<div class="nc-card-foot"><span>{cards.length} {m['networkCenter.Stat Networks']()}</span><span class="nc-go">{m['networkCenter.View Topology']()} <ChevronRight /></span></div>
			</div>
		</div>
	{/if}

	<!-- ══ NETWORK DETAIL ══ -->
	{#if view === 'network' && selected}
		<div class="nc-stats">
			<div class="nc-stat"><div class="k"><Globe />{m['networkCenter.Public IP']()}</div><div class="v" style="font-size:17px;font-family:var(--font-mono)">{selected.egressIp || selected.publicIp || '—'}</div></div>
			<div class="nc-stat"><div class="k"><Shield />{m['networkCenter.NAT Mapping']()}</div><div class="v" style="font-size:17px">{selected.nat === 'eim' ? 'EIM' : selected.nat === 'edm' ? 'EDM' : '—'}</div></div>
			<div class="nc-stat"><div class="k"><Activity />{m['networkCenter.Quality']()}</div><div class="v">{selected.quality.vantages.length ? Math.round(selected.quality.vantages.reduce((a,v)=>a+(v.score||0),0)/selected.quality.vantages.length) : '—'}<small>/ 100</small></div></div>
			<div class="nc-stat"><div class="k"><Server />{m['networkCenter.Stat Devices']()}</div><div class="v">{selected.online}<small>/ {selected.devices}</small></div></div>
		</div>
		<div class="nc-detail">
			<section class="nc-panel">
				<div class="nc-ph"><h4><Globe />{m['networkCenter.Gateway Profile']()}</h4><span class="hint">gateway_probe</span></div>
				<div class="nc-kv">
					<div class="it"><div class="k"><Globe />{m['networkCenter.Public IP']()}</div><div class="v mono">{selected.publicIp || selected.egressIp || '—'}</div></div>
					<div class="it"><div class="k"><Shield />{m['networkCenter.NAT Mapping']()}</div><div class="v">{selected.nat === 'eim' ? 'EIM' : selected.nat === 'edm' ? 'EDM' : '—'}</div></div>
					<div class="it"><div class="k"><Route />{m['networkCenter.Local Gateway']()}</div><div class="v mono">{selected.localGw || '—'} · {selected.iface || '—'}</div></div>
					<div class="it"><div class="k"><Activity />{m['networkCenter.Egress Sources']()}</div><div class="v">{selected.gateway?.stun_servers_seen ? `STUN × ${selected.gateway.stun_servers_seen}` : '—'}</div></div>
				</div>
				<div class="nc-note"><Info /><span>{selected.nat === 'edm' ? m['networkCenter.NAT EDM Note']() : selected.nat === 'eim' ? m['networkCenter.NAT EIM Note']() : m['networkCenter.NAT Unknown Note']()}</span></div>
			</section>

			<section class="nc-panel">
				<div class="nc-ph"><h4><Activity />{m['networkCenter.Quality Panel']()}</h4><span class="hint">{m['networkCenter.Quality Hint']()}</span></div>
				{#if selected.quality.vantages.length}
					{#each selected.quality.vantages as v}
						<div class="nc-vrow">
							<span class="vn">{v.network_name || networkForVantage(v.vantage) || v.vantage}</span>
							<span class="nc-badge {v.verdict === 'ok' ? 'nc-b-ok' : v.verdict === 'degraded' ? 'nc-b-warn' : 'nc-b-neutral'}"><span class="dot"></span>{v.verdict}</span>
							<span style="font-family:var(--font-mono);font-size:12px">{v.score}</span>
						</div>
					{/each}
				{:else}
					<div style="color:var(--color-text-muted);font-size:12px;padding:10px 0">—</div>
				{/if}
				<div class="nc-note"><Info /><span>{m['networkCenter.Quality Isolation Note']()}</span></div>
			</section>

			<section class="nc-panel">
				<div class="nc-ph"><h4><Route />{m['networkCenter.Route Panel']()}</h4><span class="hint">{m['networkCenter.Route Hint']()}</span></div>
				<table class="nc-table"><thead><tr><th>{m['networkCenter.Peer']()}</th><th>{m['networkCenter.RTT']()}</th><th>{m['networkCenter.Loss']()}</th><th>{m['networkCenter.Status']()}</th></tr></thead><tbody>
					{#each selected.links as l}
						<tr><td>{l.to}</td><td class="mono">{l.rtt != null ? l.rtt + ' ms' : '—'}</td><td class="mono">{l.loss != null ? l.loss + '%' : '—'}</td><td>{m['networkCenter.Interconnect']()}</td></tr>
					{/each}
					{#if selected.links.length === 0}<tr><td colspan="4" style="color:var(--color-text-muted)">—</td></tr>{/if}
				</tbody></table>
			</section>

			<section class="nc-panel">
				<div class="nc-ph"><h4><NetworkIcon />{m['networkCenter.Inter networks']()}</h4><span class="hint">{m['networkCenter.Click Switch']()}</span></div>
				{#each cards.filter(c => c.id !== selected.id) as c (c.id)}
					<div class="nc-vrow" role="button" tabindex="0" onclick={() => open(c.id)} onkeydown={(e) => e.key === 'Enter' && open(c.id)} style="cursor:pointer">
						<span class="vn"><NetworkIcon size={14} /> {c.name} <span style="color:var(--color-text-muted)">{c.cidr}</span></span><span style="color:var(--color-text-muted);font-size:12px">{c.agent}</span><ChevronRight size={14} />
					</div>
				{/each}
				<button class="nc-go" style="border:0;background:transparent;cursor:pointer;margin-top:10px;font-size:12px" onclick={() => nav('overview')}>← {m['networkCenter.Back Overview']()}</button>
			</section>

			<section class="nc-panel full">
				<div class="nc-ph"><h4><Server />{m['networkCenter.Network Assets']()}</h4><span class="hint">{selected.assets.length} {m['networkCenter.Assets Hint']()} {selected.devices}</span></div>
				<table class="nc-table"><thead><tr><th>{m['networkCenter.Name']()}</th><th>{m['networkCenter.IP']()}</th><th>{m['networkCenter.MAC']()}</th><th>{m['networkCenter.Type']()}</th><th>{m['networkCenter.Status']()}</th></tr></thead><tbody>
					{#each selected.assets as a (a.id)}
						<tr><td>{a.name}</td><td class="mono">{a.ip_address || '—'}</td><td class="mono">{a.mac_address || '—'}</td><td>{a.type}</td><td><span class="nc-sdot {a.status === 'online' ? 'nc-on' : 'nc-off'}"></span>{a.status === 'online' ? 'online' : 'offline'}</td></tr>
					{/each}
				</tbody></table>
			</section>
		</div>
	{/if}

	<!-- ══ TOPOLOGY ══ -->
	{#if view === 'topology'}
		<section class="nc-panel" style="margin-bottom:16px">
			<div class="nc-ph"><h4><Route />{m['networkCenter.Topology Title']()}</h4><span class="hint">{m['networkCenter.Click Switch']()}</span></div>
			<div class="nc-map">
				<svg viewBox="0 0 1000 420" preserveAspectRatio="xMidYMid meet">
					<defs><marker id="ncAr" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0 0L6 3L0 6" fill="none" style="stroke:var(--color-accent-cyan)" stroke-width="1.2"/></marker></defs>
					<!-- WAN node -->
					<g class="nc-node" onclick={() => nav('overview')} onkeydown={(e) => e.key === 'Enter' && nav('overview')} role="button" tabindex="0" transform="translate(430,24)">
						<rect width="140" height="52" rx="9" /><text x="16" y="24">WAN</text><text class="sub" x="16" y="40">{m['networkCenter.Egress Sources']()}</text>
					</g>
					<!-- network nodes, laid out left/right -->
					{#each cards as c, i (c.id)}
						{@const x = i % 2 === 0 ? 110 : 650}
						{@const y = 200 + (i > 1 ? 90 : 0)}
						<g class="nc-node" onclick={() => open(c.id)} onkeydown={(e) => e.key === 'Enter' && open(c.id)} role="button" tabindex="0" transform="translate({x},{y})">
							<rect width="240" height="66" rx="9" /><text x="16" y="26">{c.name}</text><text class="sub" x="16" y="43">{c.cidr || '—'}</text><text class="sub" x="16" y="58">{c.devices} {m['networkCenter.Stat Devices']()} · {m['networkCenter.Quality']()} {c.quality.vantages.length ? Math.round(c.quality.vantages.reduce((a,v)=>a+(v.score||0),0)/c.quality.vantages.length) : '—'}</text>
						</g>
						<path class="nc-edge hot" d="M{x + (i % 2 === 0 ? 180 : 0)} {y} Q 500 {y - 90} {i % 2 === 0 ? 470 : 530} 76" marker-end="url(#ncAr)" />
					{/each}
					<!-- cross-network links -->
					{#each matrix?.cells || [] as c (c.source + '-' + c.destination)}
						{@const srcNet = networks.find(n => n.agent_id === c.source.replace(/^agent:/,''))}
						{@const dstNet = networks.find(n => n.agent_id === c.destination.replace(/^agent:/,''))}
						{#if srcNet && dstNet}
							{@const si = cards.findIndex(x => x.id === srcNet.id)}
							{@const di = cards.findIndex(x => x.id === dstNet.id)}
							{@const sx = si % 2 === 0 ? 230 : 770}
							{@const dx = di % 2 === 0 ? 230 : 770}
							{#if si < di}
								<path class="nc-edge" d="M{sx} {si > 1 ? 266 : 232} Q 500 330 {dx} {di > 1 ? 266 : 232}" stroke-dasharray="5 4" />
								<text class="nc-elab" x="470" y="306">{c.p50_ms} ms · {c.loss_pct}%</text>
							{/if}
						{/if}
					{/each}
				</svg>
			</div>
		</section>
		<div class="nc-detail">
			<section class="nc-panel">
				<div class="nc-ph"><h4><Route />{m['networkCenter.Cross Link Detail']()}</h4><span class="hint">{m['networkCenter.From Matrix']()}</span></div>
				<table class="nc-table"><thead><tr><th>{m['networkCenter.Source Net']()}</th><th>{m['networkCenter.Dest Net']()}</th><th>{m['networkCenter.RTT']()}</th><th>{m['networkCenter.Loss']()}</th><th>{m['networkCenter.Jitter']()}</th></tr></thead><tbody>
					{#each matrix?.cells || [] as c (c.source + '-' + c.destination)}
						{@const srcNet = networks.find(n => n.agent_id === c.source.replace(/^agent:/,''))}
						{@const dstNet = networks.find(n => n.agent_id === c.destination.replace(/^agent:/,''))}
						<tr><td>{srcNet?.name || c.source}</td><td>{dstNet?.name || c.destination}</td><td class="mono">{c.p50_ms} ms</td><td class="mono">{c.loss_pct}%</td><td class="mono">{c.jitter_ms != null ? c.jitter_ms.toFixed(2) + ' ms' : '—'}</td></tr>
					{/each}
				</tbody></table>
			</section>
			<section class="nc-panel">
				<div class="nc-ph"><h4><Info />{m['networkCenter.Why This IA']()}</h4></div>
				<p style="color:var(--color-text-muted);font-size:13px;margin:0">{m['networkCenter.Why This IA Text']()}</p>
			</section>
		</div>
	{/if}

	<!-- ══ ALL ASSETS ══ -->
	{#if view === 'assets'}
		<section class="nc-panel">
			<div class="nc-ph"><h4><Server />{m['networkCenter.Assets Title']()}</h4><span class="hint">{devices.length}</span></div>
			<table class="nc-table"><thead><tr><th>{m['networkCenter.Name']()}</th><th>{m['networkCenter.IP']()}</th><th>{m['networkCenter.Stat Networks']()}</th><th>{m['networkCenter.Type']()}</th><th>{m['networkCenter.Status']()}</th></tr></thead><tbody>
				{#each devices as d (d.id)}
					<tr role="button" tabindex="0" onclick={() => d.network_id && open(d.network_id)} onkeydown={(e) => e.key === 'Enter' && d.network_id && open(d.network_id)} style="cursor:pointer">
						<td>{d.name}</td><td class="mono">{d.ip_address || '—'}</td><td><span class="nc-chip">{netName(d.network_id)}</span></td><td>{d.type}</td><td><span class="nc-sdot {d.status === 'online' ? 'nc-on' : 'nc-off'}"></span>{d.status === 'online' ? 'online' : 'offline'}</td>
					</tr>
				{/each}
			</tbody></table>
		</section>
	{/if}

</div>
{/if}
