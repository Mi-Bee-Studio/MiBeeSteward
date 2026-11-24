<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  Scan center: the four "find devices" entry points, as one second-level tab
  bar under 资产 › 扫描. These used to be four separate sidebar entries plus
  the standalone /discovery route; they are one job (discover what is on the
  network, then look at what came back).

  Order is daily-use → occasional: scheduled tasks, their results, the ad-hoc
  quick scan, then the passive listener. Admin-only — the parent place tab is
  gated the same way, so a non-admin never reaches these paths.
-->
<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import { page } from '$app/stores';
	import type { Snippet } from 'svelte';

	let { children }: { children: Snippet } = $props();

	const tabs = [
		{ path: '/devices/scan-tasks', label: m['devices.Tab Scan Tasks']() },
		{ path: '/devices/scan-results', label: m['devices.Tab Scan Results']() },
		{ path: '/devices/scanner', label: m['devices.Tab Scanner']() },
		{ path: '/devices/discovery', label: m['devices.Tab Passive Discovery']() }
	];

	function isActive(path: string): boolean {
		return $page.url.pathname === path || $page.url.pathname.startsWith(path + '/');
	}
</script>

<div class="flex flex-col h-full">
	<nav class="sub-tabs">
		{#each tabs as tab (tab.path)}
			<a href={tab.path} class="sub-tab" class:on={isActive(tab.path)} aria-current={isActive(tab.path) ? 'page' : undefined}>
				{tab.label}
			</a>
		{/each}
	</nav>
	<div class="flex-1 overflow-auto">
		{@render children()}
	</div>
</div>

<style>
	/* Deliberately lighter than the place tab bar above it: same horizontal
	   rhythm, no surface fill, smaller type. Two bars of equal weight would
	   compete for the eye and neither would read as the current level. */
	.sub-tabs {
		display: flex;
		gap: 4px;
		overflow-x: auto;
		scrollbar-width: none;
		padding: 8px 16px 0;
		flex: none;
	}
	.sub-tabs::-webkit-scrollbar {
		display: none;
	}
	.sub-tab {
		padding: 5px 11px;
		border-radius: var(--radius-md);
		font-size: 0.75rem;
		font-weight: 500;
		white-space: nowrap;
		color: var(--color-text-muted);
		border: 1px solid transparent;
		transition: color 0.15s ease, background-color 0.15s ease, border-color 0.15s ease;
	}
	.sub-tab:hover {
		color: var(--color-text);
		background: var(--color-surface-2);
	}
	.sub-tab.on {
		color: var(--color-primary);
		background: color-mix(in srgb, var(--color-primary) 12%, transparent);
		border-color: color-mix(in srgb, var(--color-primary) 35%, transparent);
	}
	.sub-tab:focus-visible {
		outline: 2px solid var(--color-primary);
		outline-offset: 1px;
	}
</style>
