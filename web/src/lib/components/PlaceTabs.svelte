<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  PlaceTabs — the one tab bar each "place" (资产 / 网络 / 系统管理) shows.

  The navigation model this implements: the sidebar holds PLACES, not
  features. Every capability added later becomes a tab in an existing place
  instead of a new top-level entry, which is what kept growing the sidebar to
  13 entries and burying the daily-use items.

  Tab state lives in the URL path (plain <a href>), not local state, so tabs
  are linkable, survive reload, and the browser back button walks them.
-->
<script lang="ts">
	import { page } from '$app/stores';
	import type { PlaceTab } from '$lib/components/placeTabs';

	let { tabs }: { tabs: PlaceTab[] } = $props();

	function isActive(tab: PlaceTab): boolean {
		const pathname = $page.url.pathname;
		if (tab.exact) return pathname === tab.path || pathname === tab.path + '/';
		if (pathname === tab.path || pathname.startsWith(tab.path + '/')) return true;
		return (tab.also ?? []).some((p) => pathname === p || pathname.startsWith(p + '/'));
	}
</script>

<!-- A single tab is not a choice: for a non-admin whose place has one visible
     member (网络 → only the overview, 系统管理 → only settings), the bar would
     be pure decoration. Render it only when there is something to switch to. -->
<nav class="place-tabs" aria-label="Section" hidden={tabs.length < 2}>
	{#each tabs as tab (tab.path)}
		{@const active = isActive(tab)}
		<a
			href={tab.path}
			class="place-tab"
			class:on={active}
			aria-current={active ? 'page' : undefined}
		>
			{#if tab.icon}
				<tab.icon class="ico" />
			{/if}
			<span>{tab.label}</span>
		</a>
	{/each}
</nav>

<style>
	/* Scrolls horizontally on narrow screens instead of wrapping into a
	   two-row block that shifts the page content down by a variable amount. */
	.place-tabs {
		display: flex;
		align-items: stretch;
		gap: 2px;
		overflow-x: auto;
		scrollbar-width: none;
		border-bottom: 1px solid var(--color-border);
		background: var(--color-surface);
		flex: none;
	}
	.place-tabs::-webkit-scrollbar {
		display: none;
	}
	/* An author `display` rule beats the UA style for [hidden], so the
	   single-tab case needs the explicit override or the bar still shows. */
	.place-tabs[hidden] {
		display: none;
	}
	.place-tab {
		display: inline-flex;
		align-items: center;
		gap: 6px;
		padding: 0 14px;
		height: 42px;
		font-size: 0.8125rem;
		font-weight: 500;
		white-space: nowrap;
		color: var(--color-text-muted);
		border-bottom: 2px solid transparent;
		transition: color 0.15s ease, border-color 0.15s ease;
	}
	.place-tab:hover {
		color: var(--color-text);
	}
	.place-tab.on {
		color: var(--color-primary);
		border-bottom-color: var(--color-primary);
	}
	.place-tab:focus-visible {
		outline: 2px solid var(--color-primary);
		outline-offset: -2px;
	}
	.ico {
		width: 15px;
		height: 15px;
		flex: none;
	}
</style>
