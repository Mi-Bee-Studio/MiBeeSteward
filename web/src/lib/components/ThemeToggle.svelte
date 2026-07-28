<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<script lang="ts">
	import { Sun, Moon } from '@lucide/svelte';
	import { browser } from '$app/environment';

	function getInitialDark(): boolean {
		const stored = localStorage.getItem('theme');
		if (stored === 'light') return false;
		if (stored === 'dark') return true;
		// No stored preference — detect from system
		return !window.matchMedia('(prefers-color-scheme: light)').matches;
	}

	// Guard the localStorage/matchMedia access for SSR/prerender — those APIs
	// only exist in the browser. Without this, server-side rendering throws
	// "localStorage is not defined" at component init (#71).
	let dark = $state(browser ? getInitialDark() : false);

	function toggle() {
		dark = !dark;
		const theme = dark ? 'dark' : 'light';
		localStorage.setItem('theme', theme);
		document.documentElement.setAttribute('data-theme', theme);
	}
</script>

<button
	onclick={toggle}
	class="btn-icon"
	title={dark ? 'Switch to light theme' : 'Switch to dark theme'}
	aria-label="Toggle theme"
>
	{#if dark}
		<Sun class="w-[18px] h-[18px]" />
	{:else}
		<Moon class="w-[18px] h-[18px]" />
	{/if}
</button>
