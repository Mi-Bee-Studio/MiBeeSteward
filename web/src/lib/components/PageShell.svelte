<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  PageShell — wraps a route page's content with the canonical outer padding.

  Before this component, three padding schemes coexisted:
    • `p-6` (most list pages)
    • `p-4 sm:p-6` (newer feature pages)
    • `p-4 md:p-8` (dashboard only)
  with each page hardcoding its own wrapper. This normalises to `p-4 sm:p-6`
  (room to breathe on desktop, flush to the edge on phones), with a `wide`
  variant that matches the dashboard's `p-4 md:p-8` for chart-heavy layouts.
-->

<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		wide = false,
		class: className = '',
		children
	}: {
		/** `wide` uses the dashboard's `p-4 md:p-8` for chart-heavy layouts. */
		wide?: boolean;
		class?: string;
		children: Snippet;
	} = $props();

	const padding = $derived(wide ? 'p-4 md:p-8' : 'p-4 sm:p-6');
</script>

<div class="{padding} {className}">
	{@render children()}
</div>
