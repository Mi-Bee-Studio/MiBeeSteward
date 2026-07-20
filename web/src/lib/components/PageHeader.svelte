<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  PageHeader — the single source of truth for the page title row.

  Before this component, route pages hand-rolled their headers, leading to:
    • title color drifting (most pages `text-primary`; scan-tasks/scan-results
      accidentally `text-text`)
    • title size drifting (detail page used `text-xl` while every other page
      used `text-2xl`)
    • the `mb-6` sometimes on the row, sometimes on the `<h2>` itself
    • subtitle support absent everywhere except scan-results

  This component pins the canonical look and lets pages opt into a subtitle
  and a right-aligned actions area via the `actions` snippet.
-->

<script lang="ts">
	import type { Snippet } from 'svelte';

	let {
		title,
		subtitle,
		actions,
		class: className = ''
	}: {
		title: string;
		subtitle?: string;
		actions?: Snippet;
		class?: string;
	} = $props();
</script>

<div class="flex items-start justify-between gap-4 mb-6 {className}">
	<div class="min-w-0">
		<h2 class="text-2xl font-bold text-primary tracking-tight truncate">{title}</h2>
		{#if subtitle}
			<p class="text-sm text-muted mt-1">{subtitle}</p>
		{/if}
	</div>
	{#if actions}
		<div class="flex items-center gap-2 shrink-0">
			{@render actions()}
		</div>
	{/if}
</div>
