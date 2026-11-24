<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  网络 place: networks as first-class entities. /network-center is the
  read-only aggregate view (egress / quality / topology / assets across
  networks); /networks is the editable registry (create, edit, delete a
  network and its subnets); /agents is the collector fleet that reports each
  network's data. These three were separate sidebar entries, which meant the
  same network appeared in three places with no visual relationship.

  Admin-only members are tabs only for admins; each of those pages also carries
  its own admin gate, so a non-admin reaching one by URL gets an explanation
  rather than a blank page.
-->
<script lang="ts">
	import { m } from '$lib/i18n-paraglide';
	import { auth } from '$lib/stores/auth';
	import PlaceTabs from '$lib/components/PlaceTabs.svelte';
	import type { PlaceTab } from '$lib/components/placeTabs';
	import type { Snippet } from 'svelte';

	let { children }: { children: Snippet } = $props();

	const isAdmin = $derived($auth.user?.role === 'admin');

	const tabs = $derived<PlaceTab[]>([
		{ path: '/network-center', label: m['network.Place Tab Overview']() },
		// The registry and the collector fleet are admin surfaces; each page
		// also carries its own admin gate, so a non-admin reaching them by URL
		// sees an explanation rather than a blank page.
		...(isAdmin
			? [
				{ path: '/networks', label: m['network.Place Tab Registry']() },
				{ path: '/agents', label: m['network.Place Tab Agents']() }
			]
			: [])
	]);
</script>

<div class="flex flex-col h-full">
	<PlaceTabs {tabs} />
	<div class="flex-1 overflow-auto">
		{@render children()}
	</div>
</div>
