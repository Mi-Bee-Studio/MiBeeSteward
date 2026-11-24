<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  系统管理 place: the operator surfaces — users, audit trail, and the
  settings centre (profile / password / 2FA / appearance / language, plus
  the admin sub-pages: notification channels, SNMP credentials, security
  policy, probe policy, tag dictionary, fingerprint upstream).

  Settings used to sit alone in the sidebar footer while users and audit were
  a third "Administration" group: three ways to reach what is one daily
  operator job. Now it is one place with three tabs. Non-admins keep the
  settings tab (it is self-service) and lose the other two.
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
		...(isAdmin
			? [
				{ path: '/users', label: m['admin.Place Tab Users']() },
				{ path: '/audit', label: m['admin.Place Tab Audit']() }
			]
			: []),
		{ path: '/settings', label: m['admin.Place Tab Settings']() }
	]);
</script>

<div class="flex flex-col h-full">
	<PlaceTabs {tabs} />
	<div class="flex-1 overflow-auto">
		{@render children()}
	</div>
</div>
