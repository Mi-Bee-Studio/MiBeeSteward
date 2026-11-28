<!--
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. A commercial license is available for use cases
  the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
-->

<!--
  资产 place: everything about "what is on my network and what do I know
  about it" — the device inventory plus the four supporting collections that
  used to be separate sidebar entries (changes, archive, fingerprint
  coverage, documents) and the scan center (four tabs that were their own
  entries too).

  Before this: 设备 + 变更 + 档案库 + 指纹覆盖 + 文档 + 4 个扫描入口 = 9 sidebar
  entries. After: 1 sidebar entry, 6 tabs. The scan center is admin-only, so
  the tabs come and go with the role — the same gating the sidebar used.
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
		{ path: '/devices', label: m['assets.Place Tab Devices'](), exact: true },
		{ path: '/identity', label: m['assets.Place Tab Identity']() },
		{ path: '/changes', label: m['assets.Place Tab Changes']() },
		{ path: '/archive', label: m['assets.Place Tab Archive']() },
		{ path: '/fingerprints', label: m['assets.Place Tab Fingerprints']() },
		{ path: '/documents', label: m['assets.Place Tab Documents']() },
		...(isAdmin
			? [
				{
					path: '/devices/scan-tasks',
					label: m['assets.Place Tab Scan'](),
					// All four scan-center pages are one capability ("find
					// devices"); the tab stays lit while the user moves between
					// tasks / results / quick scan / passive discovery.
					also: ['/devices/scan-results', '/devices/scanner', '/devices/discovery']
				}
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
