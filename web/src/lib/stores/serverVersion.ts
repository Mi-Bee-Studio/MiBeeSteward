/*
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero
  General Public License v3.0 or later. A commercial license is available
  for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
*/

/**
 * Running server version, shown in the sidebar footer and on the login page
 * so the deployed build is identifiable from the UI alone (field request
 * 2026-10-10: the version was only visible via /api/v1/health or
 * `mibee-steward -version`). Source is the PUBLIC /health endpoint — no
 * authentication, so the login page can show it pre-auth. Fetched once per
 * browser session; on failure the store stays empty and the UI omits the
 * line (a reachable-but-unversioned backend never renders "vundefined").
 */

import { writable } from 'svelte/store';
import { api } from '$lib/api/client';

const { subscribe, set } = writable('');

let requested = false;
let haveVersion = false;

export async function loadServerVersion(): Promise<void> {
	// Once per session WITH a result: the sidebar and the login page both
	// trigger this on mount, and navigation between them must not re-fetch.
	// A request that came back empty (backend unreachable) stays retryable.
	if (requested && haveVersion) return;
	requested = true;
	try {
		const health = await api.get<{ version?: string }>('/health');
		if (health?.version) {
			set(health.version);
			haveVersion = true;
		}
	} catch {
		// Backend unreachable: no version line. The login form stays usable.
	}
}

export const serverVersion = { subscribe };
