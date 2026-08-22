/*
  SPDX-License-Identifier: AGPL-3.0-or-later

  Copyright (c) 2026 Mi-Bee Studio. All rights reserved.

  This file is part of MiBee Steward, distributed under the GNU Affero General
  Public License v3.0 or later. See LICENSE for the full text. A commercial
  license is available for use cases the AGPL does not accommodate; see
  LICENSE-COMMERCIAL.md.
*/
import { writable } from 'svelte/store';

/**
 * Demo-mode flag (#285): the backend exposes a public GET /api/v1/demo/status
 * ONLY when running with -demo / server.demo_mode. One probe per page load —
 * a 404 (the normal deployment) resolves false.
 */
export const demoMode = writable(false);

export async function probeDemoMode(): Promise<boolean> {
	try {
		const res = await fetch('/api/v1/demo/status', { credentials: 'include' });
		if (res.ok) {
			const body = await res.json();
			const on = body?.demo === true;
			demoMode.set(on);
			return on;
		}
	} catch {
		// network hiccup — default false
	}
	demoMode.set(false);
	return false;
}
