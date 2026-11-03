/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. You may use, modify, and redistribute it under
 * those terms; see LICENSE for the full text. A commercial license is available
 * for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import type { TokenColor } from '$lib/utils/topologyGraph';

/**
 * Resolve a CSS custom property from :root with a hard fallback. Canvas
 * renderers (ECharts today, three.js per #635) can't resolve var()
 * themselves, so every theme-dependent color passes through here at render
 * time.
 */
export function cssVar(name: string, fallback: string): string {
	const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
	return v || fallback;
}

/** Resolve a TokenColor ({ token, fallback }) to a concrete color string. */
export function resolveToken(tc: TokenColor): string {
	return cssVar(tc.token, tc.fallback);
}
