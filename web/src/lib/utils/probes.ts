/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later; see LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate; see
 * LICENSE-COMMERCIAL.md.
 */

import type { ProbeTarget } from '$lib/types';

/** Management categories (#613), in the order the /probes page sections and
 *  the quality panel render them. */
export const PROBE_CATEGORIES = ['lan', 'external', 'quality'] as const;
export type ProbeCategory = (typeof PROBE_CATEGORIES)[number];

/**
 * Derive a target's management category from list-payload fields, mirroring
 * the backend's TargetCategory (internal/service/probetarget/quality.go) so
 * the /probes sections and the quality report's categories agree:
 *   quality  = source 'system' (the built-in egress matrix, config-managed)
 *   lan      = source 'auto' (policy-generated from a service) or bound to a
 *              device (device_id > 0)
 *   external = manual, unbound business targets
 */
export function probeCategory(t: Pick<ProbeTarget, 'source' | 'device_id'>): ProbeCategory {
	if (t.source === 'system') return 'quality';
	if (t.source === 'auto' || (t.device_id != null && t.device_id > 0)) return 'lan';
	return 'external';
}
