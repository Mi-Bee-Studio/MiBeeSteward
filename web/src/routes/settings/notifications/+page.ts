/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see the main repository's LICENSE-COMMERCIAL.md.
 */

// Notification settings moved into the settings accordion (in-place
// expand/collapse, no separate page). Redirect legacy links to the hub with a
// hash that auto-opens the notifications section.
import { redirect } from '@sveltejs/kit';

export function load() {
	redirect(307, '/settings#notifications');
}
