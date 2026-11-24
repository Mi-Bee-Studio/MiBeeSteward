/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. A commercial license is available for use cases
 * the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.
 */

import type { Component } from 'svelte';

/**
 * One tab in a place's tab bar. The path IS the route: tabs navigate with a
 * plain <a href>, so a tab is linkable and survives reload/back.
 */
export interface PlaceTab {
	path: string;
	label: string;
	icon?: Component;
	/** Exact pathname match only — used by a place's index tab. */
	exact?: boolean;
	/**
	 * Extra path prefixes that also light this tab up. A tab that owns a
	 * sub-route group (the scan center's four pages) would otherwise go dark
	 * as soon as the user opens one of its siblings.
	 */
	also?: string[];
}
