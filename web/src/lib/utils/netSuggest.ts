/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * This file is part of MiBee Steward, distributed under the GNU Affero General
 * Public License v3.0 or later. See LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate. See
 * LICENSE-COMMERCIAL.md.
 */

import { api } from '$lib/api/client';

// Mirrors GET /api/v1/system/network-interfaces (docs/openapi.yaml,
// SystemNetworkInterfacesReport) — the host's own interfaces as first-use
// scan suggestions (#678).

export interface SuggestedInterface {
	name: string;
	ipv4: string;
	prefix_len: number;
	cidr: string;
	mac?: string;
	kind: 'lan' | 'wireless' | 'virtual' | 'vpn';
	primary: boolean;
	addresses: number;
	suggested_cidr: string;
}

export interface NetworkSuggestReport {
	interfaces: SuggestedInterface[];
	container: boolean;
	warning?: string;
}

/**
 * Best single-network suggestion: the default-route (primary) interface's
 * suggested CIDR, falling back to the first lan/wireless candidate. Returns
 * '' when the host has nothing LAN-like to offer.
 */
export async function bestLocalNetwork(): Promise<string> {
	const report = await api.get<NetworkSuggestReport>('/system/network-interfaces');
	if (report.warning === 'no_lan' || report.interfaces.length === 0) return '';
	const primary = report.interfaces.find((n) => n.primary);
	if (primary) return primary.suggested_cidr;
	const lan = report.interfaces.find((n) => n.kind === 'lan' || n.kind === 'wireless');
	return lan ? lan.suggested_cidr : '';
}
