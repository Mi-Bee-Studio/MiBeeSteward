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

import { m } from '$lib/i18n-paraglide';
import type { DeviceTypeBucket, TopoLayer } from '$lib/utils/topologyGraph';
import type { TopoNode } from '$lib/types';

/**
 * i18n-dependent label/format helpers for the topology view family (#635
 * PR1): shared by the 2D canvas (tooltips, legend), the surrounding panels,
 * and the future 3D renderer. Pure string formatting — no DOM access.
 *
 * Everything renderer-agnostic and i18n-free lives in topologyGraph.ts
 * instead; the split keeps that module testable without message catalogs.
 */

export function layerLabel(layer: TopoLayer): string {
	const labels: Record<TopoLayer, string> = {
		root: m['topology.Layer Root'](),
		core: m['topology.Layer Core'](),
		access: m['topology.Layer Access'](),
		edge: m['topology.Layer Endpoint']()
	};
	return labels[layer];
}

/** Type-bucket label for color-by-type mode + legend chips. */
export function bucketLabel(bucket: DeviceTypeBucket): string {
	const labels: Record<DeviceTypeBucket, string> = {
		network: m['topology.Type Network'](),
		camera: m['topology.Type Camera'](),
		computer: m['topology.Type Computer'](),
		mobile: m['topology.Type Mobile'](),
		iot: m['topology.Type Iot'](),
		other: m['topology.Type Other']()
	};
	return labels[bucket];
}

export function typeLabel(type: string): string {
	const labels: Record<string, string> = {
		pc: m['devices.PC'](),
		embedded: m['devices.Embedded'](),
		iot: m['devices.IoT'](),
		server: m['devices.Server'](),
		switch: m['devices.Switch'](),
		router: m['devices.Router'](),
		firewall: m['devices.Firewall'](),
		nas: m['devices.NAS'](),
		camera: m['devices.Camera'](),
		phone: m['devices.Phone'](),
		printer: m['devices.Printer'](),
		other: m['devices.Other']()
	};
	return labels[type] ?? type;
}

export function deviceType(n: TopoNode): string {
	return (n.inferred_type || n.type || 'other').toLowerCase();
}

/** Age rendering for edges (#585): minutes under an hour, hours above. */
export function formatAge(ms: number): string {
	const minutes = Math.floor(ms / 60000);
	if (minutes < 60) return m['topology.Minutes Ago']({ n: minutes });
	return m['topology.Hours Ago']({ n: Math.floor(minutes / 60) });
}

/** Compact byte formatting for speaks-with tooltips (1.2 MB style). */
export function formatBytes(n: number): string {
	if (n < 1024) return `${n} B`;
	const units = ['KB', 'MB', 'GB', 'TB'];
	let v = n;
	let i = -1;
	do {
		v /= 1024;
		i += 1;
	} while (v >= 1024 && i < units.length - 1);
	return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}
