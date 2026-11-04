/**
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Copyright (c) 2026 Mi Bee Studio. All rights reserved.
 *
 * This file is part of MiBeeSteward, distributed under the GNU Affero General
 * Public License v3.0 or later. See LICENSE for the full text. A commercial
 * license is available for use cases the AGPL does not accommodate. See
 * LICENSE-COMMERCIAL.md.
 */

import { m } from '$lib/i18n-paraglide';

// Local copies of the two syntax primitives (dotted-IPv4 shape + octet
// range) so this module stays dependency-free — validation.ts delegates its
// validateScanTarget here, and a shared import would cycle.
const ipv4OctetPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;

function isValidOctets(ip: string): boolean {
	const parts = ip.split('.');
	return parts.length === 4 && parts.every((p) => {
		const n = Number(p);
		return Number.isInteger(n) && n >= 0 && n <= 255;
	});
}

// Mirrors internal/cidrutil's reserved-space rules (#317/#254) at the form
// layer (#684): what the backend rejects on submit is rejected at typing,
// with a human explanation instead of a raw Go error string. Endpoint
// semantics included — a block merely OVERLAPPING reserved space (e.g.
// 126.0.0.0/7, whose upper half is loopback) is caught by checking the
// first AND last address, exactly like checkReserved.

// Backend caps: POST /scanner/scan rejects >1024 IPs (413), task create
// rejects >4096 IPs (countTargetIPs).
export const SYNC_SCAN_LIMIT = 1024;
export const TASK_LIMIT = 4096;

export interface ScanTargetInfo {
	/** Localized error for the first invalid part; null = valid. */
	error: string | null;
	/** Number of comma-separated parts. */
	parts: number;
	/** Total address count across parts (0 when an error is present). */
	addresses: number;
	/**
	 * Normalized network CIDR when the whole input is EXACTLY one CIDR part
	 * (host bits stripped) — the only shape the task router can map onto a
	 * registered network (ResolveNetworkFromTargets); null otherwise.
	 */
	singleCIDR: string | null;
	overSyncLimit: boolean;
	overTaskLimit: boolean;
}

// IPv4 as uint32; bit ops stay inside JS's 32-bit domain with >>> 0.

function ipToUint32(ip: string): number {
	const o = ip.split('.');
	return ((Number(o[0]) << 24) | (Number(o[1]) << 16) | (Number(o[2]) << 8) | Number(o[3])) >>> 0;
}

function uint32ToIP(n: number): string {
	return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
}

type ReservedClass =
	| 'unspecified'
	| 'loopback'
	| 'link-local'
	| 'multicast'
	| 'broadcast'
	| 'class-e';

// Same classification order as cidrutil.reservedClass.
function reservedClass(ip: number): ReservedClass | null {
	switch (true) {
		case ip === 0:
			return 'unspecified';
		case (ip >>> 24) === 127:
			return 'loopback';
		case (ip >>> 16) === 0xa9fe:
			return 'link-local';
		case (ip >>> 28) === 0xe:
			return 'multicast';
		case ip === 0xffffffff:
			return 'broadcast';
		case (ip >>> 28) === 0xf:
			return 'class-e';
		default:
			return null;
	}
}

function reservedClassLabel(cls: ReservedClass): string {
	switch (cls) {
		case 'unspecified':
			return m['validation.Reserved Unspecified']();
		case 'loopback':
			return m['validation.Reserved Loopback']();
		case 'link-local':
			return m['validation.Reserved Link Local']();
		case 'multicast':
			return m['validation.Reserved Multicast']();
		case 'broadcast':
			return m['validation.Reserved Broadcast']();
		case 'class-e':
			return m['validation.Reserved Class E']();
	}
}

/**
 * analyzeScanTarget validates a target spec (single IP / CIDR / last-octet
 * range, comma-separated) and derives the facts the forms display: address
 * capacity, limit warnings, and the single-CIDR shape the executor hint
 * keys on. Pure function; i18n only for the error strings.
 */
export function analyzeScanTarget(value: string): ScanTargetInfo {
	const info: ScanTargetInfo = {
		error: null,
		parts: 0,
		addresses: 0,
		singleCIDR: null,
		overSyncLimit: false,
		overTaskLimit: false
	};

	if (!value.trim()) {
		info.error = m['validation.Targets Required']();
		return info;
	}

	const targets = value.split(',').map((t) => t.trim()).filter((t) => t.length > 0);
	if (targets.length === 0) {
		info.error = m['validation.Targets Required']();
		return info;
	}
	info.parts = targets.length;

	for (const target of targets) {
		// IPv6 is explicitly unsupported by the scan paths (task create
		// rejects it outright); say so instead of a generic syntax error.
		if (target.includes(':')) {
			info.error = m['validation.IPv6 Unsupported']();
			return info;
		}

		// Single IP: only the address itself is checked (a /32 has no last
		// address, same as Go's lastAddress nil).
		if (ipv4OctetPattern.test(target)) {
			if (!isValidOctets(target)) {
				info.error = m['validation.Invalid IP']({ target });
				return info;
			}
			const ip = ipToUint32(target);
			const cls = reservedClass(ip);
			if (cls) {
				info.error = m['validation.Reserved Target']({
					target,
					class: reservedClassLabel(cls)
				});
				return info;
			}
			info.addresses += 1;
			continue;
		}

		// CIDR: check both endpoints (first AND last) so overlapping blocks
		// are caught, mirroring checkReserved.
		const cidrMatch = target.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
		if (cidrMatch) {
			if (!isValidOctets(cidrMatch[1])) {
				info.error = m['validation.Invalid CIDR IP']({ target });
				return info;
			}
			const prefix = parseInt(cidrMatch[2], 10);
			if (prefix < 0 || prefix > 32) {
				info.error = m['validation.Invalid CIDR Prefix']({ target });
				return info;
			}
			const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
			const first = ipToUint32(cidrMatch[1]) & mask;
			const last = prefix >= 32 ? null : (first | (~mask >>> 0)) >>> 0;
			for (const [endpoint, cls] of [
				[first, reservedClass(first)],
				[last, last === null ? null : reservedClass(last)]
			] as const) {
				if (cls) {
					info.error =
						endpoint === first
							? m['validation.Reserved Target']({ target, class: reservedClassLabel(cls) })
							: m['validation.Reserved Overlap']({ target, class: reservedClassLabel(cls) });
					return info;
				}
			}
			info.addresses += prefix >= 32 ? 1 : 2 ** (32 - prefix);
			if (targets.length === 1) {
				info.singleCIDR = `${uint32ToIP(first)}/${prefix}`;
			}
			continue;
		}

		// Last-octet range (a.b.c.d-e): the end must not precede the start.
		const rangeMatch = target.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3})$/);
		if (rangeMatch) {
			if (!isValidOctets(rangeMatch[1])) {
				info.error = m['validation.Invalid Range IP']({ target });
				return info;
			}
			const end = parseInt(rangeMatch[2], 10);
			if (end < 0 || end > 255) {
				info.error = m['validation.Invalid Range End']({ target });
				return info;
			}
			const base = ipToUint32(rangeMatch[1]);
			const startOctet = base & 255;
			if (end < startOctet) {
				info.error = m['validation.Range Order']({ target });
				return info;
			}
			const first = base;
			const last = (base & 0xffffff00) | end;
			for (const [endpoint, cls] of [
				[first, reservedClass(first)],
				[last, reservedClass(last)]
			] as const) {
				if (cls) {
					info.error =
						endpoint === first
							? m['validation.Reserved Target']({ target, class: reservedClassLabel(cls) })
							: m['validation.Reserved Overlap']({ target, class: reservedClassLabel(cls) });
					return info;
				}
			}
			info.addresses += end - startOctet + 1;
			continue;
		}

		info.error = m['validation.Invalid Target']({ target });
		return info;
	}

	info.overSyncLimit = info.addresses > SYNC_SCAN_LIMIT;
	info.overTaskLimit = info.addresses > TASK_LIMIT;
	return info;
}

/**
 * normalizeCIDR strips host bits from an "a.b.c.d/p" string ("192.168.63.5/24"
 * → "192.168.63.0/24") so target-vs-registered-network comparisons behave
 * like the backend's ResolveNetworkFromTargets. Returns null for anything
 * that is not an IPv4 CIDR.
 */
export function normalizeCIDR(cidr: string): string | null {
	const match = cidr.trim().match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
	if (!match || !isValidOctets(match[1])) return null;
	const prefix = parseInt(match[2], 10);
	if (prefix < 0 || prefix > 32) return null;
	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return `${uint32ToIP(ipToUint32(match[1]) & mask)}/${prefix}`;
}
