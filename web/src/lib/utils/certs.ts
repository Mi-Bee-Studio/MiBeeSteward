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

import type { TLSPortCerts } from '$lib/types';

export type CertStatus = 'expired' | 'expiring' | 'valid' | 'error';

/**
 * Classify a TLS port's leaf certificate by expiry.
 *
 * Shared between the device-detail TLS sub-panel and the CertificateModal so
 * the two views can't drift on the 15-day warning window or the error cases.
 * Accepts null (defensive — the modal's open state can briefly hold none).
 */
export function certStatus(port: TLSPortCerts | null): CertStatus {
	if (!port) return 'error';
	if (port.error) return 'error';
	if (!port.leaf) return 'error';
	const now = Date.now();
	const after = Date.parse(port.leaf.not_after);
	if (Number.isNaN(after)) return 'error';
	if (after < now) return 'expired';
	// 15-day warning window — short enough to be actionable, long enough to
	// catch monthly rotations.
	if (after - now < 15 * 24 * 3600 * 1000) return 'expiring';
	return 'valid';
}

/**
 * Signed day delta to a date (positive = N days until; negative = N days ago).
 * Returns 0 on unparseable input.
 */
export function certDayDelta(iso: string): number {
	const t = Date.parse(iso);
	if (Number.isNaN(t)) return 0;
	return Math.ceil((t - Date.now()) / (24 * 3600 * 1000));
}

/**
 * Group a fingerprint into colon-separated bytes (AB12CD… → AB:12:CD:…),
 * matching the openssl format operators expect. Input is uppercase hex
 * without separators. Returns '—' for empty input.
 */
export function fmtFingerprint(fp: string): string {
	if (!fp) return '—';
	return fp.replace(/(.{2})/g, '$1:').replace(/:$/, '');
}
