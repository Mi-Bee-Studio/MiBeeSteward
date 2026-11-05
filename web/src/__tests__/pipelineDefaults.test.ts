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

import { describe, expect, it } from 'vitest';
import { backendDefaultPipeline } from '$lib/utils/pipelineDefaults';

// Pins the frontend's pre-filled pipeline to the backend's
// DefaultPipelineConfig (internal/domain/scanner.go) — the mismatch this
// suite guards against was port_scan 22,80,443,8080,9100 vs the backend's
// 22,80,443,9100 and prometheus 9090 vs 9090,9100 (#685). If this fails
// after a backend default change, update pipelineDefaults.ts in the same
// commit.
describe('backendDefaultPipeline', () => {
	it('matches the backend DefaultPipelineConfig', () => {
		expect(backendDefaultPipeline()).toEqual({
			icmp: { enabled: true, timeout: 2 },
			snmp: { enabled: true, community: 'public', timeout: 5 },
			port_scan: { enabled: true, ports: '22,80,443,9100', scan_type: 'connect' },
			service_detect: { enabled: true },
			prometheus: { enabled: true, ports: '9090,9100' },
			node_exporter: { enabled: true }
		});
	});

	it('keeps every stage enabled (an all-off config cannot run)', () => {
		const pipeline = backendDefaultPipeline();
		expect(pipeline.icmp.enabled).toBe(true);
		expect(pipeline.snmp.enabled).toBe(true);
		expect(pipeline.port_scan.enabled).toBe(true);
		expect(pipeline.service_detect.enabled).toBe(true);
		expect(pipeline.prometheus.enabled).toBe(true);
		expect(pipeline.node_exporter.enabled).toBe(true);
	});
});
