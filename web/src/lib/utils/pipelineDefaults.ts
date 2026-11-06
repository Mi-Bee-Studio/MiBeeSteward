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

import type { PipelineConfig } from '$lib/types';

// The backend's DefaultPipelineConfig (internal/domain/scanner.go), the one
// source of truth for what a task with an omitted pipeline_config runs. The
// forms pre-fill EXACTLY this (#685): what the user sees before touching the
// advanced section must be what would have run if they never opened it.
// Pinned byte-for-byte by web/src/__tests__/pipelineDefaults.test.ts — update
// both together when the backend default changes.
export function backendDefaultPipeline(): PipelineConfig {
	return {
		icmp: { enabled: true, timeout: 2 },
		snmp: { enabled: true, community: 'public' },
		port_scan: { enabled: true, ports: '22,80,443,9100', scan_type: 'connect' },
		service_detect: { enabled: true },
		prometheus: { enabled: true, ports: '9090,9100' },
		node_exporter: { enabled: true }
	};
}
