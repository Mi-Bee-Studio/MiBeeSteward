// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package config

// Project-wide shared constants that previously lived as scattered literals
// across packages (heartbeat, scannerv2 probe/handler, the agent binary, both
// scan entry points). Centralizing them here:
//
//   - kills the multi-site duplication that invited drift (the OID alone was
//     copied across 6 production sites + the SQLite schema default);
//   - gives one place to change a default that several packages must agree on;
//   - avoids import cycles: this package (internal/config) imports no other
//     internal package, so every caller (probe, handler, service, api, cmd)
//     can import these safely.
//
// These are TRUE constants — protocol-standard OIDs and a curated default port
// set — NOT operator-tunable knobs. Tunable values belong in Config structs
// (config.go) with koanf tags + MIBEE_* env overrides. See
// docs/private/architecture-debt-and-openwrt-2026-07-27.md §2.3 M4/M7.

// SysUpTimeOID is the SNMP sysUpTimeInstance OID (RFC 1213 1.3.6.1.2.1.1.3.0).
// It is the default heartbeat probe target for SNMP-method devices: a poll
// returns the device's uptime, and a non-responsive or resetting counter is the
// liveness signal. Used by the SNMP probe varbind set, the heartbeat probe
// fallback, the heartbeat-config default, the SNMP handler's generated config,
// and baked into the heartbeat_configs.snmp_oid schema DEFAULT.
//
// Note: the probe package uses the leading-dot form (".1.3.6.1.2.1.1.3.0") for
// its SNMP varbind keys (matching gosnmp's PDUs); callers comparing against
// probe output must normalize. The canonical form here is the no-leading-dot
// string stored in the DB + used by gosnmp.Get.
const SysUpTimeOID = "1.3.6.1.2.1.1.3.0"

// DefaultScanPortSpec is the curated TCP port set scanned when
// scanner.pipeline_defaults.default_ports is empty. Covers the common inventory
// cases out of the box: remote access (22/23/3389/5900), web (80/443/8000/
// 8080/8443/8888/9000/9090/9443), mail (25/110/143/389/636), databases (1433/
// 3306/5432/6379/9200/11211/27017), media (554/8554), storage (445), and
// monitoring/exporters (9100/9104/9113/9121/9187). 161 is SNMP/udp (kept in the
// spec so the port-list mirrors what the engine coordinates, even though the
// UDP probe path is separate).
//
// Shared by both scan entry points — the center (api/routes) and the agent
// (cmd/agent) — so they scan the identical default set when no config override
// is present.
const DefaultScanPortSpec = "22,21,23,25,53,80,110,143,389,443,445,554,631,636,8554,1433," +
	"3306,3389,5432,5900,6379,8000,8080,8081,8443,8888,9000,9090,9100,9104," +
	"9113,9121,9187,9200,9443,11211,27017,161"
