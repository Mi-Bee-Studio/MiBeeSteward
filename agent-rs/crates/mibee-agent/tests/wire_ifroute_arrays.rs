// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later. See LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

//! The interface census (#529) and route table (#528) cross the agent→center
//! wire as flat arrays on the host payload (same channel doctrine as
//! `neighbors`). These tests pin the field names the Go center's
//! ReportedHostToReport rebuild reads.

use mibee_agent::wire::{ReportedHost, ReportedInterface, ReportedRoute};

#[test]
fn interface_and_route_arrays_serialize_go_field_names() {
    let mut host = ReportedHost::default();
    host.ip = "10.0.0.1".into();
    host.interfaces.push(ReportedInterface {
        if_index: 3,
        if_name: "eth3".into(),
        if_descr: "Ethernet3".into(),
        mac: "aa:bb:cc:dd:ee:03".into(),
        ip: "10.0.0.3".into(),
        speed: 1000,
    });
    host.routes.push(ReportedRoute {
        dest: "172.16.0.0/12".into(),
        next_hop: "10.0.0.254".into(),
        if_index: 2,
        proto: "ospf".into(),
    });

    let j = serde_json::to_value(&host).unwrap();
    assert_eq!(j["interfaces"][0]["if_index"], 3);
    assert_eq!(j["interfaces"][0]["if_name"], "eth3");
    assert_eq!(j["interfaces"][0]["speed"], 1000);
    assert_eq!(j["routes"][0]["dest"], "172.16.0.0/12");
    assert_eq!(j["routes"][0]["next_hop"], "10.0.0.254");

    // Empty arrays omit (skip_serializing_if) - old centers never see the
    // keys, the pre-#528/#529 payload shape is unchanged.
    let bare = serde_json::to_value(&ReportedHost::default()).unwrap();
    assert!(bare.get("interfaces").is_none());
    assert!(bare.get("routes").is_none());
}
