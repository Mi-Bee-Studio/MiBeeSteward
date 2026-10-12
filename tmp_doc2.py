# -*- coding: utf-8 -*-
p = "docs/en/architecture.md"
s = open(p, encoding="utf-8").read()
anchor = "**Sighting history & vantage provenance (#527)**"
add = '''**Interface census (#529)**: the IF-MIB + ipAddrTable walk records every port of the device itself into `device_interfaces` - ifIndex, name, description, MAC, link speed, and the IPv4 each port answers at (the multi-homed detail a single `devices.ip_address` row can never express). `GET /devices/{id}/interfaces` feeds the detail-page panel; vanished ports keep their frozen last-seen row (history, not deletion). agent-rs collects the same census.

**Route-table edges (#528)**: the ipRouteTable walk collects every non-direct route (dest CIDR + next hop + egress ifIndex + protocol); routes whose next hop resolves to a known device materialize `topology_edges` rows (router -> next hop, via `route-table`, destination subnet in metadata - the more specific subnet wins when routes share a hop). The topology graph unions these edges with the neighbor-derived set, so multi-hop interconnects render as collected fact. Direct routes are skipped: the connected-subnet fact already lives in the interface census and per-network presence.

**Sighting history & vantage provenance (#527)**'''
assert s.count(anchor) == 1
s = s.replace(anchor, add)
old_t = "| `device_network_presence` | The multi-homed identity layer: every network an asset is actively present in, at which address (#526) |"
assert s.count(old_t) == 1
s = s.replace(old_t, old_t + "\n| `device_interfaces` | The device's own IF-MIB + ipAddrTable port census, per-port addresses included (#529) |")
open(p, "w", encoding="utf-8", newline="\n").write(s)
print("en done")

p2 = "docs/zh/architecture.md"
s2 = open(p2, encoding="utf-8").read()
anchor2 = "**目击历史与视角溯源（#527）**"
add2 = '''**接口清单（#529）**：IF-MIB 与 ipAddrTable 采集把设备自身的每个端口记入 `device_interfaces`——序号、名称、描述、MAC、链路速率，以及每个端口应答的 IPv4（单一 `devices.ip_address` 列表达不了的细节）。`GET /devices/{id}/interfaces` 供详情页面板；消失的端口保留冻结的 last-seen 行（历史而非删除）。agent-rs 同步采集。

**路由表边（#528）**：ipRouteTable 采集每条非直连路由（目的 CIDR + 下一跳 + 出口 ifIndex + 协议）；下一跳可解析为已知设备的路由物化 `topology_edges` 行（路由器 → 下一跳，via `route-table`，目的子网记入 metadata——同跳多条路由取更具体的子网）。拓扑图将这些边与邻居派生边并集渲染，多跳互联成为采集事实。直连路由跳过：直连子网事实已由接口清单与按网在场承载。

**目击历史与视角溯源（#527）**'''
assert s2.count(anchor2) == 1
s2 = s2.replace(anchor2, add2)
old_t2 = "| `device_network_presence` | 多归属身份层：资产活跃于哪些网络、各自地址（#526） |"
assert s2.count(old_t2) == 1
s2 = s2.replace(old_t2, old_t2 + "\n| `device_interfaces` | 设备自身 IF-MIB + ipAddrTable 端口清单，含各端口地址（#529） |")
open(p2, "w", encoding="utf-8", newline="\n").write(s2)
print("zh done")

p3 = "CHANGELOG.md"
s3 = open(p3, encoding="utf-8").read()
old3 = "## [Unreleased]\n\n### Added\n"
new3 = ("## [Unreleased]\n\n### Added\n"
"- **Interface census + route-table edges - schema window part 2 (#528, #529, generation 7)**: the IF-MIB + ipAddrTable walk records every port of the device itself into the new `device_interfaces` table (ifIndex, name, description, MAC, link speed, and the IPv4 each port answers at - the multi-homed detail a single address row can never express; vanished ports keep their frozen last-seen row). `GET /devices/{id}/interfaces` + a detail-page Interfaces panel (bilingual). The ipRouteTable walk (#528) collects every non-direct route; routes whose next hop resolves to a known device materialize topology edges (router -> next hop, via `route-table`, destination subnet in metadata - the more specific subnet wins when routes share a hop), and the topology graph now unions these `topology_edges` rows with the neighbor-derived set - previously the materialized-edge table had NO reader, so route edges (and any future edge writer) would never have rendered. Direct routes are skipped: the connected-subnet fact already lives in the census and per-network presence. Both probes ship Go + agent-rs parity (same OIDs, same evidence shapes, byte-parity helpers tested); agent reports fuse through the same extraction pipeline as local scans.\n")
assert s3.count(old3) == 1
s3 = s3.replace(old3, new3)
open(p3, "w", encoding="utf-8", newline="\n").write(s3)
print("changelog")
