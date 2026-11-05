// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. See LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate. See
// LICENSE-COMMERCIAL.md.

// Package netinfo enumerates the host's own IPv4 network interfaces as
// first-use scan suggestions (#678): which LAN is this box actually on, so the
// UI can offer a one-click "scan my network" task instead of asking a new
// user to hand-type a CIDR. Pure read-only host introspection — no probing,
// no packets on the wire (the default-route lookup is a UDP connect, which
// only makes a routing decision).
package netinfo

import (
	"net"
	"os"
	"sort"
	"time"
)

// Interface kinds, from most to least likely to be a real scannable LAN.
const (
	KindLan      = "lan"      // eth*, en*, br-lan, fallback
	KindWireless = "wireless" // wlan*, wlp*, wlx*
	KindVirtual  = "virtual"  // docker0, veth*, bridges, cni/flannel/calico…
	KindVPN      = "vpn"      // wg*, tailscale*, tun*, tap*…
)

// Warning keys surfaced by Snapshot (the UI translates them).
const (
	// WarnBridgeContainer: running inside a container whose primary address
	// sits in the RFC1918 CGNAT/docker bridge space — the enumerated networks
	// are the container's own, not the host LAN; scanning needs host
	// networking (docs/en/deployment.md mode table).
	WarnBridgeContainer = "bridge_container"
	// WarnNoLAN: nothing interface-like matched a real LAN (only
	// virtual/vpn, or nothing at all) — a suggestion would be a guess.
	WarnNoLAN = "no_lan"
)

// Interface is one enumerated IPv4 interface candidate.
type Interface struct {
	Name      string `json:"name"`
	IPv4      string `json:"ipv4"`
	PrefixLen int    `json:"prefix_len"`
	// CIDR is the interface's on-link subnet (ip/mask as configured).
	CIDR string `json:"cidr"`
	// MAC is omitted for virtual interfaces without one.
	MAC string `json:"mac,omitempty"`
	// Kind is one of the Kind* constants.
	Kind string `json:"kind"`
	// Primary marks the interface that owns the IPv4 default route —
	// the best "this is the network I'm on" answer.
	Primary bool `json:"primary"`
	// Addresses is the total address count of CIDR (display + capacity hint).
	Addresses int `json:"addresses"`
	// SuggestedCIDR is the scan-friendly form: CIDR clamped so the suggestion
	// never exceeds a /24 when the on-link subnet is larger (a /16 DHCP lease
	// should not become a 65k-host first scan; the user can widen later).
	SuggestedCIDR string `json:"suggested_cidr"`
}

// Report is the host snapshot. Warning is a machine key from the Warn*
// constants ("" = none); Container marks a containerized center.
type Report struct {
	Interfaces []Interface `json:"interfaces"`
	Container  bool        `json:"container"`
	Warning    string      `json:"warning,omitempty"`
}

// Snapshot enumerates the host's IPv4 interfaces now.
func Snapshot() Report {
	rep := Report{Interfaces: []Interface{}}

	primaryIP := defaultRouteIP()

	ifaces, err := net.Interfaces()
	if err != nil {
		return rep
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			prefixLen, bits := ipnet.Mask.Size()
			if bits != 32 || prefixLen < 0 {
				continue
			}
			mac := ""
			if iface.HardwareAddr != nil {
				mac = iface.HardwareAddr.String()
			}
			_, cidr, _ := net.ParseCIDR(ipnet.String())
			cidrStr := ipnet.String()
			if cidr != nil {
				cidrStr = cidr.String()
			}
			rep.Interfaces = append(rep.Interfaces, Interface{
				Name:          iface.Name,
				IPv4:          ip4.String(),
				PrefixLen:     prefixLen,
				CIDR:          cidrStr,
				MAC:           mac,
				Kind:          classify(iface.Name),
				Primary:       primaryIP != nil && primaryIP.Equal(ip4),
				Addresses:     1 << uint(32-prefixLen),
				SuggestedCIDR: suggestCIDR(ip4, prefixLen),
			})
			break // first IPv4 per interface is enough for a suggestion
		}
	}

	sort.SliceStable(rep.Interfaces, func(i, j int) bool {
		pi, pj := rep.Interfaces[i], rep.Interfaces[j]
		if pi.Primary != pj.Primary {
			return pi.Primary
		}
		return kindRank(pi.Kind) < kindRank(pj.Kind)
	})

	rep.Container = runningInContainer()
	rep.Warning = warningFor(rep)
	return rep
}

// classify maps an interface name to a Kind by naming convention. Pure
// function so tests can pin the table. Linux names are the target (prod is
// Linux-only); the fallback is lan because an unknown Ethernet-ish name is
// more likely a real NIC than a virtual gadget.
func classify(name string) string {
	switch {
	case hasPrefix(name, "docker", "veth", "flannel", "cali", "cni", "kube", "dummy", "virbr", "brq"):
		// "cali" covers calico's cali<id> veths (and calico-* names too).
		return KindVirtual
	case name == "br-lan": // OpenWrt LAN bridge — the real LAN on soft routers
		return KindLan
	case hasPrefix(name, "br-"): // docker's br-<bridge-name/hex> bridges
		return KindVirtual
	case hasPrefix(name, "wg", "tailscale", "zerotier", "zt", "tun", "tap", "ppp"):
		return KindVPN
	case hasPrefix(name, "wlan", "wl"):
		return KindWireless
	default:
		return KindLan
	}
}

func kindRank(kind string) int {
	switch kind {
	case KindLan:
		return 0
	case KindWireless:
		return 1
	case KindVPN:
		return 2
	default:
		return 3
	}
}

func hasPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if len(s) >= len(p) && s[:len(p)] == p {
			return true
		}
	}
	return false
}

// suggestCIDR clamps the on-link subnet for the first-scan suggestion: a
// prefix longer than /24 stays as configured; anything wider becomes the /24
// containing the interface's own address.
func suggestCIDR(ip4 net.IP, prefixLen int) string {
	if prefixLen >= 24 {
		return (&net.IPNet{IP: ip4.Mask(net.CIDRMask(prefixLen, 32)), Mask: net.CIDRMask(prefixLen, 32)}).String()
	}
	return (&net.IPNet{IP: ip4.Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)}).String()
}

// defaultRouteIP returns the local source IP the kernel would pick for an
// internet destination, i.e. the address of the default-route interface. A
// UDP connect sends nothing; it only resolves the route.
func defaultRouteIP() net.IP {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", time.Second)
	if err != nil {
		return nil
	}
	defer conn.Close()
	if udp, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return udp.IP.To4()
	}
	return nil
}

func runningInContainer() bool {
	for _, marker := range []string{"/.dockerenv", "/run/.containerenv"} {
		if _, err := os.Stat(marker); err == nil {
			return true
		}
	}
	return false
}

// warningFor decides the machine-key hint for the UI: a containerized center
// whose primary address is in the RFC1918 bridge space is almost certainly
// not host-networked (the host profile requirement); and a host with no
// lan/wireless candidate at all has nothing honest to suggest.
func warningFor(rep Report) string {
	var primary *Interface
	for i := range rep.Interfaces {
		if rep.Interfaces[i].Primary {
			primary = &rep.Interfaces[i]
			break
		}
	}
	if rep.Container && primary != nil {
		// Docker's default address pool lives in 172.16/12; 10/8 is NOT a
		// bridge signal — plenty of real LANs live there.
		ip := net.ParseIP(primary.IPv4)
		if _, bridge, err := net.ParseCIDR("172.16.0.0/12"); err == nil && bridge.Contains(ip) {
			return WarnBridgeContainer
		}
	}
	for i := range rep.Interfaces {
		if rep.Interfaces[i].Kind == KindLan || rep.Interfaces[i].Kind == KindWireless {
			return ""
		}
	}
	return WarnNoLAN
}
