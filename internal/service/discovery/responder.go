// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero
// General Public License v3.0 or later; see LICENSE for the full text. A
// commercial license is available for use cases the AGPL does not
// accommodate; see LICENSE-COMMERCIAL.md.

package discovery

import (
	"encoding/json"
	"net"
	"sync"
	"time"
)

// DiscoveryProbeV1 is the exact byte payload a client broadcasts to discover
// MiBee services (Scout docs/02 §4/§8.3: the NVR frame, unchanged — the App
// sends the same probe to every registered per-type port). Steward answers
// on its own registered port (default 49091) with a type=steward payload.
const DiscoveryProbeV1 = "MIBEE-NVR-DISCv1?"

// DefaultUDPPort is the steward discovery port registered in the Scout
// docs/02 §8.3 table (proposal pending cross-repo confirmation, #729);
// adjacent to the NVR's 49090 so MiBee services form a port group.
const DefaultUDPPort = 49091

// probeBufSize caps the datagram we are willing to read; anything larger
// than the probe cannot match it and is dropped without a reply.
const probeBufSize = 64

// replyMinInterval throttles replies per source IP so a probe flood cannot
// turn the responder into a broadcast amplification vector.
const replyMinInterval = 100 * time.Millisecond

// replyIPCacheCap bounds the per-IP throttle map; when full it is reset
// rather than grown (a reset only briefly restores the rate limit for
// previously-throttled IPs — acceptable for a discovery convenience path).
const replyIPCacheCap = 1024

// udpResponse is the reply payload. Type is ALWAYS set for steward: the
// App's default-absent semantics treat a missing type as an NVR, so an
// untyped steward reply would be silently misclassified.
type udpResponse struct {
	V    int    `json:"v"`
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
	API  int    `json:"api"`
	TLS  bool   `json:"tls"`
}

// Responder answers DiscoveryProbeV1 broadcasts over UDP (unicast reply to
// the sender; the reply's source address is how the App learns the host).
// Like the well-known endpoint it carries no more information than the
// identity itself; clients are expected to cross-check the identity
// endpoint before trusting the reply.
type Responder struct {
	payload []byte
	port    int

	mu       sync.Mutex
	conn     *net.UDPConn
	stop     chan struct{}
	stopped  sync.WaitGroup
	lastRepl map[string]time.Time
}

// NewResponder builds a responder announcing the given identity; bindPort 0
// (ephemeral) is a test seam, production passes cfg.Discovery.UDPPort.
func NewResponder(id, name string, apiPort int, tls bool, bindPort int) *Responder {
	payload, err := json.Marshal(udpResponse{
		V:    1,
		Type: "steward",
		ID:   id,
		Name: name,
		API:  apiPort,
		TLS:  tls,
	})
	if err != nil {
		// A fixed struct cannot fail to marshal; guard anyway so the caller
		// never announces garbage.
		payload = []byte(`{"v":1,"type":"steward"}`)
	}
	return &Responder{
		payload:  payload,
		port:     bindPort,
		stop:     make(chan struct{}),
		lastRepl: make(map[string]time.Time),
	}
}

// Start binds the UDP socket and spawns the read loop. A bind failure
// (port taken, ...) is returned; the routes wiring logs it once and
// continues without the responder — discovery must not block boot.
func (u *Responder) Start() error {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: u.port})
	if err != nil {
		return err
	}
	u.mu.Lock()
	u.conn = conn
	u.mu.Unlock()
	u.stopped.Add(1)
	go u.readLoop()
	return nil
}

// Port reports the actually bound port (0 = not running). Ephemeral binds
// (:0, the test seam) resolve to their real port after Start.
func (u *Responder) Port() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.conn == nil {
		return 0
	}
	return u.conn.LocalAddr().(*net.UDPAddr).Port
}

// Stop closes the socket and waits for the read loop to exit; safe to call
// when Start failed or twice in a row.
func (u *Responder) Stop() {
	u.mu.Lock()
	conn := u.conn
	u.conn = nil
	u.mu.Unlock()
	if conn == nil {
		return
	}
	close(u.stop)
	_ = conn.Close()
	u.stopped.Wait()
}

func (u *Responder) readLoop() {
	defer u.stopped.Done()
	buf := make([]byte, probeBufSize)
	for {
		u.mu.Lock()
		conn := u.conn
		u.mu.Unlock()
		if conn == nil {
			return
		}
		// Deadline-driven wake so ctx/stop is observed even with no packets.
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-u.stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			// Socket closed under Stop: exit; anything else is transient
			// (keep serving).
			select {
			case <-u.stop:
				return
			default:
				continue
			}
		}
		// Exact probe frame only; oversized datagrams were truncated by the
		// buffer and cannot match, so they drop here too.
		if n != len(DiscoveryProbeV1) || string(buf[:n]) != DiscoveryProbeV1 {
			continue
		}
		if !u.allowReply(addr.IP.String()) {
			continue
		}
		_, _ = conn.WriteToUDP(u.payload, addr)
	}
}

// allowReply applies the per-source-IP throttle; the map resets when full
// instead of growing unbounded under a spoofed-source flood.
func (u *Responder) allowReply(ip string) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	now := time.Now()
	if last, ok := u.lastRepl[ip]; ok && now.Sub(last) < replyMinInterval {
		return false
	}
	if len(u.lastRepl) >= replyIPCacheCap {
		u.lastRepl = make(map[string]time.Time)
	}
	u.lastRepl[ip] = now
	return true
}
