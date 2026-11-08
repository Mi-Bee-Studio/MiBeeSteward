// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later; see LICENSE for the full text. A commercial
// license is available for use cases the AGPL does not accommodate; see
// LICENSE-COMMERCIAL.md.

//go:build linux

package probeext

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// poll(2) event bits (the std syscall pkg does not export them).
const (
	pollIn  = 0x001
	pollOut = 0x004
	pollErr = 0x008
	pollHup = 0x010
)

// Tracer runs zero-privilege path traces (#719). Two methods, both verified
// against root traceroute on the survey rigs WITHOUT any capability (the
// shipped systemd units keep CapabilityBoundingSet empty):
//
//   - TCP connect: per-TTL nonblocking connect to the target's service port
//     with IP_TTL + IP_RECVERR; Time-Exceeded arrives on the error queue.
//     The source port is fixed per target (SO_REUSEADDR) so every attempt
//     presents the same 5-tuple to ECMP hashing (the Paris principle as far
//     as unprivileged sockets allow).
//   - ICMP ping socket: one SOCK_DGRAM ICMP socket per trace, IP_TTL set
//     per attempt, seq identifies the probe; replies and the error queue
//     are read from the same socket (IP_RECVTTL cmsg gives the reply TTL).
//
// Known caveat (measured in the survey): with per-attempt TCP sockets a
// late Time-Exceeded from attempt N can land in attempt N+1's error queue.
// The errqueue is drained before every send which bounds the race to the
// per-hop wait window; summaries dedupe hops by /24 so a shifted duplicate
// does not change the visible-hop count.
type Tracer struct {
	MaxTTL   int
	PerHop   time.Duration
	Attempts int // attempts per TTL while silent (default 1)
}

// NewTracer builds a tracer from config (zero values defaulted by the
// config layer; belt-and-braces here).
func NewTracer(maxTTL, perHopMs, attempts int) *Tracer {
	if maxTTL <= 0 {
		maxTTL = 30
	}
	if perHopMs <= 0 {
		perHopMs = 500
	}
	if attempts <= 0 {
		attempts = 1
	}
	return &Tracer{MaxTTL: maxTTL, PerHop: time.Duration(perHopMs) * time.Millisecond, Attempts: attempts}
}

// TraceResult is one trace's outcome.
type TraceResult struct {
	Method     string // tcp | icmp
	DstIP      string
	Hops       []PathHop // responding hops in TTL order
	EndState   string    // reached | max_ttl | error
	ReachedTTL int       // TTL whose answer came from the destination (0 = none)
	ReplyTTL   int       // IP TTL of the destination's reply (ICMP only; 0 = unknown)
	Err        string
}

// TraceHost resolves host and walks the path with the given method
// ("tcp" needs a port; "icmp" ignores it; "auto" = tcp when port > 0).
func (t *Tracer) TraceHost(ctx context.Context, host string, port int, method string) TraceResult {
	if method == "" || method == "auto" {
		if port > 0 {
			method = "tcp"
		} else {
			method = "icmp"
		}
	}
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return TraceResult{Method: method, EndState: "error", Err: fmt.Sprintf("resolve %s: %v", host, err)}
	}
	dst := ips[0].To4()
	if dst == nil {
		return TraceResult{Method: method, EndState: "error", Err: "no IPv4 answer"}
	}
	var d [4]byte
	copy(d[:], dst)
	if method == "tcp" {
		if port <= 0 {
			port = 80
		}
		return t.traceTCP(d, port)
	}
	return t.traceICMP(d)
}

// fixedPort derives a stable source port per (dst, port) so every TTL
// attempt of one target hashes into the same ECMP bucket.
func fixedPort(dst [4]byte, port int) int {
	h := sha256.Sum256([]byte{dst[0], dst[1], dst[2], dst[3], byte(port >> 8), byte(port)})
	return 40000 + int(binary.BigEndian.Uint16(h[:2]))%20000
}

// traceTCP walks the TTLs with nonblocking connects.
func (t *Tracer) traceTCP(dst [4]byte, port int) TraceResult {
	res := TraceResult{Method: "tcp", DstIP: net.IP(dst[:]).String()}
	dstStr := res.DstIP
	for ttl := 1; ttl <= t.MaxTTL; ttl++ {
		var hop *PathHop
		for attempt := 0; attempt < t.Attempts; attempt++ {
			h := tcpProbeOnce(dst, port, ttl, t.PerHop, fixedPort(dst, port))
			if h != nil {
				hop = h
				break
			}
		}
		if hop == nil {
			res.Hops = append(res.Hops, PathHop{TTL: ttl, IP: "", MS: 0})
			continue
		}
		if hop.IP == dstStr {
			res.Hops = append(res.Hops, *hop)
			res.EndState = "reached"
			res.ReachedTTL = ttl
			return res
		}
		res.Hops = append(res.Hops, *hop)
	}
	res.EndState = "max_ttl"
	return res
}

// tcpProbeOnce performs one TTL-limited connect. Returns the responding hop
// (destination IP = the target itself, including the refused case), or nil
// on silence.
func tcpProbeOnce(dst [4]byte, port, ttl int, wait time.Duration, srcPort int) *PathHop {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil
	}
	defer syscall.Close(fd)
	if err := prepProbeSocket(fd, ttl, srcPort); err != nil {
		return nil
	}
	start := time.Now()
	err = syscall.Connect(fd, &syscall.SockaddrInet4{Port: port, Addr: dst})
	if err != nil && err != syscall.EINPROGRESS {
		return nil
	}
	rev, ok := waitWritable(fd, wait)
	if !ok {
		return nil
	}
	ms := float64(time.Since(start).Microseconds()) / 1000
	// SO_ERROR first regardless of which bit poll set: a refused
	// connection surfaces as ECONNREFUSED here on every kernel, while the
	// POLLOUT/POLLERR mix varies.
	soerr, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err == nil {
		if soerr == 0 || syscall.Errno(soerr) == syscall.ECONNREFUSED {
			// connected (or refused by the destination itself): reached.
			return &PathHop{TTL: ttl, IP: net.IP(dst[:]).String(), MS: ms}
		}
	}
	if rev&(pollErr|pollHup) != 0 {
		if hop, ok := readErrQueue(fd, net.IP(dst[:]).String()); ok {
			hop.TTL = ttl
			hop.MS = ms
			return hop
		}
	}
	return nil
}

// traceICMP walks the TTLs on one ping socket. The kernel rewrites the
// echo id from the socket's local port; seq carries the TTL so replies and
// error-queue entries are matched to their probe.
func (t *Tracer) traceICMP(dst [4]byte) TraceResult {
	res := TraceResult{Method: "icmp", DstIP: net.IP(dst[:]).String()}
	dstStr := res.DstIP
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, syscall.IPPROTO_ICMP)
	if err != nil {
		res.EndState = "error"
		res.Err = "icmp socket: " + err.Error()
		return res
	}
	defer syscall.Close(fd)
	const ipRecvTTL = 12 // IP_RECVTTL; not exported by the std syscall pkg
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, ipRecvTTL, 1); err != nil {
		// Without the cmsg the reply TTL stays unknown; the trace still works.
		_ = err
	}
	ident := syscall.Getpid() & 0xFFFF
	_ = ident
	buf := make([]byte, 2048)
	oob := make([]byte, 512)
	for ttl := 1; ttl <= t.MaxTTL; ttl++ {
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
			res.EndState = "error"
			res.Err = "set ttl: " + err.Error()
			return res
		}
		var hop *PathHop
		for attempt := 0; attempt < t.Attempts; attempt++ {
			pkt := make([]byte, 24)
			pkt[0] = 8                                        // echo request; kernel fills id + checksum
			binary.BigEndian.PutUint16(pkt[6:8], uint16(ttl)) // seq identifies the probe
			copy(pkt[8:], "mibee-pathprobe")
			start := time.Now()
			if err := syscall.Sendto(fd, pkt, 0, &syscall.SockaddrInet4{Addr: dst}); err != nil {
				continue
			}
			hop = icmpRecvOnce(fd, dstStr, ttl, t.PerHop, start, buf, oob)
			if hop != nil {
				break
			}
		}
		if hop == nil {
			res.Hops = append(res.Hops, PathHop{TTL: ttl})
			continue
		}
		if hop.IP == dstStr {
			res.Hops = append(res.Hops, *hop)
			res.EndState = "reached"
			res.ReachedTTL = ttl
			res.ReplyTTL = hop.replyTTL
			return res
		}
		res.Hops = append(res.Hops, *hop)
	}
	res.EndState = "max_ttl"
	return res
}

// icmpRecvOnce waits for either an echo reply (type 0, seq match; carries
// the reply TTL via the IP_TTL cmsg) or an error-queue Time Exceeded.
func icmpRecvOnce(fd int, dstStr string, ttl int, wait time.Duration, start time.Time, buf, oob []byte) *PathHop {
	deadline := start.Add(wait)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return nil
		}
		rev, err := ppoll(fd, pollIn, remain)
		if err != nil || rev == 0 {
			return nil
		}
		if rev&pollErr != 0 {
			if hop, ok := readErrQueue(fd, dstStr); ok {
				hop.MS = float64(time.Since(start).Microseconds()) / 1000
				return hop
			}
			continue
		}
		n, oobn, _, _, err := syscall.Recvmsg(fd, buf, oob, syscall.MSG_DONTWAIT)
		if err != nil {
			continue
		}
		if n >= 16 && buf[0] == 0 && binary.BigEndian.Uint16(buf[6:8]) == uint16(ttl) {
			ms := float64(time.Since(start).Microseconds()) / 1000
			hop := &PathHop{TTL: ttl, IP: dstStr, MS: ms}
			hop.replyTTL = replyTTLFromCmsg(oob[:oobn])
			return hop
		}
	}
}

// prepProbeSocket applies the common socket options: IP_TTL, IP_RECVERR,
// and the fixed source port (TCP only; srcPort 0 skips the bind).
func prepProbeSocket(fd, ttl, srcPort int) error {
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, ttl); err != nil {
		return err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_RECVERR, 1); err != nil {
		return err
	}
	if srcPort > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			return err
		}
		// Drain stale error-queue entries a previous attempt (same 5-tuple)
		// may have left behind before rebinding.
		drainErrQueue(fd)
		if err := syscall.Bind(fd, &syscall.SockaddrInet4{Port: srcPort}); err != nil {
			return err
		}
	}
	return nil
}

// drainErrQueue empties the socket's error queue non-blockingly.
func drainErrQueue(fd int) {
	buf := make([]byte, 512)
	oob := make([]byte, 512)
	for i := 0; i < 32; i++ {
		_, oobn, _, _, err := syscall.Recvmsg(fd, buf, oob, syscall.MSG_DONTWAIT|syscall.MSG_ERRQUEUE)
		if err != nil || oobn == 0 {
			return
		}
	}
}

// readErrQueue interprets one error-queue entry: ICMP type 11 (Time
// Exceeded) yields the hop; type 3 from the destination itself means
// reached; anything else is ignored (returns ok=false).
func readErrQueue(fd int, dstStr string) (*PathHop, bool) {
	buf := make([]byte, 512)
	oob := make([]byte, 512)
	_, oobn, _, _, err := syscall.Recvmsg(fd, buf, oob, syscall.MSG_DONTWAIT|syscall.MSG_ERRQUEUE)
	if err != nil {
		return nil, false
	}
	msgs, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, false
	}
	for _, m := range msgs {
		if m.Header.Level != syscall.IPPROTO_IP || m.Header.Type != syscall.IP_RECVERR || len(m.Data) < 8 {
			continue
		}
		origin, typ := m.Data[4], m.Data[5]
		if origin != 2 /*SO_EE_ORIGIN_ICMP*/ {
			continue
		}
		ip := errQueueOffender(m.Data)
		if typ == 11 { // Time Exceeded: that TTL's router.
			return &PathHop{IP: ip}, true
		}
		if typ == 3 { // Unreachable (port/host...): the destination itself
			// answered. Loopback RSTs carry a zeroed offender sockaddr, so
			// fall back to the connect target.
			if ip == "" {
				ip = dstStr
			}
			if ip == dstStr {
				return &PathHop{IP: ip}, true
			}
		}
		return nil, false
	}
	return nil, false
}

// errQueueOffender extracts the offender sockaddr_in from an
// sock_extended_err's payload, when present.
func errQueueOffender(data []byte) string {
	if len(data) < 24 || binary.LittleEndian.Uint16(data[16:18]) != syscall.AF_INET {
		return ""
	}
	return net.IP(data[20:24]).String()
}

// waitWritable polls POLLOUT (TCP connect completion) within d.
func waitWritable(fd int, d time.Duration) (int16, bool) {
	deadline := time.Now().Add(d)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return 0, false
		}
		p := pollFD{fd: int32(fd), events: pollOut}
		rev, err := ppollFD(&p, remain)
		if err != nil {
			return 0, false
		}
		if rev != 0 {
			return p.revents, true
		}
	}
}

// ppoll wraps ppoll(2) on one fd (EINTR-safe).
func ppoll(fd int, events int16, d time.Duration) (int16, error) {
	p := pollFD{fd: int32(fd), events: events}
	return ppollFD(&p, d)
}

func ppollFD(p *pollFD, d time.Duration) (int16, error) {
	deadline := time.Now().Add(d)
	for {
		remain := time.Until(deadline)
		if remain <= 0 {
			return 0, nil
		}
		ts := syscall.NsecToTimespec(remain.Nanoseconds())
		_, _, e := syscall.Syscall6(syscall.SYS_PPOLL, uintptr(unsafe.Pointer(p)), 1,
			uintptr(unsafe.Pointer(&ts)), 0, 0, 0)
		if e == syscall.EINTR {
			continue
		}
		if e != 0 {
			return 0, e
		}
		return p.revents, nil
	}
}

type pollFD struct {
	fd      int32
	events  int16
	revents int16
}
