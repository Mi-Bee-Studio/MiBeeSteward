// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package probe

// activeBanners maps a port to a probe string that elicits a banner from a
// request/response service. When the passive banner read (server greeting)
// returns nothing, the port scan sends the probe string for that port and
// re-reads the response. This mirrors nmap's "rare" probe approach in a tiny,
// curated form: only ports where a passive read commonly fails.
//
// The probe strings are deliberately minimal and protocol-safe:
//   - HTTP family: a bare HTTP/0.9-style GET, which also works for HTTP/1.x
//     servers (they answer with a full response even to a 0.9 request).
//   - TLS family: nothing is sent — the server speaks first only in some TLS
//     setups; we instead rely on the separate TLS probe to read the cert.
//   - DB / cache: a protocol-specific handshake start (redis PING, postgres
//     SSLRequest, mongodb ismaster) is NOT sent here because partial handshakes
//     can confuse servers. Those are left to dedicated probes later. This table
//     only carries generic, non-mutating probes.
//
// Ports not in this map fall back to the passive read only (which already
// catches SSH, FTP, SMTP, RTSP, redis, etc. — anything that volunteers a
// greeting on connect).
var activeBanners = map[int][]byte{
	80:   []byte("GET / HTTP/1.0\r\n\r\n"),
	8080: []byte("GET / HTTP/1.0\r\n\r\n"),
	8000: []byte("GET / HTTP/1.0\r\n\r\n"),
	8008: []byte("GET / HTTP/1.0\r\n\r\n"),
	8443: []byte("GET / HTTP/1.0\r\n\r\n"),
	8081: []byte("GET / HTTP/1.0\r\n\r\n"),
	8888: []byte("GET / HTTP/1.0\r\n\r\n"),
	9000: []byte("GET / HTTP/1.0\r\n\r\n"),
	// AJV / Java app servers
	4848: []byte("GET / HTTP/1.0\r\n\r\n"),
	// IPP (CUPS) speaks HTTP on 631
	631: []byte("GET / HTTP/1.0\r\n\r\n"),
	// Elasticsearch / CouchDB / others that speak HTTP on non-web ports
	9200: []byte("GET / HTTP/1.0\r\n\r\n"),
	5984: []byte("GET / HTTP/1.0\r\n\r\n"),
}

// probeForPort returns the active probe bytes for a port (nil = passive only).
func probeForPort(port int) []byte {
	if b, ok := activeBanners[port]; ok {
		return b
	}
	return nil
}
