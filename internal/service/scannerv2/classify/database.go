// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (c) 2026 Mi-Bee Studio. All rights reserved.
//
// This file is part of MiBee Steward, distributed under the GNU Affero General
// Public License v3.0 or later. You may use, modify, and redistribute it under
// those terms; see LICENSE for the full text. A commercial license is available
// for use cases the AGPL does not accommodate; see LICENSE-COMMERCIAL.md.

package classify

import (
	"strings"

	"mibee-steward/internal/service/scannerv2"
)

// DatabaseClassifier inspects banners and port evidence for databases that
// volunteer a greeting on connect (mysql, redis, postgresql, mongodb, mssql).
// Most databases DO send a handshake/greeting immediately, so the passive
// banner read in the port probe is usually enough; this classifier turns those
// banners into typed service identities with version metadata when extractable.
//
// Service names emitted: "mysql", "redis", "postgresql", "mongodb", "mssql".
//
// Detection signatures (port → what the banner looks like):
//   - 3306 mysql:     handshake packet, version string appears early as
//     e.g. "10.11.8-MariaDB..." (the server sends its version
//     in the initial greeting packet, plain ASCII within the
//     binary packet)
//   - 6379 redis:     "-ERR" / "+PONG" / "redis" — but on a fresh connect redis
//     sends nothing; only the PING response classifies it. We
//     also accept the literal "redis" in any banner.
//   - 5432 postgres:  an error frame on a bare connect ("F...SFATAL") OR the
//     "FATAL: no PostgreSQL" style text the server emits when
//     it receives a non-protocol greeting.
//   - 27017 mongodb:  "mongodb" in banner, or an ismaster response shape.
//   - 1433 mssql:     TDS prelogin response — recognized by a leading 0x04/
//     0x01 TDS header byte + the absence of any printable
//     greeting. We key off a small TDS signature.
type DatabaseClassifier struct{}

func (DatabaseClassifier) Service() string { return "database" } // multi-emitter

func (DatabaseClassifier) Classify(ev []scannerv2.Evidence) []scannerv2.ServiceIdentity {
	idx := indexEvidence(ev)
	var out []scannerv2.ServiceIdentity

	for _, e := range idx.byKind["banner"] {
		b := strings.TrimSpace(bannerText(e))
		if b == "" {
			continue
		}
		lower := strings.ToLower(b)

		// MySQL: the greeting packet's first 1-2 bytes are a length prefix
		// (binary), but the version string follows as ASCII terminated by 0x00.
		// Look for a MariaDB/MySQL version substring which is robust to the
		// binary framing. Also catches Percona.
		// IMPORTANT: the version-shape regex alone is too broad — it matches
		// any X.Y.Z string including HTTP Server headers (nginx/1.26.1). Only
		// apply it when the banner explicitly names mysql/mariadb OR the port
		// is the canonical MySQL port 3306.
		if strings.Contains(lower, "mariadb") || strings.Contains(lower, "mysql") ||
			(e.Port == 3306 && mysqlVersionRE.MatchString(b)) {
			out = append(out, scannerv2.ServiceIdentity{
				Service: "mysql", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.9),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b, "version": extractMySQLVersion(b)},
			})
			continue
		}

		// Redis: redis doesn't greet on connect, so a banner here means either
		// a PING reply ("+PONG") or an AUTH-required error ("-NOAUTH" / "-ERR").
		if lower == "+pong" || strings.HasPrefix(lower, "-noauth") ||
			(strings.HasPrefix(lower, "-err") && e.Port == 6379) ||
			strings.Contains(lower, "redis_version") {
			out = append(out, scannerv2.ServiceIdentity{
				Service: "redis", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.85),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
			continue
		}

		// PostgreSQL: on a bare connect the server sends an error frame
		// beginning with 'E' (0x45) followed by "SFATAL...". The readable text
		// includes "FATAL" and often "PostgreSQL".
		if strings.Contains(lower, "postgresql") ||
			(strings.HasPrefix(b, "E\x00\x00\x00") && strings.Contains(lower, "fatal")) ||
			(e.Port == 5432 && strings.Contains(lower, "fatal")) {
			out = append(out, scannerv2.ServiceIdentity{
				Service: "postgresql", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.85),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
			continue
		}

		// MongoDB: the ismaster/hello response is BSON and won't be readable,
		// but a mongod receiving a non-protocol greeting may emit "It looks
		// like you are trying to connect over HTTP to a MongoDB server". Catch
		// that and the literal "mongodb".
		if strings.Contains(lower, "mongodb") {
			out = append(out, scannerv2.ServiceIdentity{
				Service: "mongodb", Port: e.Port, Protocol: "tcp",
				Confidence: fuseConfidence(e.Confidence, 0.85),
				Evidence:   []scannerv2.Evidence{e},
				Metadata:   map[string]string{"banner": b},
			})
			continue
		}
	}

	// Port-only fallbacks: when a known DB port is open but no banner was
	// captured, assert a low-confidence identity so the host isn't blind. This
	// is conservative (only the canonical port numbers) to avoid false
	// positives on ports that happen to share a number.
	for port, svc := range map[int]string{
		3306: "mysql", 6379: "redis", 5432: "postgresql",
		27017: "mongodb", 1433: "mssql", 11211: "memcached",
	} {
		// Only assert when the port is open AND no banner-based identity was
		// already emitted for this port (avoids duplicates).
		if portHasOpen(idx, port) && !outHasPort(out, port) {
			out = append(out, scannerv2.ServiceIdentity{
				Service: svc, Port: port, Protocol: "tcp",
				Confidence: 0.5, // port-shape only, no banner confirmation
				Evidence:   idx.byPort[port],
			})
		}
	}

	return out
}

// portHasOpen reports whether any port_open evidence exists for the port.
func portHasOpen(idx evidenceIndex, port int) bool {
	for _, e := range idx.byPort[port] {
		if e.Kind == "port_open" {
			return true
		}
	}
	return false
}

func outHasPort(out []scannerv2.ServiceIdentity, port int) bool {
	for _, s := range out {
		if s.Port == port {
			return true
		}
	}
	return false
}
