// walkclient walks a router's SNMP ARP table with gosnmp (the Go agent's
// exact walk semantics: ipNetToMediaPhysAddress first, RFC 4293
// ipNetToPhysicalPhysAddress only when the legacy OID is empty) and prints
// sorted `ip=<ip> mac=<mac>` lines. Output is diffed byte-for-byte against
// the Rust agent's examples/walk_arp.rs run against the same snmpd.
//
// Usage: walkclient <router> [community]
package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

const (
	oidIPNetToMedia     = "1.3.6.1.2.1.4.22.1.2"
	oidIPNetToPhysical  = "1.3.6.1.2.1.4.35.1.4"
)

func indexToIP(fullOID, prefix string) string {
	f := strings.TrimPrefix(fullOID, ".")
	p := strings.TrimPrefix(prefix, ".")
	tail := strings.TrimPrefix(f, p)
	if tail == f {
		return ""
	}
	tail = strings.TrimPrefix(tail, ".")
	parts := strings.Split(tail, ".")
	if len(parts) < 5 {
		return ""
	}
	ip := strings.Join(parts[len(parts)-4:], ".")
	if net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func mac(v interface{}) string {
	b, ok := v.([]byte)
	if !ok || len(b) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func walkInto(s *gosnmp.GoSNMP, oid string, table map[string]string) error {
	return s.Walk(oid, func(pdu gosnmp.SnmpPDU) error {
		ip := indexToIP(pdu.Name, oid)
		m := mac(pdu.Value)
		if ip != "" && m != "" {
			table[ip] = m
		}
		return nil
	})
}

func main() {
	router := "127.0.0.1"
	if len(os.Args) > 1 {
		router = os.Args[1]
	}
	s := &gosnmp.GoSNMP{
		Target:  router,
		Port:    161,
		Timeout: 4 * time.Second,
		Retries: 1,
	}
	if len(os.Args) > 2 && os.Args[2] == "v3" {
		// walkclient <router> v3 <user> <authpass> <privpass>
		s.Version = gosnmp.Version3
		s.SecurityModel = gosnmp.UserSecurityModel
		if len(os.Args) < 6 {
			fmt.Fprintln(os.Stderr, "v3 needs <user> <authpass> <privpass>")
			os.Exit(2)
		}
		s.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 os.Args[3],
			AuthenticationPassphrase: os.Args[4],
			PrivacyPassphrase:        os.Args[5],
			AuthenticationProtocol:   gosnmp.SHA,
			PrivacyProtocol:          gosnmp.AES,
		}
		s.MsgFlags = gosnmp.AuthPriv
	} else {
		community := "public"
		if len(os.Args) > 2 {
			community = os.Args[2]
		}
		s.Version = gosnmp.Version2c
		s.Community = community
	}
	if err := s.Connect(); err != nil {
		fmt.Fprintln(os.Stderr, "connect:", err)
		os.Exit(1)
	}
	defer s.Conn.Close()

	table := map[string]string{}
	if err := walkInto(s, oidIPNetToMedia, table); err != nil {
		fmt.Fprintln(os.Stderr, "walk legacy:", err)
		os.Exit(1)
	}
	if len(table) == 0 {
		if err := walkInto(s, oidIPNetToPhysical, table); err != nil {
			fmt.Fprintln(os.Stderr, "walk rfc4293:", err)
			os.Exit(1)
		}
	}
	keys := make([]string, 0, len(table))
	for k := range table {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("ip=%s mac=%s\n", k, table[k])
	}
}
