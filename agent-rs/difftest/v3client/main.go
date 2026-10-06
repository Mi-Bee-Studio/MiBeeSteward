// gosnmp v3 interop client — the Go side of the Rust agent difftest.
// Dials 127.0.0.1:<port> with a fixed user/passphrase set and the
// auth/priv protocols from argv, runs the full USM exchange (engine
// discovery + authenticated/encrypted Get of sysDescr+sysName) against
// the Rust v3_echo_agent, and prints "OK <sysDescr>" / "FAIL <err>".
//
// Build: see difftest/run_v3_interop.sh (own module; gosnmp from the
// local module cache, GOPROXY=off).
package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	gosnmp "github.com/gosnmp/gosnmp"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Println("FAIL usage: v3client <port> <auth> <priv>")
		os.Exit(2)
	}
	port, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Println("FAIL bad port")
		os.Exit(2)
	}
	authProto, err := authProtocol(os.Args[2])
	if err != nil {
		fmt.Printf("FAIL %v\n", err)
		os.Exit(2)
	}
	privProto, err := privProtocol(os.Args[3])
	if err != nil {
		fmt.Printf("FAIL %v\n", err)
		os.Exit(2)
	}

	flags := gosnmp.NoAuthNoPriv
	if authProto != gosnmp.NoAuth {
		flags = gosnmp.AuthNoPriv
	}
	if privProto != gosnmp.NoPriv {
		flags = gosnmp.AuthPriv
	}

	snmp := &gosnmp.GoSNMP{
		Target:          "127.0.0.1",
		Port:            uint16(port),
		Version:         gosnmp.Version3,
		Timeout:         3 * time.Second,
		Retries:         1,
		SecurityModel:   gosnmp.UserSecurityModel,
		MsgFlags:        flags,
		ContextEngineID: "",
		ContextName:     "",
		SecurityParameters: &gosnmp.UsmSecurityParameters{
			UserName:                 "admin",
			AuthenticationProtocol:   authProto,
			AuthenticationPassphrase: "authpass",
			PrivacyProtocol:          privProto,
			PrivacyPassphrase:        "privpass",
		},
	}
	if err := snmp.Connect(); err != nil {
		fmt.Printf("FAIL connect: %v\n", err)
		os.Exit(1)
	}
	defer snmp.Conn.Close()

	result, err := snmp.Get([]string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.5.0", // sysName
	})
	if err != nil {
		fmt.Printf("FAIL get: %v\n", err)
		os.Exit(1)
	}
	sysDescr := ""
	for _, v := range result.Variables {
		if v.Name == ".1.3.6.1.2.1.1.1.0" {
			switch val := v.Value.(type) {
			case string:
				sysDescr = val
			case []byte:
				sysDescr = string(val)
			}
		}
	}
	if sysDescr == "" {
		fmt.Printf("FAIL empty sysDescr (vars=%d)\n", len(result.Variables))
		os.Exit(1)
	}
	fmt.Printf("OK %s\n", sysDescr)
}

func authProtocol(name string) (gosnmp.SnmpV3AuthProtocol, error) {
	switch name {
	case "NoAuth":
		return gosnmp.NoAuth, nil
	case "MD5":
		return gosnmp.MD5, nil
	case "SHA":
		return gosnmp.SHA, nil
	case "SHA224":
		return gosnmp.SHA224, nil
	case "SHA256":
		return gosnmp.SHA256, nil
	case "SHA384":
		return gosnmp.SHA384, nil
	case "SHA512":
		return gosnmp.SHA512, nil
	default:
		return 0, fmt.Errorf("unknown auth protocol %q", name)
	}
}

func privProtocol(name string) (gosnmp.SnmpV3PrivProtocol, error) {
	switch name {
	case "NoPriv":
		return gosnmp.NoPriv, nil
	case "DES":
		return gosnmp.DES, nil
	case "AES":
		return gosnmp.AES, nil
	case "AES192":
		return gosnmp.AES192, nil
	case "AES256":
		return gosnmp.AES256, nil
	case "AES192C":
		return gosnmp.AES192C, nil
	case "AES256C":
		return gosnmp.AES256C, nil
	default:
		return 0, fmt.Errorf("unknown priv protocol %q", name)
	}
}
