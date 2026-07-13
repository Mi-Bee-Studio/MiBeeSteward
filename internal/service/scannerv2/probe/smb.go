package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"mibee-steward/internal/service/scannerv2"
)

// SMBProbe sends an SMB2 Negotiate Request on TCP port 445 and parses the
// Negotiate Response to extract the server's highest supported dialect. Unlike
// SSH/FTP, an SMB server does NOT greet on connect — it waits for the client to
// initiate. Without this probe, port 445 is only a port-only "smb" fallback
// with no version info.
//
// The probe sends a minimal SMB2 NEGOTIATE requesting dialects 0x0202 (2.1),
// 0x0300 (3.0), 0x0302 (3.0.2), and 0x0311 (3.1.1). The server responds with
// the highest dialect it supports.
//
// Known limitation: SMB1-only servers (some embedded NAS devices like QNAP
// "Turbo station") reject SMB2 Negotiate with STATUS_INVALID_PARAMETER. These
// require a full SMB1 Session Setup AndX to extract the ServerType/OS string,
// which is a future enhancement. For SMB2-capable servers (Windows, modern
// Samba), the dialect is correctly extracted.
//
// Evidence emitted: Kind="smb_negotiate", RawData carries "dialect" (e.g.
// "SMB 3.1.1") and "os" (from SMB1 when available).
type SMBProbe struct {
	timeout time.Duration
}

// NewSMBProbe creates an SMB probe with the given per-attempt timeout.
func NewSMBProbe(timeout time.Duration) *SMBProbe {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &SMBProbe{timeout: timeout}
}

func (p *SMBProbe) Name() string { return "active:smb" }

func (p *SMBProbe) Probe(ctx context.Context, ip string, _ scannerv2.ProbeHint) ([]scannerv2.Evidence, error) {
	dialer := net.Dialer{Timeout: p.timeout}
	addr := net.JoinHostPort(ip, "445")
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil // port closed or firewalled — not an error
	}
	defer conn.Close()

	deadline := time.Now().Add(p.timeout)
	_ = conn.SetDeadline(deadline)

	// Send SMB2 Negotiate Request.
	if _, err := conn.Write(smb2NegotiateRequest()); err != nil {
		return nil, nil
	}

	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil || n < 64 {
		return nil, nil
	}

	raw := map[string]string{}
	if dialect := parseSMB2Dialect(resp[:n]); dialect != "" {
		raw["dialect"] = dialect
	}

	// Try SMB1 negotiate for the OS string (Samba puts "Samba" in the
	// ServerType). Only attempt if the SMB2 negotiate was inconclusive.
	if raw["dialect"] == "" {
		_ = conn.SetDeadline(time.Now().Add(p.timeout))
		conn2, err2 := dialer.DialContext(ctx, "tcp", addr)
		if err2 == nil {
			defer conn2.Close()
			_ = conn2.SetDeadline(time.Now().Add(p.timeout))
			if _, err := conn2.Write(smb1NegotiateRequest()); err == nil {
				r2 := make([]byte, 4096)
				n2, _ := conn2.Read(r2)
				if n2 > 32 {
					if os := parseSMB1OS(r2[:n2]); os != "" {
						raw["os"] = os
						raw["dialect"] = "SMB 1.0"
					}
				}
			}
		}
	}

	if len(raw) == 0 {
		return nil, nil
	}
	raw["port"] = "445"

	return []scannerv2.Evidence{{
		Source:     "active:smb",
		Kind:       "smb_negotiate",
		IP:         ip,
		Port:       445,
		Protocol:   "tcp",
		RawData:    raw,
		Confidence: 0.9,
		ObservedAt: time.Now(),
	}}, nil
}

// smb2NegotiateRequest builds a minimal SMB2 NEGOTIATE request carrying
// dialects 2.1, 3.0, 3.0.2, 3.1.1. The structure follows MS-SMB2 §2.2.3.
func smb2NegotiateRequest() []byte {
	dialects := []uint16{0x0202, 0x0300, 0x0302, 0x0311}
	dialectsLen := len(dialects) * 2

	// SMB2 header (64 bytes) + Negotiate Request body.
	// StructureSize=36, DialectCount=4, SecurityMode=1, Reserved=0,
	// Capabilities=0, ClientGuid=0, NegotiateContextOffset=0,
	// NegotiateContextCount=0, Reserved2=0.
	body := make([]byte, 36)
	binary.LittleEndian.PutUint16(body[0:2], 36)                    // StructureSize
	binary.LittleEndian.PutUint16(body[2:4], uint16(len(dialects))) // DialectCount
	binary.LittleEndian.PutUint16(body[4:6], 1)                     // SecurityMode (NEGOTIATE_SIGNING_ENABLED)
	// 6:8 Reserved = 0
	binary.LittleEndian.PutUint32(body[8:12], 0) // Capabilities
	// 12:28 ClientGuid = 0 (16 bytes)
	binary.LittleEndian.PutUint32(body[28:32], 0) // NegotiateContextOffset
	binary.LittleEndian.PutUint16(body[32:34], 0) // NegotiateContextCount
	// 34:36 Reserved2 = 0

	pkt := make([]byte, 0, 4+64+36+dialectsLen)
	// NetBIOS session header: 4 bytes (type=0, length).
	nbHeader := make([]byte, 4)
	length := uint32(64 + 36 + dialectsLen)
	nbHeader[2] = byte(length >> 8)
	nbHeader[3] = byte(length)
	pkt = append(pkt, nbHeader...)

	// SMB2 header.
	hdr := make([]byte, 64)
	hdr[0] = 0xFE // ProtocolId
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	binary.LittleEndian.PutUint16(hdr[4:6], 64)           // StructureSize
	binary.LittleEndian.PutUint16(hdr[6:8], 0)            // CreditCharge
	binary.LittleEndian.PutUint32(hdr[8:12], 0)           // Status
	binary.LittleEndian.PutUint16(hdr[12:14], 0)          // Command = NEGOTIATE
	binary.LittleEndian.PutUint16(hdr[14:16], 1)          // CreditRequest
	binary.LittleEndian.PutUint32(hdr[16:20], 0xFFFFFFFF) // Flags
	binary.LittleEndian.PutUint32(hdr[20:24], 0)          // NextCommand
	binary.LittleEndian.PutUint64(hdr[24:32], 0)          // MessageId
	// 32:40 Reserved + TreeId
	binary.LittleEndian.PutUint64(hdr[40:48], 1) // SessionId
	// 48:64 Signature = 0

	pkt = append(pkt, hdr...)
	pkt = append(pkt, body...)
	for _, d := range dialects {
		db := make([]byte, 2)
		binary.LittleEndian.PutUint16(db, d)
		pkt = append(pkt, db...)
	}

	return pkt
}

// parseSMB2Dialect extracts the highest dialect from an SMB2 Negotiate Response.
// The response header starts with 0xFE "SMB". The Negotiate Response body
// starts at offset 64; DialectRevision is at body offset 4 (byte 68 of packet).
func parseSMB2Dialect(resp []byte) string {
	if len(resp) < 70 {
		return ""
	}
	// Check for SMB2 magic (0xFE "SMB").
	if resp[0] != 0xFE || resp[1] != 'S' || resp[2] != 'M' || resp[3] != 'B' {
		return ""
	}
	dialect := binary.LittleEndian.Uint16(resp[68:70])
	switch dialect {
	case 0x02FF:
		return "SMB 2.0"
	case 0x0202:
		return "SMB 2.1"
	case 0x0300:
		return "SMB 3.0"
	case 0x0302:
		return "SMB 3.0.2"
	case 0x0311:
		return "SMB 3.1.1"
	case 0x0000:
		return "" // server didn't pick a dialect
	default:
		return fmt.Sprintf("SMB 0x%04X", dialect)
	}
}

// smb1NegotiateRequest builds a minimal SMB1 negotiate with a single dialect
// "PC NETWORK PROGRAM 1.0". Samba responds with the ServerType string which
// contains the Samba version and OS info.
func smb1NegotiateRequest() []byte {
	// SMB1 header (32 bytes) + Negotiate dialect count (1) + byte count + dialect string.
	dialect := []byte("PC NETWORK PROGRAM 1.0\x00")
	// NetBIOS header.
	nb := make([]byte, 4)
	length := uint32(32 + 2 + 2 + len(dialect))
	nb[2] = byte(length >> 8)
	nb[3] = byte(length)

	hdr := make([]byte, 32)
	hdr[0] = 0xFF // SMB1 ProtocolId
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	hdr[4] = 0x72 // Command = SMB_COM_NEGOTIATE
	// Status=0, Flags=0, Flags2=0 (minimal)
	// 12:38 PID/UID/MID/TID = 0

	// Parameter: WordCount=0
	// Data: ByteCount + dialect buffer
	data := make([]byte, 0, 2+2+len(dialect))
	bc := make([]byte, 2)
	binary.LittleEndian.PutUint16(bc, uint16(len(dialect)+2))
	data = append(data, bc...)
	// Dialect buffer format: format byte (0x02=ASCII) + dialect string
	data = append(data, 0x02)
	data = append(data, dialect...)

	pkt := make([]byte, 0, len(nb)+len(hdr)+len(data))
	pkt = append(pkt, nb...)
	pkt = append(pkt, hdr...)
	pkt = append(pkt, data...)
	return pkt
}

// parseSMB1OS extracts the ServerType (OS string) from an SMB1 Negotiate Response.
// The response has a 32-byte header, then WordCount(1), then parameters, then
// the byte data containing the OEM domain name + ServerType string. The
// ServerType is the second null-terminated string in the byte data.
func parseSMB1OS(resp []byte) string {
	if len(resp) < 35 {
		return ""
	}
	// Check SMB1 magic.
	if resp[0] != 0xFF || resp[1] != 'S' || resp[2] != 'M' || resp[3] != 'B' {
		return ""
	}
	// Skip 32-byte header + WordCount byte.
	wordCount := int(resp[32])
	off := 33 + wordCount*2
	if off+2 > len(resp) {
		return ""
	}
	byteCount := int(binary.LittleEndian.Uint16(resp[off : off+2]))
	off += 2
	if off+byteCount > len(resp) {
		byteCount = len(resp) - off
	}
	// The byte data has two strings: ServerDomain (OEM name) and ServerType.
	// Find the second null-terminated string.
	data := resp[off : off+byteCount]
	firstNull := -1
	for i, b := range data {
		if b == 0 {
			firstNull = i
			break
		}
	}
	if firstNull < 0 || firstNull+1 >= len(data) {
		return ""
	}
	// Second string = ServerType.
	rest := data[firstNull+1:]
	for i, b := range rest {
		if b == 0 {
			return string(rest[:i])
		}
	}
	return string(rest)
}
