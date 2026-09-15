package smb

import (
	"bytes"
	"fmt"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// smbNegotiatePayload sends SMB1 and SMB2 dialect negotiations.
var smbNegotiatePayload = []byte{
	// NetBIOS Session Service Header
	0x00, 0x00, 0x00, 0x54,
	// SMB Header
	0xff, 0x53, 0x4d, 0x42, // "\xffSMB"
	0x72,                   // SMB_COM_NEGOTIATE
	0x00, 0x00, 0x00, 0x00, // Status
	0x18,                   // Flags
	0x53, 0xc8,             // Flags2
	0x00, 0x00,             // PID High
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
	0x00, 0x00,             // Reserved
	0x00, 0x00,             // TID
	0xff, 0xfe,             // PID
	0x00, 0x00,             // UID
	0x00, 0x00,             // MID
	// Word Count
	0x00,
	// Byte Count
	0x31, 0x00,
	// Dialects
	0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, // LANMAN1.0
	0x02, 0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32, 0x00, // LM1.2X002
	0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00, // NT LANMAN 1.0
	0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00, // NT LM 0.12
}

// smb2NegotiatePayload sends SMB2/SMB3 dialect negotiations (dialects 0x0202, 0x0210, 0x0300, 0x0311).
var smb2NegotiatePayload = []byte{
	// NetBIOS Session Service Header (Length: 0x6c = 108 bytes)
	0x00, 0x00, 0x00, 0x6c,
	// SMB2 Header (64 bytes)
	0xfe, 0x53, 0x4d, 0x42, // ProtocolId: "\xfeSMB"
	0x40, 0x00,             // StructureSize (64)
	0x00, 0x00,             // CreditCharge (0)
	0x00, 0x00, 0x00, 0x00, // Status (0)
	0x00, 0x00,             // Command: NEGOTIATE (0x0000)
	0x00, 0x00,             // CreditsRequested (0)
	0x00, 0x00, 0x00, 0x00, // Flags (0)
	0x00, 0x00, 0x00, 0x00, // NextCommand (0)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageId (0)
	0x00, 0x00, 0x00, 0x00, // ProcessId (0)
	0x00, 0x00, 0x00, 0x00, // TreeId (0)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionId (0)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (16 zeros)
	// SMB2 Negotiate Request Body (36 bytes)
	0x24, 0x00, // StructureSize (36)
	0x04, 0x00, // DialectCount (4)
	0x01, 0x00, // SecurityMode (Signing enabled)
	0x00, 0x00, // Reserved (0)
	0x00, 0x00, 0x00, 0x00, // Capabilities (0)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientGuid (16 zeros)
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime (0)
	// Dialects (4 * 2 = 8 bytes)
	0x02, 0x02, // SMB 2.0.2
	0x10, 0x02, // SMB 2.1
	0x00, 0x03, // SMB 3.0
	0x11, 0x03, // SMB 3.1.1
}

// Verify tests whether an SMB / Samba service is active and responsive to dialect negotiation.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	// Try SMB1 negotiate first
	finding, err := probeDialect(host, port, timeout, smbNegotiatePayload)
	if err == nil && finding != nil {
		return finding, nil
	}

	// Fallback to SMB2/SMB3 negotiate (for modern Windows Server / Win10/11 where SMB1 is disabled)
	return probeDialect(host, port, timeout, smb2NegotiatePayload)
}

func probeDialect(host string, port int, timeout time.Duration, payload []byte) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return nil, err
	}

	// Check for SMB1 (\xffSMB) or SMB2 (\xfeSMB) response magic
	if bytes.Contains(buf[:n], []byte("\xffSMB")) || bytes.Contains(buf[:n], []byte("\xfeSMB")) {
		proto := "SMBv1/SMBv2"
		if bytes.Contains(buf[:n], []byte("\xfeSMB")) {
			proto = "SMBv2/SMBv3"
		}

		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "smb",
			Service:    "smb",
			Title:      fmt.Sprintf("Active %s File Sharing Service Detected", proto),
			Severity:   "medium",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "negotiate",
				Status:    "successful",
			},
			Evidence:  []string{fmt.Sprintf("SMB protocol header handshake confirmed (%d bytes)", n)},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
