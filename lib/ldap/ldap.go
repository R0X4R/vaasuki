package ldap

import (
	"bytes"
	"fmt"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

// ldapAnonymousBindRequest is a standard BER-encoded LDAPv3 simple anonymous bind packet.
var ldapAnonymousBindRequest = []byte{
	0x30, 0x0c, // SEQUENCE, 12 bytes
	0x02, 0x01, 0x01, // Message ID: 1
	0x60, 0x07, // BindRequest (APPLICATION 0), 7 bytes
	0x02, 0x01, 0x03, // Version: 3
	0x04, 0x00, // Name: "" (anonymous)
	0x80, 0x00, // Authentication: simple ""
}

// Verify tests whether an LDAP directory service accepts anonymous authentication binds.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(ldapAnonymousBindRequest); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return nil, err
	}

	// LDAP bindResponse has tag 0x61. ResultCode 0 (success) is encoded as 0x0a, 0x01, 0x00.
	if bytes.Contains(buf[:n], []byte{0x61}) && bytes.Contains(buf[:n], []byte{0x0a, 0x01, 0x00}) {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "ldap",
			Service:    "ldap",
			Title:      "LDAP Anonymous Directory Bind Authentication Permitted",
			Severity:   "high",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "anonymous",
				Status:    "successful",
			},
			Evidence:  []string{fmt.Sprintf("LDAPv3 bindResponse success code confirmed (%d bytes)", n)},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
