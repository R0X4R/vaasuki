package mongo

import (
	"bytes"
	"fmt"
	"time"

	"github.com/R0X4R/vaasuki/v2/pkg/model"
	"github.com/R0X4R/vaasuki/v2/pkg/network"
)

// mongoListDatabasesOpMsg is an OP_MSG wire protocol command {"listDatabases": 1, "$db": "admin"}.
var mongoListDatabasesOpMsg = []byte{
	0x3c, 0x00, 0x00, 0x00, // Message length (60 bytes)
	0x01, 0x00, 0x00, 0x00, // Request ID
	0x00, 0x00, 0x00, 0x00, // ResponseTo
	0xdd, 0x07, 0x00, 0x00, // OpCode: OP_MSG (2013)
	0x00, 0x00, 0x00, 0x00, // FlagBits
	0x00,                   // Section Kind 0
	0x27, 0x00, 0x00, 0x00, // BSON document length (39 bytes)
	0x10, 'l', 'i', 's', 't', 'D', 'a', 't', 'a', 'b', 'a', 's', 'e', 's', 0x00,
	0x01, 0x00, 0x00, 0x00, // 1
	0x02, '$', 'd', 'b', 0x00,
	0x06, 0x00, 0x00, 0x00, // "$db" string length (6)
	'a', 'd', 'm', 'i', 'n', 0x00,
	0x00, // Document terminator
}

// Verify tests whether a MongoDB database instance permits unauthenticated database listing.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	if _, err := conn.Write(mongoListDatabasesOpMsg); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil || n < 16 {
		return nil, err
	}

	resp := buf[:n]
	if bytes.Contains(resp, []byte("requires authentication")) || bytes.Contains(resp, []byte("Unauthorized")) {
		return nil, nil
	}

	if bytes.Contains(resp, []byte("databases")) {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "mongodb",
			Service:    "mongodb",
			Title:      "Unauthenticated MongoDB Administrative Database Access",
			Severity:   "critical",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  []string{fmt.Sprintf("MongoDB OP_MSG listDatabases confirmed (%d bytes response)", n)},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
