package cassandra

import (
	"fmt"
	"io"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether an exposed Cassandra instance permits unauthenticated access without PasswordAuthenticator.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Cassandra Native Protocol v4 STARTUP frame
	// Header (9 bytes): version=0x04, flags=0x00, stream=0x0001, opcode=0x01 (STARTUP), length=22 (0x00000016)
	// Body: map count=1, key="CQL_VERSION", val="3.0.0"
	startupFrame := []byte{
		0x04, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x16,
		0x00, 0x01,
		0x00, 0x0b, 'C', 'Q', 'L', '_', 'V', 'E', 'R', 'S', 'I', 'O', 'N',
		0x00, 0x05, '3', '.', '0', '.', '0',
	}

	if _, err := conn.Write(startupFrame); err != nil {
		return nil, err
	}

	buf := make([]byte, 9)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, nil
	}

	// Response header: byte 0=0x84, byte 4=opcode
	if buf[0] == 0x84 {
		opcode := buf[4]
		// Opcode 0x02 = READY (Authentication disabled / unauthenticated)
		if opcode == 0x02 {
			return &model.Finding{
				Target:     host,
				Port:       port,
				Protocol:   "cql",
				Service:    "cassandra",
				Title:      "Unauthenticated Apache Cassandra Cluster Access (AllowAllAuthenticator)",
				Severity:   "high",
				Confidence: model.Confirmed,
				Auth: model.AuthResult{
					Attempted: true,
					Method:    "none",
					Status:    "successful",
				},
				Evidence:  []string{"STARTUP frame received 0x02 READY response without authentication challenge"},
				Timestamp: time.Now().UTC(),
			}, nil
		}
	}

	return nil, nil
}
