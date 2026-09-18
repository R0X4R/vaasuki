package kafka

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether an Apache Kafka broker allows unauthenticated wire protocol requests.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Metadata Request v0 (ApiKey 3, ApiVersion 0, CorrelationId 1234, ClientId null, TopicsCount 0):
	// A SASL-enforced broker disconnects or rejects non-SASL Metadata requests prior to authentication.
	req := []byte{
		0x00, 0x00, 0x00, 0x0e,
		0x00, 0x03,
		0x00, 0x00,
		0x00, 0x00, 0x04, 0xd2,
		0xff, 0xff,
		0x00, 0x00, 0x00, 0x00,
	}

	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return nil, nil
	}

	// First 4 bytes = response size, next 4 bytes = CorrelationId
	corrID := binary.BigEndian.Uint32(buf[4:8])
	if corrID == 1234 {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "kafka",
			Service:    "kafka",
			Title:      "Unauthenticated Apache Kafka Broker Access",
			Severity:   "high",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  []string{"Kafka Metadata wire protocol response accepted without SASL authentication"},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}