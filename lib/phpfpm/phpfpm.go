package phpfpm

import (
	"fmt"
	"io"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	fcgiProbe := []byte{
		0x01, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	if _, err := conn.Write(fcgiProbe); err != nil {
		return nil, err
	}

	header := make([]byte, 8)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil
	}

	if header[0] == 0x01 && (header[1] == 0x0a || header[1] == 0x03 || header[1] == 0x07) {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "fastcgi",
			Service:    "php-fpm",
			Title:      "Exposed Raw PHP-FPM FastCGI Daemon",
			Severity:   "critical",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  []string{"Valid FastCGI record response received"},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
