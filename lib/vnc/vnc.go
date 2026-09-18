package vnc

import (
	"bytes"
	"fmt"
	"io"
	"strings"
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

	bannerBuf := make([]byte, 12)
	if _, err := io.ReadFull(conn, bannerBuf); err != nil {
		return nil, nil
	}
	banner := string(bannerBuf)
	if !strings.HasPrefix(banner, "RFB ") {
		return nil, nil
	}

	// Negotiate compatible RFB version
	clientVersion := "RFB 003.008\n"
	isRFB33 := strings.HasPrefix(banner, "RFB 003.003")
	isRFB37 := strings.HasPrefix(banner, "RFB 003.007")
	if isRFB33 {
		clientVersion = "RFB 003.003\n"
	} else if isRFB37 {
		clientVersion = "RFB 003.007\n"
	}

	if _, err := conn.Write([]byte(clientVersion)); err != nil {
		return nil, err
	}

	hasNoneAuth := false

	if isRFB33 {
		// In RFB 3.3, server sends single 32-bit int: 1 = None, 2 = VNC Auth
		secTypeBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, secTypeBuf); err == nil {
			if secTypeBuf[0] == 0 && secTypeBuf[1] == 0 && secTypeBuf[2] == 0 && secTypeBuf[3] == 1 {
				hasNoneAuth = true
			}
		}
	} else {
		// In RFB 3.7 and 3.8, server sends count followed by types
		countBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, countBuf); err == nil && countBuf[0] > 0 {
			types := make([]byte, int(countBuf[0]))
			if _, err := io.ReadFull(conn, types); err == nil {
				for _, t := range types {
					if t == 0x01 { // SecurityType None
						hasNoneAuth = true
						break
					}
				}
			}
		}
	}

	if hasNoneAuth {
		evidence := []string{fmt.Sprintf("Banner: %s", strings.TrimSpace(banner)), "Security Type 1 (None) offered without authentication"}

		if !isRFB33 {
			// Send chosen security type 1 (None)
			if _, err := conn.Write([]byte{0x01}); err != nil {
				return nil, err
			}

			// RFB 3.8 sends 4-byte SecurityResult (0x00000000 = OK)
			if !isRFB37 {
				resBuf := make([]byte, 4)
				if _, err := io.ReadFull(conn, resBuf); err != nil || !bytes.Equal(resBuf, []byte{0x00, 0x00, 0x00, 0x00}) {
					return nil, nil
				}
				evidence = append(evidence, "SecurityResult OK (0x00000000) confirmed")
			}
		}

		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "vnc",
			Service:    "vnc",
			Version:    strings.TrimSpace(banner),
			Title:      "Unauthenticated VNC Remote Desktop Access (Security Type None)",
			Severity:   "critical",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  evidence,
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
