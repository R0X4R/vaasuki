package vnc

import (
	"bytes"
	"fmt"
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

	bannerBuf := make([]byte, 32)
	n, err := conn.Read(bannerBuf)
	if err != nil || n < 12 {
		return nil, nil
	}
	banner := string(bannerBuf[:n])
	if !strings.HasPrefix(banner, "RFB ") {
		return nil, nil
	}

	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		return nil, err
	}

	secBuf := make([]byte, 64)
	sn, err := conn.Read(secBuf)
	if err != nil || sn < 1 {
		return nil, nil
	}

	hasNoneAuth := false
	numTypes := int(secBuf[0])
	if numTypes > 0 && sn >= 1+numTypes {
		for _, st := range secBuf[1 : 1+numTypes] {
			if st == 0x01 { // SecurityType None
				hasNoneAuth = true
				break
			}
		}
	} else if sn == 4 && secBuf[0] == 0x00 && secBuf[1] == 0x00 && secBuf[2] == 0x00 && secBuf[3] == 0x01 {
		// RFB 003.003 legacy single 32-bit int security type: 1 = None
		hasNoneAuth = true
	}

	if hasNoneAuth {
		// Select SecurityType None (1) and confirm SecurityResult OK (0x00000000)
		if _, err := conn.Write([]byte{0x01}); err == nil {
			resBuf := make([]byte, 4)
			rn, err := conn.Read(resBuf)
			if err == nil && rn == 4 && bytes.Equal(resBuf, []byte{0x00, 0x00, 0x00, 0x00}) {
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
					Evidence:  []string{fmt.Sprintf("Banner: %s", strings.TrimSpace(banner)), "Security Type 1 (None) accepted, SecurityResult OK (0x00000000)"},
					Timestamp: time.Now().UTC(),
				}, nil
			}
		}
	}

	return nil, nil
}
