package nfs

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
	"github.com/R0X4R/vaasuki/pkg/network"
)

// Verify tests whether an exposed NFS service responds to RPC queries.
func Verify(host string, port int, timeout time.Duration) (*model.Finding, error) {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// RPC Call: Record marking (last fragment, len=40), XID=0x12345678, MsgType=CALL(0), RPCVers=2, Prog=100003 (NFS), Vers=3, Proc=0 (NULL), Auth=NULL, Verf=NULL
	rpcNull := []byte{
		0x80, 0x00, 0x00, 0x28, // Fragment header: last fragment, len 40
		0x12, 0x34, 0x56, 0x78, // XID
		0x00, 0x00, 0x00, 0x00, // Msg Type: CALL (0)
		0x00, 0x00, 0x00, 0x02, // RPC Version 2
		0x00, 0x01, 0x86, 0xa3, // Program: 100003 (NFS)
		0x00, 0x00, 0x00, 0x03, // Version: 3
		0x00, 0x00, 0x00, 0x00, // Procedure: 0 (NULL)
		0x00, 0x00, 0x00, 0x00, // Auth Flavor: NULL
		0x00, 0x00, 0x00, 0x00, // Auth Length: 0
		0x00, 0x00, 0x00, 0x00, // Verf Flavor: NULL
		0x00, 0x00, 0x00, 0x00, // Verf Length: 0
	}

	if _, err := conn.Write(rpcNull); err != nil {
		return nil, err
	}

	// Read full RPC reply header: fragment(4) + XID(4) + MsgType(4) + ReplyStat(4) + VerfFlavor(4) + VerfLen(4) + AcceptStat(4) = 28 bytes
	buf := make([]byte, 28)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, nil
	}

	xid := binary.BigEndian.Uint32(buf[4:8])
	msgType := binary.BigEndian.Uint32(buf[8:12])     // 1 = REPLY
	replyStat := binary.BigEndian.Uint32(buf[12:16])  // 0 = MSG_ACCEPTED
	acceptStat := binary.BigEndian.Uint32(buf[24:28]) // 0 = SUCCESS

	if xid == 0x12345678 && msgType == 1 && replyStat == 0 && acceptStat == 0 {
		return &model.Finding{
			Target:     host,
			Port:       port,
			Protocol:   "nfs",
			Service:    "nfs",
			Title:      "Exposed Network File System (NFS) Service",
			Severity:   "high",
			Confidence: model.Confirmed,
			Auth: model.AuthResult{
				Attempted: true,
				Method:    "none",
				Status:    "successful",
			},
			Evidence:  []string{"NFS RPC NULL procedure succeeded with MSG_ACCEPTED and SUCCESS status"},
			Timestamp: time.Now().UTC(),
		}, nil
	}

	return nil, nil
}
