package zookeeper

import (
	"bufio"
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
	_, err = conn.Write([]byte("stat\n"))
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	var lines []string
	for i := 0; i < 20; i++ {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			lines = append(lines, strings.TrimSpace(line))
		}
		if err != nil {
			break
		}
	}

	fullResp := strings.Join(lines, " ")
	if !strings.Contains(fullResp, "Zookeeper version") && !strings.Contains(fullResp, "Node count") && !strings.Contains(fullResp, "Environment") {
		// Try envi command if stat is restricted
		if connEnvi, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout); err == nil {
			_ = connEnvi.SetDeadline(time.Now().Add(timeout))
			_, _ = connEnvi.Write([]byte("envi\n"))
			readerEnvi := bufio.NewReader(connEnvi)
			for i := 0; i < 20; i++ {
				l, err := readerEnvi.ReadString('\n')
				if len(l) > 0 {
					lines = append(lines, strings.TrimSpace(l))
				}
				if err != nil {
					break
				}
			}
			connEnvi.Close()
			fullResp = strings.Join(lines, " ")
		}
	}

	if !strings.Contains(fullResp, "Zookeeper version") && !strings.Contains(fullResp, "Node count") && !strings.Contains(fullResp, "Environment") {
		return nil, nil
	}

	mode := "read-only"
	severity := "medium"
	if conn2, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout); err == nil {
		_ = conn2.SetDeadline(time.Now().Add(timeout))
		_, _ = conn2.Write([]byte("isro\n"))
		buf := make([]byte, 32)
		n, _ := conn2.Read(buf)
		conn2.Close()
		if strings.Contains(string(buf[:n]), "rw") {
			mode = "read-write"
			severity = "high"
		}
	}

	evidence := []string{fmt.Sprintf("ZooKeeper mode: %s", mode)}
	if len(lines) > 0 {
		evidence = append(evidence, lines[0])
	}

	return &model.Finding{
		Target:     host,
		Port:       port,
		Protocol:   "zookeeper",
		Service:    "zookeeper",
		Title:      fmt.Sprintf("Unauthenticated Apache ZooKeeper Access (%s mode)", mode),
		Severity:   severity,
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
