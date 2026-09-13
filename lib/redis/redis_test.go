package redis

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
)

func TestRedisUnauthenticatedMock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		line, _ := rw.ReadString('\n')
		if line == "PING\r\n" {
			rw.WriteString("+PONG\r\n")
			rw.Flush()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	finding, err := Verify("127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding for unauthenticated redis")
	}
	if finding.Confidence != model.Confirmed {
		t.Errorf("expected confirmed, got %s", finding.Confidence)
	}
}

func TestRedisPasswordProtectedMock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		line, _ := rw.ReadString('\n')
		if line == "PING\r\n" {
			rw.WriteString("-NOAUTH Authentication required.\r\n")
			rw.Flush()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	finding, err := Verify("127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding != nil {
		t.Fatalf("expected nil finding for password-protected redis, got: %+v", finding)
	}
}
