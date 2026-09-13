package ftp

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/R0X4R/vaasuki/pkg/model"
)

func TestFTPAnonymousMock(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		rw.WriteString("220 Welcome to Test FTP\r\n")
		rw.Flush()

		line, _ := rw.ReadString('\n')
		if line == "USER anonymous\r\n" {
			rw.WriteString("331 Please specify the password.\r\n")
			rw.Flush()
		}
		line, _ = rw.ReadString('\n')
		if line == "PASS anonymous@\r\n" {
			rw.WriteString("230 Login successful.\r\n")
			rw.Flush()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	finding, err := Verify("127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding == nil {
		t.Fatal("expected finding for anonymous ftp")
	}
	if finding.Confidence != model.Confirmed {
		t.Errorf("expected confirmed finding, got %s", finding.Confidence)
	}
}

func TestFTPAnonymousRejected(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		rw := bufio.NewReadWriter(bufio.NewReader(conn), bufio.NewWriter(conn))
		rw.WriteString("220 Welcome to Hardened FTP\r\n")
		rw.Flush()

		line, _ := rw.ReadString('\n')
		if line == "USER anonymous\r\n" {
			rw.WriteString("530 Permission denied.\r\n")
			rw.Flush()
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	finding, err := Verify("127.0.0.1", port, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if finding != nil {
		t.Fatalf("expected nil finding for rejected anonymous login, got: %+v", finding)
	}
}
