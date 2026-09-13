package network

import (
	"net"
	"testing"
	"time"
)

func TestLocalPortCheck(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("unable to start test listener: %v", err)
	}
	defer ln.Close()

	port := ln.Addr().(*net.TCPAddr).Port
	if !IsPortOpen("127.0.0.1", port, 2*time.Second) {
		t.Errorf("expected port %d to be open", port)
	}

	if IsPortOpen("127.0.0.1", 65530, 200*time.Millisecond) {
		t.Errorf("expected unused port to be closed")
	}
}
