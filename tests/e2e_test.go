package tests

import (
	"bufio"
	"net"
	"testing"
	"time"

	"github.com/R0X4R/vaasuki/lib/ftp"
	"github.com/R0X4R/vaasuki/lib/redis"
	"github.com/R0X4R/vaasuki/pkg/model"
)

func TestEndToEndFTPAndRedisVerification(t *testing.T) {
	// 1. Mock Vulnerable FTP Listener
	ftpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on ftp port: %v", err)
	}
	defer ftpLn.Close()

	go func() {
		for {
			conn, err := ftpLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
				rw.WriteString("220 Welcome to Test FTP\r\n")
				rw.Flush()

				line, _ := rw.ReadString('\n')
				if line == "USER anonymous\r\n" {
					rw.WriteString("331 Anonymous password accepted.\r\n")
					rw.Flush()
				}
				line, _ = rw.ReadString('\n')
				if line == "PASS anonymous@\r\n" {
					rw.WriteString("230 User logged in successfully.\r\n")
					rw.Flush()
				}
			}(conn)
		}
	}()

	// 2. Mock Vulnerable Redis Listener
	redisLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on redis port: %v", err)
	}
	defer redisLn.Close()

	go func() {
		for {
			conn, err := redisLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
				line, _ := rw.ReadString('\n')
				if line == "PING\r\n" {
					rw.WriteString("+PONG\r\n")
					rw.Flush()
				}
			}(conn)
		}
	}()

	ftpPort := ftpLn.Addr().(*net.TCPAddr).Port
	redisPort := redisLn.Addr().(*net.TCPAddr).Port

	// Verify FTP
	ftpFinding, err := ftp.Verify("127.0.0.1", ftpPort, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected ftp error: %v", err)
	}
	if ftpFinding == nil || ftpFinding.Confidence != model.Confirmed {
		t.Fatalf("expected confirmed ftp finding, got: %+v", ftpFinding)
	}

	// Verify Redis
	redisFinding, err := redis.Verify("127.0.0.1", redisPort, 2*time.Second)
	if err != nil {
		t.Fatalf("unexpected redis error: %v", err)
	}
	if redisFinding == nil || redisFinding.Confidence != model.Confirmed {
		t.Fatalf("expected confirmed redis finding, got: %+v", redisFinding)
	}
}
