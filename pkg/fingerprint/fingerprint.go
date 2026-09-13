package fingerprint

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/R0X4R/vaasuki/pkg/network"
)

// Service identifies the recognized network application protocol.
type Service string

const (
	ServiceFTP           Service = "ftp"
	ServiceRedis         Service = "redis"
	ServiceMemcached     Service = "memcached"
	ServiceElasticsearch Service = "elasticsearch"
	ServiceDockerAPI     Service = "docker"
	ServiceEtcd          Service = "etcd"
	ServiceConsul        Service = "consul"
	ServiceGrafana       Service = "grafana"
	ServiceJenkins       Service = "jenkins"
	ServicePrometheus    Service = "prometheus"
	ServiceRabbitMQ      Service = "rabbitmq"
	ServiceSMB           Service = "smb"
	ServiceMongo         Service = "mongodb"
	ServiceSMTP          Service = "smtp"
	ServiceTelnet        Service = "telnet"
	ServiceHTTP          Service = "http"
	ServiceUnknown       Service = "unknown"
)

// Identify dynamically detects the service on an open host:port endpoint.
func Identify(host string, port int, timeout time.Duration) Service {
	// Step 1: Passive Banner Grab (Services that talk first, e.g. FTP, SMTP, Telnet, SSH)
	if svc := probeBanner(host, port, timeout); svc != ServiceUnknown {
		return svc
	}

	// Step 2: Protocol-Specific Active Probes
	if svc := probeRedis(host, port, timeout); svc != ServiceUnknown {
		return svc
	}
	if svc := probeMemcached(host, port, timeout); svc != ServiceUnknown {
		return svc
	}
	if svc := probeMongo(host, port, timeout); svc != ServiceUnknown {
		return svc
	}
	if svc := probeSMB(host, port, timeout); svc != ServiceUnknown {
		return svc
	}
	if svc := probeHTTP(host, port, timeout); svc != ServiceUnknown {
		return svc
	}

	return ServiceUnknown
}

// Guess fallback service based on standard port heuristics when dynamic probes are inconclusive.
func Guess(port int) Service {
	switch port {
	case 21, 2121:
		return ServiceFTP
	case 23, 2323:
		return ServiceTelnet
	case 25, 465, 587, 1025, 2525:
		return ServiceSMTP
	case 445, 4445, 139:
		return ServiceSMB
	case 2375, 2376:
		return ServiceDockerAPI
	case 2379, 2380:
		return ServiceEtcd
	case 3000:
		return ServiceGrafana
	case 5672, 15672:
		return ServiceRabbitMQ
	case 6379, 6380:
		return ServiceRedis
	case 8080:
		return ServiceJenkins
	case 8500:
		return ServiceConsul
	case 9090:
		return ServicePrometheus
	case 9200, 9300:
		return ServiceElasticsearch
	case 11211:
		return ServiceMemcached
	case 27017, 27018:
		return ServiceMongo
	default:
		return ServiceUnknown
	}
}

func probeBanner(host string, port int, timeout time.Duration) Service {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return ServiceUnknown
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ServiceUnknown
	}
	banner := string(buf[:n])

	if strings.HasPrefix(banner, "220") {
		lower := strings.ToLower(banner)
		if strings.Contains(lower, "smtp") || strings.Contains(lower, "mailpit") || strings.Contains(lower, "esmtp") {
			return ServiceSMTP
		}
		return ServiceFTP
	}
	if bytes.Contains(buf[:n], []byte{0xff, 0xfd}) || bytes.Contains(buf[:n], []byte{0xff, 0xfb}) {
		return ServiceTelnet
	}
	return ServiceUnknown
}

func probeRedis(host string, port int, timeout time.Duration) Service {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return ServiceUnknown
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Write([]byte("PING\r\n"))
	if err != nil {
		return ServiceUnknown
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return ServiceUnknown
	}
	trimmed := strings.TrimSpace(resp)
	if trimmed == "+PONG" || strings.HasPrefix(trimmed, "-NOAUTH") || strings.HasPrefix(trimmed, "-ERR") {
		return ServiceRedis
	}
	return ServiceUnknown
}

func probeMemcached(host string, port int, timeout time.Duration) Service {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return ServiceUnknown
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Write([]byte("version\r\n"))
	if err != nil {
		return ServiceUnknown
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return ServiceUnknown
	}
	if strings.HasPrefix(strings.TrimSpace(resp), "VERSION") {
		return ServiceMemcached
	}
	return ServiceUnknown
}

func probeHTTP(host string, port int, timeout time.Duration) Service {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: (&net.Dialer{
				Timeout: timeout,
			}).DialContext,
		},
	}

	for _, scheme := range []string{"http", "https"} {
		url := fmt.Sprintf("%s://%s:%d/", scheme, host, port)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Vaasuki-Recon)")

		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		bodyStr := string(body)
		jenkinsHeader := resp.Header.Get("X-Jenkins")
		serverHeader := strings.ToLower(resp.Header.Get("Server"))

		if strings.Contains(bodyStr, "cluster_name") || strings.Contains(bodyStr, "tagline") {
			return ServiceElasticsearch
		}
		if jenkinsHeader != "" || strings.Contains(bodyStr, "Jenkins") {
			return ServiceJenkins
		}
		if strings.Contains(bodyStr, "ApiVersion") || strings.Contains(bodyStr, "Docker") || strings.Contains(serverHeader, "docker") {
			return ServiceDockerAPI
		}
		if strings.Contains(bodyStr, "etcdserver") || strings.Contains(bodyStr, "etcdcluster") {
			return ServiceEtcd
		}
		if strings.Contains(bodyStr, "Consul") || strings.Contains(bodyStr, "consul") {
			return ServiceConsul
		}
		if strings.Contains(bodyStr, "Prometheus") {
			return ServicePrometheus
		}
		if strings.Contains(bodyStr, "Grafana") || strings.Contains(bodyStr, "grafana") {
			return ServiceGrafana
		}
		if strings.Contains(bodyStr, "RabbitMQ") {
			return ServiceRabbitMQ
		}
		return ServiceHTTP
	}
	return ServiceUnknown
}

func probeSMB(host string, port int, timeout time.Duration) Service {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return ServiceUnknown
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	// SMB1 Negotiate Header
	smbPayload := []byte{
		0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42,
		0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xc8,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x4e, 0x54,
		0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
		0x00,
	}
	if _, err := conn.Write(smbPayload); err != nil {
		return ServiceUnknown
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil || n < 8 {
		return ServiceUnknown
	}
	if bytes.Contains(buf[:n], []byte("\xffSMB")) || bytes.Contains(buf[:n], []byte("\xfeSMB")) {
		return ServiceSMB
	}
	return ServiceUnknown
}

func probeMongo(host string, port int, timeout time.Duration) Service {
	conn, err := network.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return ServiceUnknown
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(500 * time.Millisecond))
	// Modern MongoDB OP_MSG {"isMaster": 1, "$db": "admin"}
	mongoPayload := []byte{
		0x37, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xdd, 0x07, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00,
		0x00, 0x10, 'i', 's', 'M', 'a', 's', 't',
		'e', 'r', 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
		'$', 'd', 'b', 0x00, 0x06, 0x00, 0x00, 0x00,
		'a', 'd', 'm', 'i', 'n', 0x00, 0x00,
	}
	if _, err := conn.Write(mongoPayload); err != nil {
		return ServiceUnknown
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 16 {
		return ServiceUnknown
	}
	if bytes.Contains(buf[:n], []byte("ismaster")) || bytes.Contains(buf[:n], []byte("isWritablePrimary")) || bytes.Contains(buf[:n], []byte("maxBsonObjectSize")) {
		return ServiceMongo
	}
	return ServiceUnknown
}
