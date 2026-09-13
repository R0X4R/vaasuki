package dispatcher

import (
	"time"

	"github.com/R0X4R/vaasuki/lib/consul"
	"github.com/R0X4R/vaasuki/lib/dockerapi"
	"github.com/R0X4R/vaasuki/lib/elastic"
	"github.com/R0X4R/vaasuki/lib/etcd"
	"github.com/R0X4R/vaasuki/lib/ftp"
	"github.com/R0X4R/vaasuki/lib/grafana"
	"github.com/R0X4R/vaasuki/lib/jenkins"
	"github.com/R0X4R/vaasuki/lib/ldap"
	"github.com/R0X4R/vaasuki/lib/memcached"
	"github.com/R0X4R/vaasuki/lib/mongo"
	"github.com/R0X4R/vaasuki/lib/prometheus"
	"github.com/R0X4R/vaasuki/lib/rabbitmq"
	"github.com/R0X4R/vaasuki/lib/redis"
	"github.com/R0X4R/vaasuki/lib/smb"
	"github.com/R0X4R/vaasuki/lib/smtp"
	"github.com/R0X4R/vaasuki/lib/telnet"
	"github.com/R0X4R/vaasuki/pkg/fingerprint"
	"github.com/R0X4R/vaasuki/pkg/model"
)

// VerifyTarget triggers targeted active security verification matching the identified or guessed service.
func VerifyTarget(svc fingerprint.Service, host string, port int, timeout time.Duration) (*model.Finding, error) {
	switch svc {
	case fingerprint.ServiceFTP:
		return ftp.Verify(host, port, timeout)

	case fingerprint.ServiceRedis:
		return redis.Verify(host, port, timeout)

	case fingerprint.ServiceMemcached:
		return memcached.Verify(host, port, timeout)

	case fingerprint.ServiceElasticsearch:
		return elastic.Verify(host, port, timeout)

	case fingerprint.ServiceDockerAPI:
		return dockerapi.Verify(host, port, timeout)

	case fingerprint.ServiceEtcd:
		return etcd.Verify(host, port, timeout)

	case fingerprint.ServiceConsul:
		return consul.Verify(host, port, timeout)

	case fingerprint.ServiceGrafana:
		return grafana.Verify(host, port, timeout)

	case fingerprint.ServiceJenkins:
		return jenkins.Verify(host, port, timeout)

	case fingerprint.ServicePrometheus:
		return prometheus.Verify(host, port, timeout)

	case fingerprint.ServiceRabbitMQ:
		return rabbitmq.Verify(host, port, timeout)

	case fingerprint.ServiceSMB:
		return smb.Verify(host, port, timeout)

	case fingerprint.ServiceMongo:
		return mongo.Verify(host, port, timeout)

	case fingerprint.ServiceLDAP:
		return ldap.Verify(host, port, timeout)

	case fingerprint.ServiceSMTP:
		return smtp.Verify(host, port, timeout)

	case fingerprint.ServiceTelnet:
		return telnet.Verify(host, port, timeout)

	case fingerprint.ServiceHTTP:
		// Check common high-impact unauthenticated HTTP APIs
		if f, _ := elastic.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := dockerapi.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := etcd.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := consul.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := grafana.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := jenkins.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := prometheus.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := rabbitmq.Verify(host, port, timeout); f != nil {
			return f, nil
		}
	}

	return nil, nil
}
