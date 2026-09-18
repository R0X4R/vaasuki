package dispatcher

import (
	"time"

		"github.com/R0X4R/vaasuki/v2/lib/cassandra"
	"github.com/R0X4R/vaasuki/v2/lib/nfs"
	"github.com/R0X4R/vaasuki/v2/lib/rmi"
	"github.com/R0X4R/vaasuki/v2/lib/tftp"
	"github.com/R0X4R/vaasuki/v2/lib/zabbix"
	"github.com/R0X4R/vaasuki/v2/lib/activemq"
	"github.com/R0X4R/vaasuki/v2/lib/actuator"
	"github.com/R0X4R/vaasuki/v2/lib/clickhouse"
	"github.com/R0X4R/vaasuki/v2/lib/consul"
	"github.com/R0X4R/vaasuki/v2/lib/couchdb"
	"github.com/R0X4R/vaasuki/v2/lib/dns"
	"github.com/R0X4R/vaasuki/v2/lib/dockerapi"
	"github.com/R0X4R/vaasuki/v2/lib/elastic"
	"github.com/R0X4R/vaasuki/v2/lib/etcd"
	"github.com/R0X4R/vaasuki/v2/lib/ftp"
	"github.com/R0X4R/vaasuki/v2/lib/grafana"
	"github.com/R0X4R/vaasuki/v2/lib/hadoop"
	"github.com/R0X4R/vaasuki/v2/lib/influxdb"
	"github.com/R0X4R/vaasuki/v2/lib/jdwp"
	"github.com/R0X4R/vaasuki/v2/lib/jenkins"
	"github.com/R0X4R/vaasuki/v2/lib/k8s"
	"github.com/R0X4R/vaasuki/v2/lib/kafka"
	"github.com/R0X4R/vaasuki/v2/lib/kibana"
	"github.com/R0X4R/vaasuki/v2/lib/kubelet"
	"github.com/R0X4R/vaasuki/v2/lib/ldap"
	"github.com/R0X4R/vaasuki/v2/lib/memcached"
	"github.com/R0X4R/vaasuki/v2/lib/mongo"
	"github.com/R0X4R/vaasuki/v2/lib/neo4j"
	"github.com/R0X4R/vaasuki/v2/lib/phpfpm"
	"github.com/R0X4R/vaasuki/v2/lib/prometheus"
	"github.com/R0X4R/vaasuki/v2/lib/rabbitmq"
	"github.com/R0X4R/vaasuki/v2/lib/redis"
	"github.com/R0X4R/vaasuki/v2/lib/registry"
	"github.com/R0X4R/vaasuki/v2/lib/rsync"
	"github.com/R0X4R/vaasuki/v2/lib/smb"
	"github.com/R0X4R/vaasuki/v2/lib/smtp"
	"github.com/R0X4R/vaasuki/v2/lib/snmp"
	"github.com/R0X4R/vaasuki/v2/lib/solr"
	"github.com/R0X4R/vaasuki/v2/lib/telnet"
	"github.com/R0X4R/vaasuki/v2/lib/vnc"
	"github.com/R0X4R/vaasuki/v2/lib/zookeeper"
	"github.com/R0X4R/vaasuki/v2/pkg/fingerprint"
	"github.com/R0X4R/vaasuki/v2/pkg/model"
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

	case fingerprint.ServiceDNS:
		return dns.Verify(host, port, timeout)

	case fingerprint.ServiceRegistry:
		return registry.Verify(host, port, timeout)

	case fingerprint.ServiceK8s:
		return k8s.Verify(host, port, timeout)

	case fingerprint.ServiceKubelet:
		return kubelet.Verify(host, port, timeout)

	case fingerprint.ServiceZooKeeper:
		return zookeeper.Verify(host, port, timeout)

	case fingerprint.ServiceActuator:
		return actuator.Verify(host, port, timeout)

	case fingerprint.ServiceSolr:
		return solr.Verify(host, port, timeout)

	case fingerprint.ServiceHadoop:
		return hadoop.Verify(host, port, timeout)

	case fingerprint.ServiceKibana:
		return kibana.Verify(host, port, timeout)

	case fingerprint.ServiceJDWP:
		return jdwp.Verify(host, port, timeout)

	case fingerprint.ServiceVNC:
		return vnc.Verify(host, port, timeout)

	case fingerprint.ServiceRsync:
		return rsync.Verify(host, port, timeout)

	case fingerprint.ServiceSNMP:
		return snmp.Verify(host, port, timeout)

	case fingerprint.ServiceCouchDB:
		return couchdb.Verify(host, port, timeout)

	case fingerprint.ServiceInfluxDB:
		return influxdb.Verify(host, port, timeout)

	case fingerprint.ServiceClickHouse:
		return clickhouse.Verify(host, port, timeout)

	case fingerprint.ServiceNeo4j:
		return neo4j.Verify(host, port, timeout)

	case fingerprint.ServicePHPFPM:
		return phpfpm.Verify(host, port, timeout)

	case fingerprint.ServiceKafka:
		return kafka.Verify(host, port, timeout)

	case fingerprint.ServiceActiveMQ:
		return activemq.Verify(host, port, timeout)

	case fingerprint.ServiceCassandra:
		return cassandra.Verify(host, port, timeout)

	case fingerprint.ServiceZabbix:
		return zabbix.Verify(host, port, timeout)

	case fingerprint.ServiceRMI:
		return rmi.Verify(host, port, timeout)

	case fingerprint.ServiceTFTP:
		return tftp.Verify(host, port, timeout)

	case fingerprint.ServiceNFS:
		return nfs.Verify(host, port, timeout)


	case fingerprint.ServiceHTTP:
		// Check common high-impact unauthenticated HTTP APIs
		if f, _ := elastic.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := dockerapi.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := registry.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := k8s.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := kubelet.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := actuator.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := solr.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := hadoop.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := kibana.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := couchdb.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := influxdb.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := clickhouse.Verify(host, port, timeout); f != nil {
			return f, nil
		}
		if f, _ := neo4j.Verify(host, port, timeout); f != nil {
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
		if f, _ := activemq.Verify(host, port, timeout); f != nil {
			return f, nil
		}
	}

	return nil, nil
}
