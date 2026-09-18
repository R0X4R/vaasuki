# Vaasuki Comprehensive Module Testing Lab

This directory contains a complete Docker Compose test environment covering **all services and protocols** across core modules and v2.7.0 additions. It allows verifying positive detections (misconfigured/unauthenticated) and negative tests (hardened/authenticated) without touching external networks.

## Complete Services Matrix

| Category | Service | Container Name | Port (Host:Container) | State | What It Verifies |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FTP** | FTP Anon | `vaasuki-ftp-vuln` | `2121:21` | Vulnerable | Anonymous auth allowed (`230`), file listing permitted |
| **FTP** | FTP Hardened | `vaasuki-ftp-hardened` | `2122:21` | Secured | Anonymous auth rejected (`530`), requires credentials |
| **Telnet** | Telnet Server | `vaasuki-telnet-vuln` | `2323:23` | Active | RFC option negotiation & prompt detection |
| **SMB** | Samba Guest | `vaasuki-smb-vuln` | `4445:445` | Vulnerable | Null session / unauthenticated guest share enumeration |
| **Databases**| Redis Open | `vaasuki-redis-vuln` | `6379:6379` | Vulnerable | `PING` returns `+PONG`, `INFO` responds unauthenticated |
| **Databases**| Redis Hardened | `vaasuki-redis-hardened` | `6380:6379` | Secured | `PING` returns `NOAUTH Authentication required.` |
| **Databases**| Mongo Open | `vaasuki-mongo-vuln` | `27017:27017` | Vulnerable | Unauthenticated connection and DB metadata discovery |
| **Databases**| Mongo Hardened| `vaasuki-mongo-hardened` | `27018:27017` | Secured | Requires authentication |
| **Search** | Elasticsearch | `vaasuki-elastic-vuln` | `9200:9200` | Vulnerable | Unauthenticated cluster metadata (`GET /`, `GET /_cat/indices`) |
| **Cache** | Memcached | `vaasuki-memcached-vuln` | `11211:11211` | Vulnerable | Unauthenticated `stats` and `version` execution |
| **DevOps** | Docker API Mock | `vaasuki-docker-api-vuln`| `2375:2375` | Vulnerable | Exposed unauthenticated Docker HTTP daemon (`/version`, `/_ping`) |
| **K/V Store**| etcd v3 | `vaasuki-etcd-vuln` | `2379:2379` | Vulnerable | Unauthenticated API endpoint (`/version`, key metadata) |
| **Service Mesh**| Consul Agent | `vaasuki-consul-vuln` | `8500:8500` | Vulnerable | Unauthenticated agent catalog and status endpoints |
| **Directory**| LDAP (OpenLDAP) | `vaasuki-ldap-vuln` | `3890:10389` | Vulnerable | Anonymous bind, Base DSE directory disclosure |
| **Mail** | SMTP (Mailpit) | `vaasuki-smtp-vuln` | `1025:1025` (Web: `8025`) | Controlled | Banner detection, STARTTLS, controlled non-delivery relay probe |
| **DNS** | CoreDNS | `vaasuki-dns-vuln` | `5354:53` (TCP/UDP) | Vulnerable | CHAOS version query disclosure, recursive query behavior |
| **Queues** | RabbitMQ | `vaasuki-rabbitmq-vuln` | `5672:5672`, `15672:15672` | Exposed | AMQP handshake and management web portal |
| **Metrics** | Prometheus | `vaasuki-prom-vuln` | `9090:9090` | Exposed | Unauthenticated metrics scrape interface |
| **Dashboard**| Grafana | `vaasuki-grafana-vuln` | `3000:3000` | Vulnerable | Anonymous Admin login enabled |
| **CI/CD** | Jenkins | `vaasuki-jenkins-vuln` | `8080:8080` | Exposed | Jenkins header and interface detection |
| **Web Admin**| Generic Admin | `vaasuki-http-admin` | `8088:80` | Exposed | Nginx admin landing mock |
| **Orchestration** | K8s API Server | `vaasuki-k8s-api-vuln` | `6443:6443`, `8443:8443` | Vulnerable | `/version`, unauthenticated `/api/v1/namespaces`, `/api/v1/pods` |
| **Orchestration** | Kubelet API | `vaasuki-kubelet-vuln` | `10250:10250`, `10255:10255` | Vulnerable | Unauthenticated `/pods` and `/stats/summary` disclosure |
| **Containers** | Docker Registry | `vaasuki-registry-vuln` | `5000:5000` | Vulnerable | Unauthenticated `/v2/` API and `_catalog` enumeration |
| **Coordination** | ZooKeeper | `vaasuki-zookeeper-vuln`| `2181:2181` | Vulnerable | 4LW commands (`envi`, `stat`, `isro`, `wchp`) permitted |
| **Streaming** | Apache Kafka | `vaasuki-kafka-vuln` | `9092:9092` | Vulnerable | Unauthenticated wire protocol metadata probe |
| **Queues** | ActiveMQ | `vaasuki-activemq-vuln` | `8161:8161`, `61616:61616`| Vulnerable | Web console and OpenWire port banner exposure |
| **Databases** | CouchDB | `vaasuki-couchdb-vuln` | `5984:5984` | Vulnerable | Unauthenticated DB listing `/_all_dbs` |
| **Databases** | InfluxDB | `vaasuki-influxdb-vuln` | `8086:8086` | Vulnerable | `/query?q=SHOW DATABASES` unauthenticated query |
| **Databases** | Neo4j | `vaasuki-neo4j-vuln` | `7474:7474`, `7687:7687` | Vulnerable | HTTP `authDisabled: true`, unauth Bolt handshake |
| **Databases** | ClickHouse | `vaasuki-clickhouse-vuln`| `8123:8123`, `9001:9000`| Vulnerable | HTTP query endpoint (`SELECT 1`) without auth |
| **Storage** | Hadoop WebHDFS | `vaasuki-hadoop-vuln` | `9870:9870` | Vulnerable | `/webhdfs/v1/?op=LISTSTATUS` directory listing |
| **Search** | Apache Solr | `vaasuki-solr-vuln` | `8983:8983` | Vulnerable | Unauthenticated core status `/solr/admin/cores` |
| **Monitoring** | Kibana | `vaasuki-kibana-vuln` | `5601:5601` | Vulnerable | Unauthenticated `/api/status` endpoint |
| **Frameworks** | Spring Actuator | `vaasuki-actuator-vuln`| `8081:8080` | Vulnerable | `/actuator/env`, `/actuator/mappings`, `/actuator/heapdump` |
| **FastCGI** | PHP-FPM | `vaasuki-php-fpm-vuln` | `9000:9000` | Vulnerable | Raw FastCGI port listening without reverse proxy |
| **Debug** | JDWP | `vaasuki-jdwp-vuln` | `8000:8000` | Vulnerable | Java Debug Wire Protocol `JDWP-Handshake` responder |
| **Remote Desktop**| VNC | `vaasuki-vnc-vuln` | `5900:5900` | Vulnerable | RFB 003.008 with Security Type 1 (None) |
| **File Sync** | rsync | `vaasuki-rsync-vuln` | `873:873` | Vulnerable | Anonymous `@RSYNCD` module listing permitted |
| **Management** | SNMP | `vaasuki-snmp-vuln` | `161:161/udp` | Vulnerable | UDP community string `public` accepted |

---

## Operating Instructions

### 1. Prerequisites
- Start **Docker Desktop** on Windows.
- Ensure PowerShell or Command Prompt has access to `docker` and `docker compose`.

### 2. Launch All Test Containers
```powershell
cd e:\service-exploit\lab
docker compose up -d --build
```

### 3. Launch Grouped Targets (Save RAM)
You can start individual service groups as needed:

#### Container & Orchestration
```powershell
docker compose up -d k8s-api-vuln kubelet-vuln registry-vuln
```

#### Message Queues & Streaming
```powershell
docker compose up -d zookeeper-vuln kafka-vuln activemq-vuln
```

#### Databases & Analytics
```powershell
docker compose up -d couchdb-vuln influxdb-vuln neo4j-vuln clickhouse-vuln
```

#### Monitoring, Search & Frameworks
```powershell
docker compose up -d solr-vuln kibana-vuln hadoop-vuln actuator-vuln
```

#### Debug & Remote Protocols
```powershell
docker compose up -d jdwp-vuln vnc-vuln rsync-vuln php-fpm-vuln snmp-vuln
```

### 4. Verify Running Containers
```powershell
docker compose ps
```

### 5. Running the Scanner
```powershell
# Scan all standard lab ports locally
vaasuki -u 127.0.0.1 -p 161,873,1025,2121,2122,2181,2323,2375,2379,3000,3890,4445,5000,5354,5601,5900,6379,6380,6443,7474,8000,8080,8081,8086,8088,8123,8161,8443,8500,8983,9000,9090,9092,9200,9870,10250,10255,11211,15672,27017,27018 -vf -o lab_findings.jsonl
```

### 6. Tear Down
```powershell
docker compose down -v
```
