# ServiceGuard Comprehensive Module Testing Lab

This directory contains a complete Docker Compose test environment covering **all services and protocols** specified in `plan.md`. It allows verifying both positive detections (misconfigured/vulnerable) and negative tests (hardened/authenticated) without touching external networks.

## Complete Services Matrix

| Category | Service | Container Name | Port (Host:Container) | State | What It Verifies |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **FTP** | FTP Anon | `serviceguard-ftp-vuln` | `2121:21` | Vulnerable | Anonymous auth allowed (`230`), file listing permitted |
| **FTP** | FTP Hardened | `serviceguard-ftp-hardened` | `2122:21` | Secured | Anonymous auth rejected (`530`), requires credentials |
| **Telnet** | Telnet Server | `serviceguard-telnet-vuln` | `2323:23` | Active | RFC option negotiation & prompt detection |
| **SMB** | Samba Guest | `serviceguard-smb-vuln` | `4445:445` | Vulnerable | Null session / unauthenticated guest share enumeration |
| **Databases**| Redis Open | `serviceguard-redis-vuln` | `6379:6379` | Vulnerable | `PING` returns `+PONG`, `INFO` responds unauthenticated |
| **Databases**| Redis Hardened | `serviceguard-redis-hardened` | `6380:6379` | Secured | `PING` returns `NOAUTH Authentication required.` |
| **Databases**| Mongo Open | `serviceguard-mongo-vuln` | `27017:27017` | Vulnerable | Unauthenticated connection and DB metadata discovery |
| **Databases**| Mongo Hardened| `serviceguard-mongo-hardened` | `27018:27017` | Secured | Requires authentication |
| **Search** | Elasticsearch | `serviceguard-elastic-vuln` | `9200:9200` | Vulnerable | Unauthenticated cluster metadata (`GET /`, `GET /_cat/indices`) |
| **Cache** | Memcached | `serviceguard-memcached-vuln` | `11211:11211` | Vulnerable | Unauthenticated `stats` and `version` execution |
| **DevOps** | Docker API Mock | `serviceguard-docker-api-vuln`| `2375:2375` | Vulnerable | Exposed unauthenticated Docker HTTP daemon (`/version`, `/_ping`) |
| **K/V Store**| etcd v3 | `serviceguard-etcd-vuln` | `2379:2379` | Vulnerable | Unauthenticated API endpoint (`/version`, key metadata) |
| **Service Mesh**| Consul Agent | `serviceguard-consul-vuln` | `8500:8500` | Vulnerable | Unauthenticated agent catalog and status endpoints |
| **Directory**| LDAP (OpenLDAP) | `serviceguard-ldap-vuln` | `3890:10389` | Vulnerable | Anonymous bind, Base DSE directory disclosure |
| **Mail** | SMTP (Mailpit) | `serviceguard-smtp-vuln` | `1025:1025` (Web: `8025`) | Controlled | Banner detection, STARTTLS, controlled non-delivery relay probe |
| **DNS** | CoreDNS | `serviceguard-dns-vuln` | `5354:53` (TCP/UDP) | Vulnerable | CHAOS version query disclosure, recursive query behavior |
| **Queues** | RabbitMQ | `serviceguard-rabbitmq-vuln` | `5672:5672`, `15672:15672` | Exposed | AMQP handshake and management web portal |
| **Metrics** | Prometheus | `serviceguard-prom-vuln` | `9090:9090` | Exposed | Unauthenticated metrics scrape interface |
| **Dashboard**| Grafana | `serviceguard-grafana-vuln` | `3000:3000` | Vulnerable | Anonymous Admin login enabled |
| **CI/CD** | Jenkins | `serviceguard-jenkins-vuln` | `8080:8080` | Exposed | Jenkins header and interface detection |
| **Web Admin**| Generic Admin | `serviceguard-http-admin` | `8088:80` | Exposed | Nginx admin landing mock |

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

### 3. Launch Only Specific Targets (Save RAM)
You can start individual service groups as needed:
```powershell
# Test only FTP and Redis
docker compose up -d ftp-vuln ftp-hardened redis-vuln redis-hardened

# Test only Telnet and Samba
docker compose up -d telnet-vuln smb-vuln
```

### 4. Verify Running Containers
```powershell
docker compose ps
```

### 5. Running the Scanner
```powershell
# Scan all lab ports locally with active verification
serviceguard scan -i 127.0.0.1 -p 2121,2122,2323,4445,6379,6380,27017,27018,9200,11211,2375,2379,8500,3890,1025,5354,5672,15672,9090,3000,8080,8088 --verify -o lab_findings.jsonl
```

### 6. Tear Down
```powershell
docker compose down -v
```
