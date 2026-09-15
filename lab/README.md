# Vaasuki Comprehensive Module Testing Lab

This directory contains a complete Docker Compose test environment covering **all services and protocols** specified in `plan.md`. It allows verifying both positive detections (misconfigured/vulnerable) and negative tests (hardened/authenticated) without touching external networks.

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
vaasuki -u 127.0.0.1 -p 1025,2121,2122,2323,2375,2379,3000,3890,4445,5354,6379,6380,8080,8088,8500,9090,9200,11211,15672,27017,27018 -vf -o lab_findings.jsonl
```

### 6. Tear Down
```powershell
docker compose down -v
```
