// Package lib provides protocol-specific reconnaissance and active vulnerability verification modules.
//
// Supported protocols and services:
//   - Consul: HashiCorp Consul unauthenticated HTTP API (/v1/status/leader, /v1/agent/self)
//   - DNS: DNS CHAOS TXT queries (version.bind, id.server)
//   - DockerAPI: Exposed unauthenticated Docker Remote Engine REST API (/version, /info)
//   - Elastic: Elasticsearch cluster unauthenticated inspection (/, /_cat/indices)
//   - Etcd: Unauthenticated etcd key-value store (/version, /v2/keys, /v3/kv/range)
//   - FTP: Anonymous FTP login verification and directory listing (USER anonymous)
//   - Grafana: Unauthenticated access and anonymous organization API (/api/org)
//   - Jenkins: Unauthenticated CI/CD server, crumb issuer, and job metadata exposure
//   - LDAP: Anonymous LDAP v3 bind and root DSE queries
//   - Memcached: Unauthenticated Memcached text protocol (stats, version)
//   - Mongo: MongoDB unauthenticated wire-protocol queries (isMaster / hello)
//   - Prometheus: Unauthenticated metrics and runtime configuration (/api/v1/status/config)
//   - RabbitMQ: Management HTTP API default guest credentials and anonymous access
//   - Redis: Unauthenticated Redis database commands (PING -> +PONG)
//   - SMB: SMBv1 and SMBv2 dialect negotiation and null session verification
//   - SMTP: Unauthenticated mail transfer agent banner and VRFY/EXPN/NOOP checks
//   - Telnet: Cleartext Telnet service negotiation and unauthenticated command prompt detection
package lib
