<p align="center">
  <h1 align="center">Vaasuki</h1>
  <p align="center">Network Service Reconnaissance & Active Verification Engine</p>
</p>

<p align="center">
  <a href="#overview">Overview</a> •
  <a href="#features">Features</a> •
  <a href="#architecture">Architecture</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#testing-lab">Testing Lab</a>
</p>

---

## Overview

Vaasuki is a high-performance network reconnaissance and service verification tool written in Go.

Most vulnerability scanners rely solely on passive banner grabbing, leading to high rates of false positives caused by backported patches and deceptive banners. Vaasuki eliminates false positives by actively executing safe, non-destructive protocol handshakes (such as anonymous FTP logins and unauthenticated Redis commands) to confirm actual exploitability before reporting findings.

## Features

* **Active Verification:** Handshakes directly with target services to verify authentication states, eliminating banner-based false positives.
* **Integrated Port Discovery:** Embeds ProjectDiscovery's Naabu v2 runner to scan open ports automatically when naked domains or CIDR blocks are provided.
* **Strict Scope Validation:** Evaluates target hosts, IPs, and CIDRs against allow and deny policies to keep operations within authorized boundaries.
* **Three-Letter Status Output:** Clean console logging using colored three-letter status tags inside plain square brackets:
  * `[INF]` (Blue): Informational updates and operational progress
  * `[WRN]` (Yellow): Target warnings and non-fatal anomalies
  * `[ERR]` (Red): Connection errors and fatal drops
  * `[HIT]` (Magenta): Discovered exposures and potential weaknesses
  * `[CNF]` (Green): Confirmed findings and verified logins
* **Colorblind Friendly:** Built-in `-b` / `--color-blind` option to disable terminal ANSI sequences cleanly.
* **Structured Output:** Emits findings to JSONL for integration into Unix pipelines and reporting tools.

## Architecture

```mermaid
graph TD
    %% Global Node Styles
    classDef input fill:#1a1c1e,stroke:#30363d,stroke-width:2px,color:#fff;
    classDef process fill:#1f242c,stroke:#ffbc00,stroke-width:2px,color:#fff;
    classDef module fill:#161b22,stroke:#58a6ff,stroke-width:2px,color:#fff;
    classDef success fill:#1b2a1a,stroke:#2ea44f,stroke-width:2px,color:#fff;
    classDef drop fill:#2a1b1b,stroke:#da3637,stroke-width:2px,color:#fff;

    IN["Target Input<br>(Domain / IP / CIDR)"]:::input
    SC["Scope Policy Check<br>(Allow / Deny CIDRs)"]:::process
    PS["Port Discovery<br>(Naabu v2 Runner)"]:::process

    subgraph VerificationModules [" Active Verification Pipeline "]
        direction TB
        FTP["FTP Module<br>(Anonymous Login Handshake)"]:::module
        RDS["Redis Module<br>(Unauthenticated PING/INFO)"]:::module
        TCP["Network Probes<br>(Context-Aware Dialers)"]:::module
    end

    SEC["Secured / Rejected<br>(Zero False Positives)"]:::drop
    CNF["[CNF] Confirmed Finding<br>(Terminal & JSONL Output)"]:::success

    IN --> SC
    SC -->|In Scope| PS
    PS -->|Port 21 / 2121| FTP
    PS -->|Port 6379 / 6380| RDS
    PS -->|Other Ports| TCP

    FTP -->|Auth Failed 530| SEC
    FTP -->|Login OK 230| CNF
    RDS -->|NOAUTH| SEC
    RDS -->|+PONG| CNF
```

## Installation

```bash
go install -v github.com/R0X4R/vaasuki@latest
```

**Build from source:**

```bash
git clone https://github.com/R0X4R/vaasuki.git
cd vaasuki
go build -o vaasuki .
```

## Usage

```bash
vaasuki -h
```

### Flags Reference

| Short Flag | Long Flag | Default | Description |
| :--- | :--- | :--- | :--- |
| **`-u`** | `--target` | `""` | Single target host, IP, or CIDR block |
| **`-l`** | `--list` | `""` | Path to file containing target hosts |
| **`-p`** | `--ports` | `""` | Ports to scan (e.g. `21,22,80,6379` or `1-1000`) |
| **`-tp`** | `--top-ports`| `""` | Top ports profile for Naabu (`100`, `1000`) |
| **`-vf`** | `--verify` | `true` | Perform safe active authentication verification |
| **`-sc`** | `--scope` | `""` | Path to scope authorization policy file |
| **`-t`** | `--threads` | `25` | Number of concurrent workers |
| **`-to`** | `--timeout` | `5` | Connection timeout in seconds |
| **`-r`** | `--rate` | `50` | Maximum connection attempts per second |
| **`-o`** | `--output` | `""` | Output file path for findings |
| **`-j`** | `--json` | `false` | Write output in JSONL format |
| **`-s`** | `--silent` | `false` | Suppress banner and informational messages |
| **`-b`** | `--color-blind`| `false` | Disable terminal color codes |
| **`-v`** | `--verbose` | `false` | Show connection diagnostics |

### Examples

**Scan a target with automated Naabu port discovery:**

```bash
vaasuki -u 192.168.1.10
```

**Scan specific ports and save confirmed findings to JSONL:**

```bash
vaasuki -u 10.0.0.5 -p 21,2121,6379,6380 -o findings.jsonl
```

**Scan a list of targets with custom rate limits:**

```bash
vaasuki -l targets.txt -t 50 -r 100 -o results.jsonl
```

## Testing Lab

Vaasuki includes a multi-container Docker Compose testbed under `lab/` that provisions both vulnerable and hardened instances of all supported services.

To start the lab:

```powershell
cd lab
docker compose up -d --build
```

To run Vaasuki against the local testbed:

```powershell
vaasuki -u 127.0.0.1 -p 2121,2122,6379,6380 -o lab_findings.jsonl
```
