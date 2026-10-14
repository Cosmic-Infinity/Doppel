# Doppel: AI-Augmented Hybrid Deception Honeypot System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture](https://img.shields.io/badge/Architecture-Hybrid%20Sandbox%20%2B%20LLM-purple.svg)]()
[![Web SOC](https://img.shields.io/badge/Web%20SOC-FastAPI%20%2B%20WebSockets-009688.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Real--time%20Mapping-red.svg)]()
[![GeoIP](https://img.shields.io/badge/GeoIP-MaxMind%20GeoLite2-orange.svg)]()
[![HTTP Sensor](https://img.shields.io/badge/HTTP%20Sensor-Port%208080-teal.svg)]()

**Doppel** is an intelligent, high-interaction honeypot system designed to deceive, monitor, and profile cyber adversaries in real time. By combining an **isolated Docker execution sandbox** with a **generative LLM deception layer**, Doppel achieves authentic Linux behaviour while dynamically synthesising contextual honeytokens, simulating missing penetration-testing tools, classifying attackers behaviourally, and generating real-time MITRE ATT&CK telemetry — all observable through a live Web SOC dashboard.

---

## System Architecture

```mermaid
flowchart TD
    subgraph AdversaryIngress ["Adversary Ingress"]
        Attacker["Adversary / Automated Scanner<br>(SSH Port 2222)"]
        WebProbe["Web Attacker<br>(HTTP Port 8080)"]
    end

    subgraph CoreEngine ["Doppel Core Engine"]
        SSH["AsyncSSH Daemon & PTY Session<br>(doppel.core.ssh_server)"]
        GeoIP["GeoIP Enrichment<br>(doppel.core.geoip — MaxMind mmdb)"]
        CredAnalyzer["Credential Analyzer<br>(doppel.core.credential_analyzer)"]
        Router{"Hybrid Command Router<br>(doppel.router.hybrid_router)"}
        FakeFS["Fake Filesystem<br>(doppel.core.fake_filesystem)"]
    end

    subgraph SandboxLayer ["Isolated Execution Sandbox"]
        Docker["Ephemeral Alpine Container<br>(--network none | uid 1000)"]
    end

    subgraph DeceptionLayer ["Generative Deception"]
        LLM["LLM Deception Engine<br>(Ollama / vLLM / llama.cpp)"]
        Persona["Deception Persona + Port Inventory<br>(Web Server / Cloud Worker / FinTech)"]
        HttpSensor["HTTP Honeypot Sensor<br>(doppel.http_sensor — Port 8080)"]
    end

    subgraph IntelligenceLayer ["Threat Intelligence & Analytics"]
        Observer["Async Threat Observer<br>(MITRE ATT&CK Mapping & Threat Scoring)"]
        Profiler["Attacker Behavior Profiler<br>(doppel.analytics.profiler)"]
        DB[("SQLite Telemetry DB<br>sessions · commands · phase_transitions · web_probes")]
        Report["Incident Response Report<br>(Markdown in reports/)"]
    end

    subgraph WebSOCLayer ["Web SOC & GUI Control Center"]
        Controller["Lifecycle Controller & Diagnostics Engine"]
        FastAPI["FastAPI Daemon (:8000)"]
        WS["WebSocket / SSE Broadcaster"]
        Browser["Browser UI<br>(Pre-Flight Launch Screen & Fleet Monitor)"]
    end

    Attacker <-->|"Interactive PTY Session"| SSH
    WebProbe -->|"HTTP Probes"| HttpSensor

    SSH --> GeoIP
    SSH --> CredAnalyzer
    SSH --> Router

    Router -->|"Benign / Safe-IP Commands"| Docker
    Router -->|"Sensitive / Missing Tools / Deception"| LLM
    Persona -.->|"Persona Prompt + Port Map"| LLM
    FakeFS -.->|"Session Filesystem State"| LLM
    HttpSensor -->|"LLM-Synthesized HTTP Response"| LLM

    Docker -->|"Real Container Output"| SSH
    LLM -->|"Synthesised Deceptive Output"| SSH

    SSH -.->|"Async Keystroke Stream"| Observer
    SSH -.->|"Async Keystroke Stream"| Profiler
    Observer --> DB
    Profiler --> DB
    HttpSensor --> DB
    Observer --> Report

    Controller <--> FastAPI
    DB --> FastAPI
    SSH -.->|"Live Session Telemetry"| WS
    FastAPI --> Browser
    WS --> Browser
```

---

## Hybrid Command Routing Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Adversary (SSH Client)
    participant SSH as Doppel SSH Daemon
    participant GeoIP as GeoIP + Cred Analyzer
    participant Router as Hybrid Router
    participant Docker as Docker Sandbox (--network none)
    participant LLM as LLM Deception Engine
    participant Profiler as Behavior Profiler
    participant DB as SQLite & Web SOC

    Attacker->>SSH: Connect (e.g. ssh -p 2222 ubuntu@host)
    SSH->>GeoIP: Enrich IP (country, ASN, is_datacenter)
    SSH->>GeoIP: Classify credential (risk_level, label, notes)
    SSH-->>Attacker: Authenticated + Ubuntu 22.04 LTS MOTD

    rect rgb(240, 248, 255)
    Note over Attacker,Docker: 1. Safe Command — Real Sandbox Execution
    Attacker->>SSH: Command: `whoami`
    SSH->>Router: classify_command — SANDBOX (benign_commands list)
    Router->>Docker: Execute in container as user `ubuntu`
    Docker-->>SSH: `ubuntu`
    SSH-->>Attacker: `ubuntu`
    end

    rect rgb(255, 240, 245)
    Note over Attacker,LLM: 2. Sensitive Reconnaissance / Credential Harvesting
    Attacker->>SSH: Command: `cat .env`
    SSH->>Router: Match sensitive file pattern → LLM_DECEPTION
    Router->>LLM: Synthesise contextual honeytokens (persona + FakeFS context)
    LLM-->>SSH: `APP_ENV=production\nDB_PASSWORD=...`
    SSH-->>Attacker: Plausible fake production credentials
    end

    rect rgb(245, 255, 245)
    Note over Attacker,LLM: 3. Missing Tool Simulation + Port Deception
    Attacker->>SSH: Command: `nmap -sV 10.0.4.50`
    SSH->>Router: Match missing tool regex → LLM_DECEPTION
    Router->>LLM: Synthesise nmap output using AUTHORITATIVE port inventory
    LLM-->>SSH: Port scan matching real exposed ports (22, 80, 443, 3306)
    SSH-->>Attacker: Consistent, persona-coherent Nmap output
    end

    rect rgb(245, 245, 255)
    Note over Attacker,DB: 4. Behavior Profiling & Phase Detection (async)
    SSH-)Profiler: Record command + monotonic timestamp
    Profiler->>Profiler: Classify bot/semi-automated/human (5-signal vote)
    Profiler->>Profiler: Detect kill-chain phase transition
    Profiler-)DB: update_session_profile + log_phase_transition
    Profiler-)SSH: phase_transition event → WebSocket broadcast
    end

    par Async Threat Intelligence
        SSH-)Observer: Stream command & session metadata
        Observer->>Observer: Classify MITRE ATT&CK technique & compute threat score
        Observer-)DB: Record command telemetry (SQLite)
        SSH-)DB: Broadcast terminal line to Web SOC (/ws/stream)
    end
```

---

## 🆕 What's New

### Session 1 — Safe IP Allowlist & Benign Command Passthrough

- **Safe IP allowlist** (`access.safe_ips` in `config.yaml`): any IP in the list gets a real Docker sandbox shell with all deception bypassed. The connection is still logged and alerted so you know it happened.
- **Benign command list** (`benign_commands`): ~70 common Unix commands (`ls`, `cat`, `grep`, `git`, `python3`, …) are always routed to the real sandbox instead of the LLM deception engine, making normal activity look authentic to a careful attacker.
- **Adaptive connection alerting**: `connection_made()` now logs `[SAFE IP]` or `[ALERT]` with role-appropriate context on every connection.

### Session 2 — Credential Pattern Analysis, Fake Filesystem, HTTP Sensor, Port-Scan Deception

**10 — Credential Pattern Analysis** (`doppel/core/credential_analyzer.py`)

Every SSH `validate_password()` call runs through `CredentialAnalyzer` before the attacker is admitted. Nine detection dimensions:

| Label | What it catches |
|---|---|
| `default_credential` | `admin:admin`, `pi:raspberry`, 15 device/service default pairs |
| `same_as_username` | `ubuntu:ubuntu`, `root:root` |
| `common_password` | Built-in top-200 wordlist (extend via `rockyou.txt` path) |
| `hash_pattern` | bcrypt, sha512crypt, MD5, SHA1, SHA256, NTLM in the password field |
| `leaked_credential` | `user:hash` credential-dump format |
| `credential_stuffing` | Email address as username |
| `keyboard_walk` | `qwerty`, `1q2w3e`, `123456`, etc. |
| `empty_password` | Blank field |
| `complex_password` | Long, mixed-case + special char (possible human pen-tester) |

Each analysis emits `risk_level` (`low/medium/high/critical`), `primary_label`, and a human-readable `notes` string. High/critical attempts log a `[CRED ALERT]` warning. Results are stored on `SessionState`, persisted to the DB, and broadcast in the `session_created` event.

**13 — Fake Filesystem Persistence** (`doppel/core/fake_filesystem.py`)

A `FakeFilesystem` instance lives on every `SessionState`. After every LLM-routed command, `update_from_command()` parses the shell idiom and tracks:

- Redirects (`echo "x" > /tmp/f`, `printf … > f`)
- Appends (`>>`)
- `touch`, `mkdir [-p]`, `cp`, `mv`, `rm`
- `wget -O`, `curl -o` (downloaded files)
- `chmod +x` (marks files executable)

Before every subsequent LLM call, `build_context_block()` injects the session's filesystem state into the system prompt so file operations feel persistent across turns.

**15 — HTTP Honeypot Sensor** (`doppel/http_sensor/sensor.py`)

A standalone FastAPI app starts on port 8080 alongside the SSH server. It catches all HTTP methods on all paths and classifies probes into 25 categories:

- Sensitive files: `/.env`, `/.git/config`, `wp-config.php`, `.aws/credentials`, SSH keys, backup files
- Admin panels: `/wp-admin`, `/phpmyadmin`, `/adminer`, `/jenkins`, `/grafana`
- API enumeration: `/api/v1/users`, `/api/v1/keys`, Swagger endpoints
- Path traversal, SQLi, command-injection query params

Each hit is LLM-synthesised (using the existing persona as a pseudo-shell command), logged to a `web_probes` table in SQLite, and broadcast over WebSocket/SSE with a MITRE `T1190` tag and a per-category threat score.

**16 — Port-Scan Deception** (`doppel/ai/prompts/deception_prompts.py`)

`PERSONA_PORTS` maps each persona to an authoritative port inventory injected into every LLM system prompt. `nmap`, `ss -tlnp`, `netstat -an`, and `lsof -i` output all return the same ports — matching whatever is actually exposed externally — so an attacker doing both an external scan and an internal `nmap` sees a coherent picture.

### Session 3 — GeoIP Enrichment, Attacker Classification, Kill-Chain Phase Tracking

**9 — GeoIP Enrichment** (`doppel/core/geoip.py`)

Zero-latency enrichment using local MaxMind GeoLite2 `.mmdb` files — no HTTP, no DNS, no API key. Runs synchronously inside `connection_made()` in under 1 ms. Enriches every session with:

- Country ISO code + name, city, latitude/longitude
- ASN number + org name
- `is_datacenter` — heuristic substring match against 200+ known cloud/VPS/CDN/VPN ASN org names (AWS, DigitalOcean, Vultr, Hetzner, Cloudflare, NordVPN, etc.)

Persisted to six new columns on the `sessions` table. Included in the `session_created` WebSocket event. Gracefully degrades to null fields if the `.mmdb` files are missing.

**7 — Automated vs. Human Classifier** (`doppel/analytics/profiler.py`)

`AttackerProfiler` runs a five-signal weighted vote per command:

| Signal | Bot evidence | Human evidence |
|---|---|---|
| Median inter-command gap | < 0.5 s | > 3 s |
| Timing regularity (CV) | stdev/mean < 0.15 | High variance |
| Bot-tool invocations | linpeas, nmap, hydra, sqlmap, metasploit, … | — |
| Navigation backtracking | — | ls→cd→ls, repeated pwd |
| Empty submits / Ctrl+C / backspace | — | Human hesitation signals |

Emits `attacker_type`: `bot`, `semi-automated`, `human`, or `unknown`. Confidence score 0–1. Updates live on every command and broadcasts in `command_executed` and `profile_updated` events.

**Adaptive tar-pit** — `tar_pit_delay_ms` is now a base value, not the actual delay:
- `bot` → 3× base + ±20% random jitter (wastes scanner resources; jitter defeats fingerprinting)
- `semi-automated` → 1.5×
- `human` → 0.3× (deception still feels like real I/O)

**8 — Attack Phase Tracker** (`doppel/analytics/profiler.py`)

Aggregates per-command MITRE tactics into a session-level 10-phase kill-chain:

```
Reconnaissance → Weaponization → Delivery → Exploitation →
Credential Access → Installation → C2 → Lateral Movement →
Exfiltration → Impact
```

Phase is determined first from MITRE tactic mappings (authoritative LLM output), then from command-pattern regex heuristics as fallback. Advancement is forward-only. Each forward transition fires a `phase_transition` WebSocket event with `from_phase`, `to_phase`, `phase_index`, and the triggering command, and is persisted to a new `phase_transitions` table for incident report timelines.

---

## Repository Layout

```
Doppel/
├── doppel/
│   ├── ai/                          # LLM Client, Deception Engine & Prompts
│   │   ├── deception_engine.py      # Prompt templating, FakeFS injection, output sanitiser
│   │   ├── llm_client.py            # Async OpenAI-compatible client + Mock Mode
│   │   └── prompts/
│   │       ├── deception_prompts.py # Persona prompts + PERSONA_PORTS port inventory
│   │       └── threat_prompts.py    # MITRE analysis & incident report prompts
│   ├── analytics/                   # Threat intelligence & telemetry
│   │   ├── db.py                    # Async SQLite (sessions, commands, phase_transitions, web_probes)
│   │   ├── observer.py              # Background MITRE ATT&CK tagger & threat scorer
│   │   ├── profiler.py              # Attacker type classifier + kill-chain phase tracker
│   │   └── reporter.py             # Automated Markdown incident report generator
│   ├── core/                        # Core honeypot runtime
│   │   ├── credential_analyzer.py  # SSH auth pattern classifier (9 categories)
│   │   ├── fake_filesystem.py      # Per-session in-memory filesystem for LLM context
│   │   ├── geoip.py                # Zero-latency GeoIP enrichment (MaxMind mmdb)
│   │   ├── session_manager.py      # Session lifecycle, routing, profiling, tar-pit
│   │   └── ssh_server.py           # AsyncSSH PTY daemon + GeoIP/cred hooks
│   ├── dashboard/                   # Web SOC & GUI Control Center
│   │   ├── app.py                   # FastAPI backend & WebSocket/SSE endpoints
│   │   ├── controller.py            # Honeypot daemon, HTTP sensor lifecycle, diagnostics
│   │   └── static/                  # Minimalist dark-mode UI
│   ├── http_sensor/                 # HTTP honeypot sensor
│   │   └── sensor.py               # 25-category probe classifier + LLM response synthesis
│   ├── router/
│   │   └── hybrid_router.py        # Command router: BUILTIN / SANDBOX / LLM_DECEPTION
│   ├── sandbox/
│   │   └── docker_manager.py       # Ephemeral container lifecycle & user isolation
│   ├── cli.py                       # Unified CLI entrypoint (Typer & Rich)
│   └── config.py                    # Pydantic config (GeoIPSettings, AccessSettings, …)
├── tests/                           # Pytest test suite
├── config.yaml                      # Full system configuration (see below)
├── docker-compose.yml
├── Dockerfile
├── pyproject.toml
└── requirements.txt
```

---

## Web SOC Dashboard & Pre-Flight Control Center

Doppel features a built-in, zero-CLI Web Control Center (`http://localhost:8000`):

```mermaid
flowchart LR
    subgraph Phase1 ["Phase 1: Pre-Flight Launch Screen"]
        A["Access Web SOC<br>http://localhost:8000"] --> B{"Proactive Diagnostics"}
        B --> C["Docker Status"]
        B --> D["Ollama Reachability"]
        B --> E["Port 2222 Conflict"]
        C --> F["1-Click Resolvers"]
        D --> F
        E --> F
        F -->|"Port occupied"| G["Quick Switch"]
        F -->|"Endpoint unreachable"| H["Enable Mock Mode"]
        F -->|"Model target"| I["Select Model"]
    end

    subgraph Phase2 ["Phase 2: Live Attack Fleet Operations"]
        J["▶ Launch Honeypot Listener"] --> K["Live Attack Fleet Monitor"]
        K --> L["Multi-Session Selector"]
        K --> M["Live Streaming ANSI Terminal<br>(WebSocket/SSE)"]
        K --> N["MITRE ATT&CK · Threat Score · Attacker Type · Phase"]
        K --> O["Executive Markdown Reports"]
    end

    F --> J
    B -->|"All Systems Healthy"| J
    ### Dashboard Firewall (IP Allow-List)

Restrict who can open the dashboard (HTTP, SSE, and WebSocket) by listing allowed IPs or CIDR ranges in `config.yaml`:

```yaml
access:
  dashboard_allowed_ips:
    - "127.0.0.1"
    - "::1"
    - "192.168.1.10"
    - "10.0.0.0/24"
```

- Any IP not listed receives `403 Forbidden`.
- If the list is empty, only loopback (`127.0.0.1` / `::1`) is allowed.
- This is separate from `access.safe_ips`, which controls honeypot deception bypass.
- Behind a reverse proxy, configure uvicorn's `--forwarded-allow-ips` so the real client IP is seen.
```

### Live event stream

Every WebSocket/SSE event is typed. New event types added in this iteration:

| Event | When fired | Key payload fields |
|---|---|---|
| `session_created` | Connection authenticated | `geoip`, `credential_analysis` |
| `command_executed` | Each command processed | `attacker_type`, `current_phase`, `decision` |
| `profile_updated` | After each command | Full `profile` dict incl. `median_gap_ms`, `bot_tool_hits` |
| `phase_transition` | Kill-chain advances | `from_phase`, `to_phase`, `phase_index`, `triggered_by` |
| `threat_analyzed` | MITRE tagging completes | `threat`, `threat_score` |
| `web_probe` | HTTP sensor hit | `probe_label`, `method`, `path`, `status_code` |
| `session_closed` | Session ends | `report_path` |

---

## Quick Start

### 1. Web SOC Dashboard (recommended)

```bash
git clone https://github.com/Cosmic-Infinity/Doppel.git
cd Doppel
pip install -r requirements.txt
python -m doppel.cli dashboard --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`, run diagnostics, click **▶ Launch Honeypot Listener**.

### 2. Local Interactive Simulator

```bash
python -m doppel.cli sim
```

```bash
ubuntu@prod-api-node-01:/home/ubuntu$ whoami
ubuntu
ubuntu@prod-api-node-01:/home/ubuntu$ cat .env
APP_ENV=production
DB_HOST=10.0.4.50
DB_PASSWORD=P@ssw0rdProd2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ubuntu@prod-api-node-01:/home/ubuntu$ exit
```

### 3. Remote GPU over Tailscale

```bash
# On the GPU machine
OLLAMA_HOST=0.0.0.0:11434 ollama serve
ollama pull qwen2.5-coder:7b
```

```bash
# In .env
DOPPEL_LLM_BASE_URL=http://<tailscale-ip>:11434/v1
DOPPEL_LLM_MODEL=qwen2.5-coder:7b
```

```bash
python -m doppel.cli test-model
python -m doppel.cli dashboard --port 8000
```

### 4. GeoIP setup (optional, zero-cost)

1. Register at [maxmind.com](https://www.maxmind.com/en/geolite2/signup) (free).
2. Download `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb`.
3. Set paths in `config.yaml`:

```yaml
geoip:
  city_db_path: "/opt/geoip/GeoLite2-City.mmdb"
  asn_db_path:  "/opt/geoip/GeoLite2-ASN.mmdb"
```

Doppel runs fine without the files — enrichment returns null fields with a one-time warning.

---

## Configuration (`config.yaml`)

```yaml
honeypot:
  host: "0.0.0.0"
  port: 2222
  server_banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  hostname: "prod-api-node-01"
  default_user: "ubuntu"
  accept_any_password: true
  motd: |
    Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)
    ...

llm:
  base_url: "http://127.0.0.1:11434/v1"
  model: "qwen2.5-coder:7b"
  api_key: "ollama"
  timeout_seconds: 45.0
  temperature: 0.2
  mock_mode: false

deception:
  persona: "ubuntu_web_server"   # ubuntu_web_server | cloud_worker | fintech_api
  tar_pit_delay_ms: 0            # base delay in ms; actual delay scales with attacker_type
  intercept_sensitive_files: true
  intercept_missing_tools: true
  dynamic_honeytokens: true

sandbox:
  enabled: true
  image: "alpine:latest"
  network_disabled: true
  memory_limit: "256m"
  cpu_quota: 50000

analytics:
  db_path: "doppel_telemetry.db"
  enable_mitre_tagging: true
  reports_dir: "reports"

# Safe IPs bypass all deception — get a real sandbox shell.
# Connections are still logged and alerted.
access:
  safe_ips:
    - "127.0.0.1"
    - "192.168.1.10"

# Commands always routed to the real sandbox (never LLM deception).
# Makes normal activity look authentic to a careful attacker.
benign_commands:
  - "ls"
  - "cat"
  - "grep"
  - "git"
  - "python3"
  # ... (see config.yaml for full list of ~70 commands)

# HTTP honeypot sensor — LLM-synthesised responses to web probes.
# Set to 0 to disable.
http_sensor_port: 8080

# GeoIP — local MaxMind mmdb files. Leave empty to disable.
geoip:
  city_db_path: ""   # e.g. /opt/geoip/GeoLite2-City.mmdb
  asn_db_path:  ""   # e.g. /opt/geoip/GeoLite2-ASN.mmdb
```

### Environment variable overrides

| Variable | Description | Default |
|---|---|---|
| `DOPPEL_HONEYPOT_PORT` | SSH listener port | `2222` |
| `DOPPEL_HONEYPOT_HOST` | SSH binding address | `0.0.0.0` |
| `DOPPEL_LLM_BASE_URL` | OpenAI-compatible endpoint | `http://127.0.0.1:11434/v1` |
| `DOPPEL_LLM_MODEL` | Target generative model | `qwen2.5-coder:7b` |
| `DOPPEL_LLM_TIMEOUT` | Generation timeout (s) | `45.0` |
| `DOPPEL_LLM_MOCK_MODE` | Offline mock deception | `false` |
| `DOPPEL_DECEPTION_PERSONA` | Active deception persona | `ubuntu_web_server` |
| `DOPPEL_HTTP_SENSOR_PORT` | HTTP sensor port | `8080` |
| `DOPPEL_GEOIP__CITY_DB_PATH` | Path to GeoLite2-City.mmdb | `""` |
| `DOPPEL_GEOIP__ASN_DB_PATH` | Path to GeoLite2-ASN.mmdb | `""` |

---

## Database Schema

SQLite (`doppel_telemetry.db`) — four tables:

**`sessions`** — one row per SSH or HTTP-probe session.

| Column | Description |
|---|---|
| `session_id` | UUID |
| `remote_ip`, `remote_port` | Source address |
| `username`, `password` | Credentials tried |
| `start_time`, `end_time` | ISO-8601 timestamps |
| `max_threat_score` | Highest MITRE score (0–100) |
| `country_code`, `country_name`, `city` | GeoIP |
| `asn`, `asn_org`, `is_datacenter` | ASN enrichment |
| `attacker_type` | `bot` / `semi-automated` / `human` / `unknown` |
| `type_confidence` | Classifier confidence 0–1 |
| `current_phase` | Latest kill-chain phase |
| `credential_risk` | `low` / `medium` / `high` / `critical` |
| `summary` | LLM-generated incident summary |

**`commands`** — one row per command.

| Column | Description |
|---|---|
| `session_id` | FK → sessions |
| `timestamp`, `cwd`, `command`, `output` | Command detail |
| `route_decision` | `BUILTIN` / `SANDBOX` / `LLM_DECEPTION` / `http_sensor` |
| `technique_id`, `technique_name`, `tactics` | MITRE ATT&CK |
| `threat_score` | Per-command score |
| `reasoning` | Model chain-of-thought (sanitized from attacker, visible on dashboard) |

**`phase_transitions`** — one row per forward kill-chain transition.

| Column | Description |
|---|---|
| `session_id` | FK → sessions |
| `timestamp` | When the transition occurred |
| `from_phase`, `to_phase` | Phase names |
| `phase_index` | Numeric position in kill-chain (0–9) |
| `triggered_by` | Command that caused the transition |

**`web_probes`** — one row per HTTP sensor hit.

| Column | Description |
|---|---|
| `remote_ip`, `remote_port` | Source |
| `method`, `path`, `query`, `user_agent` | Request detail |
| `probe_label` | e.g. `sensitive_file_env`, `sqli_probe` |
| `status_code`, `response_snippet` | What was returned |

---

## Testing

```bash
python -m pytest
```

Coverage areas:
- `tests/test_router.py` — safe vs. sensitive classification, benign-command passthrough, safe-IP mode.
- `tests/test_llm_client.py` — async completions, deterministic mock responses.
- `tests/test_session.py` — session lifecycle, PTY processing, background task sync, report emission.
- `tests/test_dashboard.py` — pre-flight diagnostics, quick-fixes, config endpoints.

---

## Telemetry & Reports

- **Web SOC Dashboard**: `http://localhost:8000` — live WebSocket/SSE fleet monitoring.
- **SQLite DB**: `doppel_telemetry.db` — fully queryable with any SQLite client.
- **Incident reports**: auto-generated at session close in `reports/incident_<id>_<ts>.md`.
- **Manual report generation**:
  ```bash
  python -m doppel.cli report <session_id>
  ```

---

## Roadmap

> Features are marked `[x]` when fully implemented.

- [x] **Minimalist Web SOC Dashboard & Control Center**
  - Pre-Flight diagnostics (Ollama, Docker, port), 1-click fixes, multi-session fleet monitor, live WebSocket terminal, incident report viewer.
- [x] **Safe IP Allowlist & Benign Command Passthrough**
  - Trusted IPs bypass deception and receive a real sandbox shell. Benign commands always route to Docker.
- [x] **Credential Pattern Analysis**
  - Nine-category classifier (`default_credential`, `hash_pattern`, `leaked_credential`, `credential_stuffing`, …) with risk scoring on every SSH auth attempt.
- [x] **Fake Filesystem Persistence**
  - Per-session in-memory filesystem injected into LLM context so file operations remain consistent across turns.
- [x] **HTTP Honeypot Sensor (Port 8080)**
  - 25-category web-probe classifier; LLM-synthesised responses; logged to `web_probes` table; broadcast over WebSocket.
- [x] **Port-Scan Deception**
  - `PERSONA_PORTS` inventory injected into every LLM prompt — `nmap`, `ss`, `netstat` output matches real exposed ports.
- [x] **GeoIP Enrichment**
  - Zero-latency MaxMind mmdb enrichment at connection time. Country, city, ASN, datacenter detection. Persisted to DB.
- [x] **Automated vs. Human Operator Classifier**
  - Five-signal weighted vote: timing cadence, regularity, bot-tool hits, navigation backtracking, hesitation signals.
- [x] **Adaptive Tar-Pit**
  - `tar_pit_delay_ms` is now a base value; actual delay is 3× for bots, 0.3× for humans, with ±20% jitter.
- [x] **Attack Phase Tracker (Kill-Chain)**
  - 10-phase kill-chain; forward-only; fires `phase_transition` events; persisted to `phase_transitions` table.
- [ ] **Canarytoken Integration**
  - Inject real Canarytokens (AWS keys, DNS tokens) into honeytoken files for out-of-band attribution when exfiltrated credentials are used on the public internet.
- [ ] **Honeytoken Coherence Store**
  - Per-session cache of previously synthesised credentials (DB passwords, IPs, filenames) re-injected into every subsequent LLM prompt for cross-turn consistency.
- [ ] **LLM Output Sanitiser**
  - Post-process LLM output for AI self-disclosure phrases ("As an AI…"); replace with `command not found` fallback.
- [ ] **Streaming LLM Output**
  - Stream LLM responses token-by-token so long commands (`find /`, `linpeas`) appear to print progressively.
- [ ] **Webhook Alerts**
  - POST to Slack/Discord/PagerDuty when session threat score crosses a configurable threshold.
- [ ] **Session Replay**
  - Dashboard endpoint to replay a closed session with correct inter-command timing.
- [ ] **Cross-Session Attacker Correlation**
  - Link sessions by IP, credential pattern, or command playbook fingerprint into `campaign_id` groups.