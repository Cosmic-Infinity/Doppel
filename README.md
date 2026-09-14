# 🍯 Doppel: AI-Augmented Hybrid Deception Honeypot System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture](https://img.shields.io/badge/Architecture-Hybrid%20Sandbox%20%2B%20LLM-purple.svg)]()
[![Web SOC](https://img.shields.io/badge/Web%20SOC-FastAPI%20%2B%20WebSockets-009688.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Real--time%20Mapping-red.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Doppel** is an intelligent, high-interaction honeypot system designed to deceive, monitor, and profile cyber adversaries in real time. By combining an **isolated Docker execution sandbox** with a **generative LLM deception layer**, Doppel achieves authentic Linux behavior while dynamically synthesizing contextual honeytokens, simulating missing penetration testing tools, and generating real-time MITRE ATT&CK telemetry.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph AdversaryIngress ["Adversary Ingress"]
        Attacker["Adversary / Automated Scanner<br>(SSH Port 2222)"]
    end

    subgraph CoreEngine ["Doppel Core Engine"]
        SSH["AsyncSSH Daemon & PTY Session<br>(doppel.core.ssh_server)"]
        Router{"Hybrid Command Router<br>(doppel.router.hybrid_router)"}
    end

    subgraph SandboxLayer ["Isolated Execution Sandbox"]
        Docker["Ephemeral Alpine Container<br>(--network none | uid 1000)"]
    end

    subgraph DeceptionLayer ["Generative Deception (GPU via Tailscale)"]
        LLM["LLM Deception Engine<br>(Ollama / vLLM / llama.cpp)"]
        Persona["Deception Persona Context<br>(Web Server / Cloud Worker / FinTech)"]
    end

    subgraph IntelligenceLayer ["Threat Intelligence & Analytics"]
        Observer["Async Threat Observer<br>(MITRE ATT&CK Mapping & Threat Scoring)"]
        DB[("SQLite Telemetry DB<br>doppel_telemetry.db")]
        Report["Incident Response Report<br>(Markdown in reports/)"]
    end

    subgraph WebSOCLayer ["Web SOC & GUI Control Center"]
        Controller["Lifecycle Controller & Diagnostics Engine"]
        FastAPI["FastAPI Daemon (:8000)"]
        WS["WebSocket Broadcaster (/ws/stream)"]
        Browser["Browser UI<br>(Pre-Flight Launch Screen & Fleet Monitor)"]
    end

    Attacker <-->|"Interactive PTY Session"| SSH
    SSH --> Router

    Router -->|"Safe Linux Commands<br>(ls, whoami, pwd, id)"| Docker
    Router -->|"Sensitive Reads / Missing Tools / Pipelines<br>(cat .env, /etc/shadow, nmap, linpeas)"| LLM
    Persona -.->|"Persona Prompt"| LLM

    Docker -->|"Real Container Output"| SSH
    LLM -->|"Synthesized Deceptive Output"| SSH

    SSH -.->|"Async Keystroke Stream"| Observer
    Observer --> DB
    Observer --> Report

    Controller <--> FastAPI
    DB --> FastAPI
    SSH -.->|"Live Session Telemetry"| WS
    FastAPI --> Browser
    WS --> Browser
```

---

## ⚡ Hybrid Command Routing Sequence

The following diagram illustrates how Doppel transparently routes attacker input between the real isolated container and the generative AI deception engine:

```mermaid
sequenceDiagram
    autonumber
    actor Attacker as Adversary (SSH Client)
    participant SSH as Doppel SSH Daemon
    participant Router as Hybrid Router
    participant Docker as Docker Sandbox (--network none)
    participant LLM as LLM Deception Engine
    participant Observer as Threat Observer
    participant DB as SQLite & Web SOC

    Attacker->>SSH: Connect (e.g. ssh -p 2222 ubuntu@host)
    SSH-->>Attacker: Authenticated + Ubuntu 22.04 LTS MOTD

    rect rgb(240, 248, 255)
    Note over Attacker,Docker: 1. Safe Command Execution (Standard Utilities)
    Attacker->>SSH: Command: `whoami`
    SSH->>Router: Route `whoami`
    Router->>Docker: Execute in container as user `ubuntu`
    Docker-->>SSH: `ubuntu`
    SSH-->>Attacker: `ubuntu`
    end

    rect rgb(255, 240, 245)
    Note over Attacker,LLM: 2. Sensitive Reconnaissance / Credential Harvesting
    Attacker->>SSH: Command: `cat .env`
    SSH->>Router: Match sensitive file pattern (`.env`)
    Router->>LLM: Synthesize contextual honeytokens (persona context)
    LLM-->>SSH: `APP_ENV=production\nDB_PASSWORD=...`
    SSH-->>Attacker: Plausible fake production credentials
    end

    rect rgb(245, 255, 245)
    Note over Attacker,LLM: 3. Missing Penetration Testing Tool Simulation
    Attacker->>SSH: Command: `nmap -sV 10.0.4.50`
    SSH->>Router: Match missing tool regex (`nmap`)
    Router->>LLM: Hallucinate authentic tool banner and scan results
    LLM-->>SSH: Synthesized Nmap scan output
    SSH-->>Attacker: Plausible Nmap port scan output
    end

    par Async Threat Intelligence
        SSH-)Observer: Stream command & session metadata
        Observer->>Observer: Classify MITRE ATT&CK technique & compute threat score
        Observer-)DB: Record command telemetry (SQLite)
        SSH-)DB: Broadcast terminal line to Web SOC WebSocket (/ws/stream)
    end
```

---

## 🖥️ Web SOC Dashboard & Pre-Flight Control Center

Doppel features a built-in, zero-CLI Web Control Center (`http://localhost:8000`) designed with a clean, minimalist aesthetic and two operational phases:

```mermaid
flowchart LR
    subgraph Phase1 ["Phase 1: Pre-Flight Launch Screen"]
        A["Access Web SOC<br>http://localhost:8000"] --> B{"Proactive Diagnostics"}
        B --> C["Docker Status<br>(Daemon running / image cached)"]
        B --> D["Ollama Reachability<br>(Remote GPU / installed models)"]
        B --> E["Port 2222 Conflict<br>(Socket availability test)"]
        
        C --> F["1-Click Resolvers"]
        D --> F
        E --> F

        F -->|"Port occupied"| G["Quick Switch<br>(e.g. 2222 -> 22222)"]
        F -->|"Endpoint unreachable"| H["Enable Mock Mode<br>(Zero-GPU fallback)"]
        F -->|"Model target"| I["Select Model<br>(From scraped local models)"]
    end

    subgraph Phase2 ["Phase 2: Live Attack Fleet Operations"]
        J["▶ Launch Honeypot Listener"] --> K["Live Attack Fleet Monitor"]
        K --> L["Interactive Multi-Session Selector"]
        K --> M["Live Streaming ANSI Terminal<br>(WebSocket)"]
        K --> N["MITRE ATT&CK & Threat Telemetry"]
        K --> O["Executive Markdown Reports"]
    end

    F --> J
    B -->|"All Systems Healthy"| J
```

### Key Capabilities:
1. **Pre-Flight Environment Diagnostics**:
   - Automatically probes Docker Desktop availability and Alpine base image readiness.
   - Tests Ollama / remote GPU reachability and scrapes available local models.
   - Verifies whether SSH Port 2222 (or custom port) is free or in conflict.
2. **1-Click Proactive Fixes**:
   - **Quick Port Switch**: Rebinds to an alternative port (e.g. `22222`) if `2222` is occupied.
   - **Offline Mock Mode**: Allows instant local testing without an active GPU/LLM.
   - **Model Selector**: Picks from all models discovered on the active Ollama instance.
3. **Plain-English `ⓘ` Tooltips**:
   - Explains technical concepts like *"Mock Mode"*, *"Docker Sandbox"*, *"Port Conflict"*, and *"Deception Persona"* so any operator or reviewer can understand without prior setup knowledge.
4. **Live Multi-Session Attack Fleet Monitor**:
   - Real-time fleet cards with threat score pills (`0–100`), MITRE tactic tags, command counts, and duration.
   - Live WebSocket-driven terminal playback streaming raw attacker sessions with route indicators (`[DOCKER]` vs `[LLM]`).
   - In-browser incident report viewer.

---

## 📁 Repository Layout

```
Doppel/
├── doppel/
│   ├── ai/                      # LLM Client, Deception Engine & Prompts
│   │   ├── deception_engine.py  # Prompt templating & terminal output sanitizer
│   │   ├── llm_client.py        # Async OpenAI-compatible client + Mock Mode
│   │   └── prompts/             # System prompts for bash emulation & personas
│   ├── analytics/               # Threat intelligence & telemetry
│   │   ├── db.py                # Async SQLite persistence (aiosqlite)
│   │   ├── observer.py          # Background MITRE ATT&CK tagger & threat scorer
│   │   └── reporter.py          # Automated Markdown incident report generator
│   ├── core/                    # Core honeypot runtime
│   │   ├── session_manager.py   # Ephemeral session lifecycle & event dispatch
│   │   └── ssh_server.py        # AsyncSSH PTY server daemon (CRLF-safe)
│   ├── dashboard/               # Web SOC & GUI Control Center
│   │   ├── app.py               # FastAPI backend & WebSocket endpoints
│   │   ├── controller.py        # Background honeypot daemon & diagnostic engine
│   │   └── static/              # Minimalist dark-mode UI (HTML, CSS, JS)
│   ├── router/                  # Command classification engine
│   │   └── hybrid_router.py     # Regex matching for safe vs. deceptive routes
│   ├── sandbox/                 # Container sandbox management
│   │   └── docker_manager.py    # Ephemeral container lifecycle & user isolation
│   ├── cli.py                   # Unified CLI entrypoint (Typer & Rich)
│   └── config.py                # Pydantic configuration loader
├── tests/                       # Pytest test suite (12 tests)
├── config.yaml                  # System configuration
├── docker-compose.yml           # Containerized honeypot deployment
├── Dockerfile                   # Doppel production container image
├── pyproject.toml               # Python packaging & dependencies
└── requirements.txt             # Pip dependency list
```

---

## 🚀 Quick Start

### 1. Launch the Web SOC Dashboard & Control Center (Recommended)

The easiest way to configure and run Doppel without manual CLI parameters:

```bash
# Clone the repository
git clone https://github.com/Cosmic-Infinity/Doppel.git
cd Doppel

# Install dependencies
pip install -r requirements.txt

# Start the Web Control Center (accessible locally or over Tailscale)
python -m doppel.cli dashboard --host 0.0.0.0 --port 8000
```

1. Open **`http://localhost:8000`** (or your Tailscale IP `http://<tailscale-ip>:8000`).
2. Review the **Pre-Flight Diagnostics** (checks Ollama, Docker, and Port 2222).
3. Apply any 1-click suggestions (e.g., switch port or enable Mock Mode if offline).
4. Click **▶ Launch Honeypot Listener** to start!

---

### 2. Local Interactive Simulator (CLI Testing without SSH)

Test Doppel's routing, deception engine, and report generation in your local terminal without an SSH client:

```bash
python -m doppel.cli sim
```

Inside the simulator:
```bash
ubuntu@prod-api-node-01:/home/ubuntu$ whoami
ubuntu
ubuntu@prod-api-node-01:/home/ubuntu$ cat .env
APP_ENV=production
DB_HOST=10.0.4.50
DB_DATABASE=app_production
DB_PASSWORD=P@ssw0rdProd2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

ubuntu@prod-api-node-01:/home/ubuntu$ exit
```

---

### 3. Deploying with a Remote GPU over Tailscale

#### Step A: Start Ollama on the remote machine
```bash
# On Linux:
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# On Windows (PowerShell):
# $env:OLLAMA_HOST="0.0.0.0:11434"; ollama serve
```

Pull your preferred model (fits comfortably in 12GB VRAM):
```bash
ollama pull qwen2.5-coder:7b
# or: ollama pull llama3.1:8b
```

#### Step B: Configure Doppel
Copy `.env.example` to `.env` and set your remote Tailscale IP:
```bash
cp .env.example .env
```
Edit `.env`:
```ini
DOPPEL_LLM_BASE_URL=http://127.0.0.1:11434/v1
DOPPEL_LLM_MODEL=qwen2.5-coder:7b
DOPPEL_LLM_TIMEOUT=45.0
DOPPEL_LLM_MOCK_MODE=false
```

#### Step C: Test Model Connectivity
```bash
python -m doppel.cli test-model
```

#### Step D: Launch the Honeypot
```bash
# Option 1: Via the Web Control Center (Recommended)
python -m doppel.cli dashboard --port 8000

# Option 2: Directly via CLI
python -m doppel.cli run --verbose

# Option 3: Using Docker Compose
docker compose up -d
```

---

## ⚙️ Configuration (`config.yaml`)

```yaml
# Doppel Configuration File
honeypot:
  host: "0.0.0.0"
  port: 2222
  server_banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  hostname: "prod-api-node-01"
  default_user: "ubuntu"
  accept_any_password: true
  motd: |
    Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)
     * Documentation:  https://help.ubuntu.com
     * Management:     https://landscape.canonical.com
     * Support:        https://ubuntu.com/pro

    System information as of current session:
      System load:  0.18               Processes:             112
      Usage of /:   34.2% of 48.29GB   Users logged in:       1
      Memory usage: 28%                IPv4 address for eth0: 10.0.4.15

    0 updates can be applied immediately.

llm:
  # Remote or local endpoint (e.g. over Tailscale: http://100.x.y.z:11434/v1)
  base_url: "http://127.0.0.1:11434/v1"
  model: "qwen2.5-coder:7b"
  api_key: "ollama"
  timeout_seconds: 45.0
  temperature: 0.2
  mock_mode: false

deception:
  persona: "ubuntu_web_server" # ubuntu_web_server | cloud_worker | fintech_api
  tar_pit_delay_ms: 0
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
```

### Environment Variable Overrides

All options in `config.yaml` can be overridden via `.env`:

| Environment Variable | Description | Default |
|---|---|---|
| `DOPPEL_HONEYPOT_PORT` | SSH listener port | `2222` |
| `DOPPEL_HONEYPOT_HOST` | SSH binding address | `0.0.0.0` |
| `DOPPEL_LLM_BASE_URL` | OpenAI-compatible endpoint URL | `http://127.0.0.1:11434/v1` |
| `DOPPEL_LLM_MODEL` | Target generative model | `qwen2.5-coder:7b` |
| `DOPPEL_LLM_TIMEOUT` | Generation timeout in seconds | `45.0` |
| `DOPPEL_LLM_MOCK_MODE` | Enable offline mock deception | `false` |
| `DOPPEL_DECEPTION_PERSONA` | Active deception persona | `ubuntu_web_server` |

---

## 🧪 Testing

Doppel includes an automated test suite covering routing logic, mock LLM generation, PTY session lifecycle, and dashboard diagnostics:

```bash
python -m pytest
```

Test coverage includes:
- `tests/test_router.py`: Safe vs. sensitive command classification, credential harvesting regex, and absent tool matching.
- `tests/test_llm_client.py`: Async HTTP completions and deterministic offline mock responses.
- `tests/test_session.py`: Session lifecycle, PTY command processing, background task synchronization, and report emission.
- `tests/test_dashboard.py`: Pre-flight diagnostics engine, 1-click quick-fixes, status lifecycle, and configuration endpoints.

---

## 📊 Telemetry & Reports

- **Web SOC Dashboard**: Live WebSocket session streaming and multi-instance fleet monitoring at `http://localhost:8000`.
- **Database**: Recorded in SQLite (`doppel_telemetry.db`) using `aiosqlite`.
- **Automated Reports**: Generated on session close in `reports/incident_<session_id>_<timestamp>.md`.
- **Manual Report Generation**:
  ```bash
  python -m doppel.cli report <session_id>
  ```

---

## 🗺️ Roadmap & Feature Suggestions

> **Agent Instruction**: Keep this roadmap updated whenever features are initiated, modified, or completed. Mark completed features with `[x]` and add brief operational notes.

- [x] **Minimalist Web SOC Dashboard & Control Center**
  - Fully implemented with dedicated Pre-Flight Launch Screen, live diagnostics (Ollama, Docker, Port), 1-click issue resolution, plain-English `ⓘ` tooltips, multi-instance attack fleet monitor, and live streaming terminal.
- [ ] **Active AI Tar-Pit & Decoy Breadcrumbs**
  - Dynamic latency scaling based on attacker threat score to exhaust attacker resources.
  - Contextual decoy breadcrumbs (fake internal subnets, mock Git repositories, decoy backup archives).
- [ ] **Canarytoken Integration (Real-World Attribution & Tracking)**
  - Dynamic injection of verifiable Canarytokens (AWS API keys, DNS tokens, webhooks) into honeytoken files.
  - External alerts when exfiltrated credentials are tested on the public internet.
- [ ] **Multi-Protocol Deception / Web Sensor (Port 80/8080)**
  - HTTP honeypot simulating internal administrative panels and REST APIs.
  - LLM-synthesized responses to web exploit probes (SQLi, path traversal, unauthenticated endpoints).
- [ ] **Automated Adversary Profiling**
  - Behavioral classification distinguishing automated mass-scanners, brute-force bots, and interactive human operators.

