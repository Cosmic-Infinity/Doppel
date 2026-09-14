# 🍯 Doppel: AI-Augmented Hybrid Deception Honeypot System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Architecture](https://img.shields.io/badge/Architecture-Hybrid%20Sandbox%20%2B%20LLM-purple.svg)]()
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-Real--time%20Mapping-red.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Doppel** is an intelligent, high-interaction honeypot system designed to deceive, monitor, and profile cyber adversaries in real time. By combining an **isolated Docker execution sandbox** with a **generative LLM deception layer**, Doppel achieves authentic Linux behavior while dynamically synthesizing contextual honeytokens, simulating missing penetration testing tools, and generating real-time MITRE ATT&CK telemetry.

---

## 🏛️ Architecture Overview

```
                      +---------------------------------------+
                      | Attacker / Scanner via SSH (Port 2222) |
                      +---------------------------------------+
                                          |
                                          v
                      +---------------------------------------+
                      |     Doppel SSH Server & Session Mgr   |
                      +---------------------------------------+
                                          |
                                          v
                              [ Hybrid Command Router ]
                             /                         \
           (Safe standard commands)              (Sensitive reads / tools / downloads)
                           v                             v
           +-----------------------------+     +-------------------------------+
           |   Isolated Docker Sandbox   |     |     LLM Deception Engine      |
           |     (--network none)        |     | (Remote A2000 GPU via Tailscale)
           +-----------------------------+     +-------------------------------+
                                         \     /
                                          v   v
                             [ Shell Output to Attacker ]
                                          |
                                (Async Command Stream)
                                          v
                      +---------------------------------------+
                      |     LLM Threat Observer (MITRE)       |
                      +---------------------------------------+
                                   |              |
                                   v              v
                        [ SQLite Telemetry ] [ Executive Incident Report ]
```

### Key Components

1. **Hybrid Shell Router**:
   - **Safe utilities** (`ls`, `whoami`, `id`, `pwd`, `date`) execute inside an isolated ephemeral Docker container (`--network none`).
   - **Sensitive reconnaissance** (`cat /etc/shadow`, `cat .env`, `cat ~/.aws/credentials`, `grep -i password`) are intercepted by the LLM, returning dynamic, plausible honeytokens tailored to the active persona.
   - **Penetration tools** (`nmap`, `linpeas.sh`, `sqlmap`) that are absent from minimal containers are hallucinated by the LLM, keeping the attacker engaged rather than tipping them off with `command not found`.

2. **Model Agnostic Inference (Remote GPU via Tailscale)**:
   - Communicates with standard OpenAI-compatible endpoints (`/v1/chat/completions`).
   - Works seamlessly with **Ollama**, **vLLM**, or **llama.cpp** running on your remote lab system (e.g., NVIDIA RTX A2000 12GB).
   - Hot-swap models (`qwen2.5-coder:7b`, `llama3.1:8b`, `mistral-nemo:12b`, `deepseek-r1:8b`) via environment variables or `config.yaml`.

3. **Continuous Threat Intelligence & MITRE Tagging**:
   - Asynchronous co-process maps every command to MITRE ATT&CK tactics & techniques (e.g., `T1087 Account Discovery`, `T1552 Unsecured Credentials`).
   - Computes dynamic threat scores (0–100) and detects automated botnets vs. interactive human adversaries.

4. **Automated Incident Response Reporting**:
   - On session disconnect, Doppel generates a detailed Markdown incident report with timelines, extracted IOCs, and remediation suggestions.

---

## 🚀 Quick Start

### 1. Local Interactive Simulator (No GPU / No Docker Needed)

You can test Doppel's routing, deception engine, and report generation locally:

```bash
# Clone the repository
git clone https://github.com/your-org/Doppel.git
cd Doppel

# Install dependencies
pip install -r requirements.txt

# Run the local interactive shell simulator (runs in mock mode)
python -m doppel.cli sim
```

Inside the simulator:
```bash
ubuntu@prod-api-node-01:/home/ubuntu$ cat .env
APP_ENV=production
DB_HOST=10.0.4.50
DB_DATABASE=app_production
DB_PASSWORD=P@ssw0rdProd2026!
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

ubuntu@prod-api-node-01:/home/ubuntu$ exit
```

---

### 2. Deploying on Remote Machine (with NVIDIA A2000 & Tailscale)

#### Step A: Start your local LLM on the remote machine
Using **Ollama**:
```bash
# Serve Ollama accessible over Tailscale
OLLAMA_HOST=0.0.0.0:11434 ollama serve

# Pull your preferred model (fits in 12GB VRAM)
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
DOPPEL_LLM_BASE_URL=http://100.x.y.z:11434/v1
DOPPEL_LLM_MODEL=qwen2.5-coder:7b
DOPPEL_LLM_MOCK_MODE=false
```

#### Step C: Test Model Connectivity
```bash
python -m doppel.cli test-model
```

#### Step D: Launch the Honeypot
```bash
# Option 1: Directly with Python
python -m doppel.cli run --verbose

# Option 2: Using Docker Compose
docker compose up -d
```

---

## ⚙️ Configuration (`config.yaml`)

```yaml
honeypot:
  host: "0.0.0.0"
  port: 2222
  server_banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  hostname: "prod-api-node-01"
  default_user: "ubuntu"
  accept_any_password: true

llm:
  base_url: "http://100.x.y.z:11434/v1"
  model: "qwen2.5-coder:7b"
  timeout_seconds: 15.0
  temperature: 0.2
  mock_mode: false

deception:
  persona: "ubuntu_web_server" # ubuntu_web_server | cloud_worker | fintech_api
  intercept_sensitive_files: true
  intercept_missing_tools: true

sandbox:
  enabled: true
  image: "alpine:latest"
  network_disabled: true
  memory_limit: "256m"
```

---

## 🧪 Testing

Run the test suite:
```bash
pytest tests/
```

---

## 📊 Telemetry & Reports

- **Database**: Recorded in SQLite (`doppel_telemetry.db`).
- **Reports**: Auto-generated in `reports/incident_<session_id>_<timestamp>.md`.
- **Manual Report Generation**:
  ```bash
  python -m doppel.cli report <session_id>
  ```

---

## 🗺️ Roadmap & Feature Suggestions

> **Agent Instruction**: Keep this roadmap updated whenever features are initiated, modified, or completed. Mark completed features with `[x]` and add brief operational notes.

- [ ] **Minimalist Web SOC Dashboard & Control Center** `[In Progress]`
  - GUI-driven lifecycle control: start, stop, and configure the honeypot without manual CLI commands.
  - Multi-instance attack monitor with individual session drilldown and real-time terminal inspection.
  - Live WebSocket telemetry and MITRE ATT&CK breakdown.
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

