from typing import Dict, Any

PERSONA_PROMPTS: Dict[str, str] = {
    "ubuntu_web_server": """You are an authentic Ubuntu 22.04.4 LTS Linux production web server.
Hostname: prod-api-node-01
Current User: ubuntu (uid=1000, gid=1000)
Installed Services: Nginx 1.18.0, PHP 8.1-FPM, MySQL 8.0.36, Node.js 18.19.0, Redis 6.0.16.
Working Directory: /home/ubuntu
Web Directory: /var/www/html (contains a Laravel/Node production API with .env, config/, package.json)
Recent History: git deployments, restarting nginx, editing .env, database migrations.
Honeytokens:
 - Database password: P@ssw0rdProd2026!
 - AWS Key: AKIAIOSFODNN7EXAMPLE (secret: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY)
 - JWT Secret: s3cr3t_jwt_k3y_9921_production
""",
    "cloud_worker": """You are an AWS EC2 instance (Amazon Linux 2023 / Ubuntu base) acting as a Kubernetes worker node.
Hostname: ip-10-0-2-44.ec2.internal
Current User: ec2-user (uid=1000, gid=1000)
Installed Services: containerd, kubelet, aws-cli v2.15.0, docker 24.0.7.
Environment: Fake AWS IMDSv2 metadata reachable at 169.254.169.254, ~/.aws/credentials populated with mock IAM role tokens.
Working Directory: /home/ec2-user
""",
    "fintech_api": """You are an internal payment gateway staging server running Debian 12 Bookworm.
Hostname: staging-payments-gw01
Current User: api-runner (uid=1001, gid=1001)
Services: Python 3.11, FastAPI, PostgreSQL 15, Celery, Stripe webhook listener.
Files: /opt/fintech-api contains config.yaml, keys/private_key.pem, .env.staging.
Honeytokens:
 - Fake Stripe test secret: sk_test_51MzFakeKeyFintech2026
 - Postgres connection: postgresql://fintech_admin:FinT3ch_Secure_2026@10.0.10.15:5432/payments
"""
}

TERMINAL_SYSTEM_INSTRUCTION = """CRITICAL RULES:
1. You are simulating the raw terminal output of a Linux server.
2. DO NOT explain yourself.
3. DO NOT output markdown code blocks (never use ```bash or ```).
4. DO NOT provide conversational commentary, greetings, or warnings.
5. If the command normally produces NO output in bash (e.g., `touch file`, `cd dir`, `export VAR=val`, successful `rm`), return an EMPTY STRING.
6. Output MUST strictly match authentic Linux CLI output, error codes, and formatting.
7. If a sensitive file is inspected (e.g., `.env`, `/etc/shadow`, `wp-config.php`, AWS configs), generate convincing, realistic file contents containing plausible honeytokens and credentials.
8. If an unfamiliar tool or recon script is run (e.g. `nmap`, `linpeas.sh`), hallucinate believable output matching the system persona rather than failing with 'command not found'.
"""


def build_deception_system_prompt(persona_name: str = "ubuntu_web_server") -> str:
    persona_desc = PERSONA_PROMPTS.get(persona_name, PERSONA_PROMPTS["ubuntu_web_server"])
    port_context = _build_port_context(persona_name)
    return f"{persona_desc}\n{port_context}\n{TERMINAL_SYSTEM_INSTRUCTION}"


# ---------------------------------------------------------------------------
# Per-persona port inventory used to make internal nmap / ss / netstat output
# consistent with the external-facing port profile.  This prevents an attacker
# who does both an external scan and an internal nmap from spotting discrepancies.
# ---------------------------------------------------------------------------
PERSONA_PORTS: dict[str, dict] = {
    "ubuntu_web_server": {
        "open_ports": [
            {"port": 22,   "service": "ssh",   "version": "OpenSSH 8.9p1"},
            {"port": 80,   "service": "http",  "version": "nginx 1.18.0"},
            {"port": 443,  "service": "https", "version": "nginx 1.18.0"},
            {"port": 3306, "service": "mysql", "version": "MySQL 8.0.36"},
        ],
        "internal_only": [
            {"port": 6379,  "service": "redis",      "version": "Redis 6.0.16"},
            {"port": 9000,  "service": "php-fpm",     "version": "PHP 8.1 FPM"},
            {"port": 32768, "service": "rpc-unknown", "version": ""},
        ],
    },
    "cloud_worker": {
        "open_ports": [
            {"port": 22,   "service": "ssh",    "version": "OpenSSH 8.9p1"},
        ],
        "internal_only": [
            {"port": 10250, "service": "kubelet",   "version": "1.29.3"},
            {"port": 10256, "service": "kube-proxy", "version": ""},
            {"port": 2376,  "service": "docker",    "version": "24.0.7"},
        ],
    },
    "fintech_api": {
        "open_ports": [
            {"port": 22,   "service": "ssh",   "version": "OpenSSH 8.9p1"},
            {"port": 443,  "service": "https", "version": "uvicorn/FastAPI"},
        ],
        "internal_only": [
            {"port": 5432, "service": "postgresql", "version": "15.6"},
            {"port": 6379, "service": "redis",      "version": "7.2.4"},
            {"port": 5555, "service": "celery",     "version": "Flower 2.0"},
        ],
    },
}


def _build_port_context(persona_name: str) -> str:
    """
    Build a deterministic port-awareness block injected into the system prompt.
    Ensures nmap/ss/netstat/netstat output always matches the persona's real
    exposed ports rather than being hallucinated inconsistently.
    """
    ports = PERSONA_PORTS.get(persona_name, PERSONA_PORTS["ubuntu_web_server"])
    all_ports = ports["open_ports"] + ports.get("internal_only", [])

    lines = [
        "AUTHORITATIVE PORT STATE (always use these exact ports for nmap, ss, netstat, lsof -i output):",
        "External (publicly reachable):",
    ]
    for p in ports["open_ports"]:
        ver = f"  version={p['version']}" if p.get("version") else ""
        lines.append(f"  {p['port']}/tcp  OPEN  {p['service']}{ver}")

    if ports.get("internal_only"):
        lines.append("Internal / loopback only (127.0.0.1):")
        for p in ports["internal_only"]:
            ver = f"  version={p['version']}" if p.get("version") else ""
            lines.append(f"  {p['port']}/tcp  LISTEN  {p['service']}{ver}")

    lines.append(
        "All other ports are CLOSED or FILTERED.  Never invent ports not listed above."
    )
    return "\n".join(lines)
