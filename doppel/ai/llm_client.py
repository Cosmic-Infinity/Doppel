import asyncio
import contextlib
import json
import logging
import random
import re
import time
from datetime import timedelta
from typing import List, Dict, Any, Optional, AsyncGenerator
import httpx

from doppel.core import clock

logger = logging.getLogger("doppel.ai")


class LLMClient:
    """Async OpenAI-compatible client for remote or local LLM inference (Ollama, vLLM, etc.)."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434/v1",
        model: str = "qwen2.5-coder:7b",
        api_key: str = "ollama",
        timeout: float = 15.0,
        temperature: float = 0.2,
        mock_mode: bool = False,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.timeout = timeout
        self.temperature = temperature
        self.mock_mode = mock_mode
        # Ask the server to skip the reasoning step (OpenAI-style reasoning_effort).
        # Models without reasoning ignore it.
        self.reasoning_off = False
        # Async context manager factory wrapped around every request (see
        # BackgroundQueue.terminal): background analysis gives way to this client
        self.priority_gate = None

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: int = 1024,
        response_format: Optional[Dict[str, str]] = None,
        stop: Optional[List[str]] = None,
        frequency_penalty: Optional[float] = None,
        presence_penalty: Optional[float] = None,
        reasoning_off: Optional[bool] = None,
    ) -> str:
        """Send chat messages and return the assistant reply string."""
        metrics = await self.chat_completion_with_metrics(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            response_format=response_format,
            stop=stop,
            frequency_penalty=frequency_penalty,
            presence_penalty=presence_penalty,
            reasoning_off=reasoning_off,
        )
        return metrics["content"]

    async def chat_completion_with_metrics(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: int = 1024,
        response_format: Optional[Dict[str, str]] = None,
        stop: Optional[List[str]] = None,
        frequency_penalty: Optional[float] = None,
        presence_penalty: Optional[float] = None,
        reasoning_off: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """Send chat messages and return the reply along with latency and token throughput metrics.

        `reasoning_off` overrides the client default for this request only.
        """
        start_t = time.perf_counter()
        if self.mock_mode:
            content = self._mock_response(messages)
            elapsed = max(time.perf_counter() - start_t, 0.05)
            # Estimate token count for mock mode
            tokens = max(1, int(len(content.split()) * 1.35))
            return {
                "content": content,
                "tokens": tokens,
                "latency_seconds": round(elapsed, 3),
                "tokens_per_second": round(tokens / elapsed, 1),
                "model": self.model,
            }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens,
        }

        if response_format:
            payload["response_format"] = response_format
        if stop:
            payload["stop"] = stop
        if frequency_penalty is not None:
            payload["frequency_penalty"] = frequency_penalty
        if presence_penalty is not None:
            payload["presence_penalty"] = presence_penalty
        if self.reasoning_off if reasoning_off is None else reasoning_off:
            payload["reasoning_effort"] = "none"

        url = f"{self.base_url}/chat/completions"
        gate = self.priority_gate() if self.priority_gate else contextlib.nullcontext()
        try:
            async with gate, httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                elapsed = max(time.perf_counter() - start_t, 0.001)
                choice = data["choices"][0]
                message_obj = choice.get("message", {})
                content = message_obj.get("content") or choice.get("text") or ""
                reasoning = (
                    message_obj.get("reasoning_content")
                    or message_obj.get("reasoning")
                    or message_obj.get("thinking")
                    or ""
                )

                if not content.strip() and reasoning.strip():
                    content = f"<think>\n{reasoning.strip()}\n</think>"
                elif reasoning.strip() and content.strip():
                    content = f"<think>\n{reasoning.strip()}\n</think>\n\n{content.strip()}"
                
                usage = data.get("usage", {})
                tokens = usage.get("completion_tokens")
                if not tokens or tokens <= 0:
                    tokens = max(1, int(len(content.split()) * 1.35))

                return {
                    "content": content,
                    "tokens": tokens,
                    "latency_seconds": round(elapsed, 3),
                    "tokens_per_second": round(tokens / elapsed, 1),
                    "model": data.get("model", self.model),
                }
        except Exception as e:
            logger.warning(f"LLM request to {url} failed: {e}. Falling back to mock generator.")
            elapsed = max(time.perf_counter() - start_t, 0.05)
            content = self._mock_response(messages)
            tokens = max(1, int(len(content.split()) * 1.35))
            return {
                "content": content,
                "tokens": tokens,
                "latency_seconds": round(elapsed, 3),
                "tokens_per_second": round(tokens / elapsed, 1),
                "model": self.model,
                # Callers that hold better data than the generic mock (for
                # example real sandbox output) use this to prefer their own
                "fallback": True,
            }

    async def chat_completion_stream(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: int = 2048,
        response_format: Optional[Dict[str, str]] = None,
        stop: Optional[List[str]] = None,
        frequency_penalty: Optional[float] = None,
        presence_penalty: Optional[float] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Stream tokens in real time along with live latency and throughput metrics."""
        start_t = time.perf_counter()

        if self.mock_mode:
            content = self._mock_response(messages)
            parts = re.split(r'(\s+)', content)
            token_count = 0
            for part in parts:
                if not part:
                    continue
                await asyncio.sleep(0.005)
                token_count += 1
                elapsed = max(time.perf_counter() - start_t, 0.001)
                yield {
                    "delta": part,
                    "tokens": token_count,
                    "latency_seconds": round(elapsed, 3),
                    "tokens_per_second": round(token_count / elapsed, 1),
                    "model": self.model,
                    "done": False,
                }
            elapsed = max(time.perf_counter() - start_t, 0.001)
            yield {
                "delta": "",
                "tokens": token_count,
                "latency_seconds": round(elapsed, 3),
                "tokens_per_second": round(token_count / elapsed, 1),
                "model": self.model,
                "done": True,
            }
            return

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature if temperature is not None else self.temperature,
            "max_tokens": max_tokens,
            "stream": True,
        }

        if response_format:
            payload["response_format"] = response_format
        if stop:
            payload["stop"] = stop
        if frequency_penalty is not None:
            payload["frequency_penalty"] = frequency_penalty
        if presence_penalty is not None:
            payload["presence_penalty"] = presence_penalty
        if self.reasoning_off:
            payload["reasoning_effort"] = "none"

        url = f"{self.base_url}/chat/completions"
        token_count = 0
        in_thinking = False
        target_model = self.model

        stream_timeout = httpx.Timeout(connect=20.0, read=60.0, write=20.0, pool=20.0)

        try:
            async with httpx.AsyncClient(timeout=stream_timeout) as client:
                async with client.stream("POST", url, json=payload, headers=headers) as resp:
                    resp.raise_for_status()
                    async for line in resp.aiter_lines():
                        line = line.strip()
                        if not line or not line.startswith("data:"):
                            continue
                        data_str = line[5:].strip()
                        if data_str == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue

                        if chunk.get("model"):
                            target_model = chunk["model"]

                        choices = chunk.get("choices", [])
                        if not choices:
                            continue
                        delta = choices[0].get("delta", {})
                        content_piece = delta.get("content") or ""
                        reasoning_piece = (
                            delta.get("reasoning_content")
                            or delta.get("reasoning")
                            or delta.get("thinking")
                            or ""
                        )

                        emitted_delta = ""
                        current_stage = "reasoning" if (reasoning_piece or in_thinking) else "compiling"

                        if reasoning_piece:
                            if not in_thinking:
                                emitted_delta += "<think>\n"
                                in_thinking = True
                            emitted_delta += reasoning_piece
                            current_stage = "reasoning"
                        elif content_piece:
                            if in_thinking:
                                emitted_delta += "\n</think>\n\n"
                                in_thinking = False
                            emitted_delta += content_piece
                            current_stage = "compiling"

                        if emitted_delta:
                            token_count += max(1, len(emitted_delta.split()))
                            elapsed = max(time.perf_counter() - start_t, 0.001)
                            yield {
                                "delta": emitted_delta,
                                "stage": current_stage,
                                "thought": reasoning_piece,
                                "content": content_piece if not in_thinking else "",
                                "tokens": token_count,
                                "latency_seconds": round(elapsed, 3),
                                "tokens_per_second": round(token_count / elapsed, 1),
                                "model": target_model,
                                "done": False,
                            }

            if in_thinking:
                token_count += 1
                elapsed = max(time.perf_counter() - start_t, 0.001)
                yield {
                    "delta": "\n</think>\n",
                    "stage": "reasoning",
                    "thought": "",
                    "content": "",
                    "tokens": token_count,
                    "latency_seconds": round(elapsed, 3),
                    "tokens_per_second": round(token_count / elapsed, 1),
                    "model": target_model,
                    "done": False,
                }

            elapsed = max(time.perf_counter() - start_t, 0.001)
            yield {
                "delta": "",
                "stage": "completed",
                "thought": "",
                "content": "",
                "tokens": token_count,
                "latency_seconds": round(elapsed, 3),
                "tokens_per_second": round(token_count / elapsed, 1),
                "model": target_model,
                "done": True,
            }
        except Exception as e:
            logger.warning(f"Streaming LLM request to {url} failed: {e}. Falling back to mock generator.")
            content = self._mock_response(messages)
            parts = re.split(r'(\s+)', content)
            token_count = 0
            for part in parts:
                if not part:
                    continue
                await asyncio.sleep(0.005)
                token_count += 1
                elapsed = max(time.perf_counter() - start_t, 0.001)
                yield {
                    "delta": part,
                    "stage": "compiling",
                    "thought": "",
                    "content": part,
                    "tokens": token_count,
                    "latency_seconds": round(elapsed, 3),
                    "tokens_per_second": round(token_count / elapsed, 1),
                    "model": self.model,
                    "done": False,
                }
            elapsed = max(time.perf_counter() - start_t, 0.001)
            yield {
                "delta": "",
                "stage": "completed",
                "thought": "",
                "content": "",
                "tokens": token_count,
                "latency_seconds": round(elapsed, 3),
                "tokens_per_second": round(token_count / elapsed, 1),
                "model": self.model,
                "done": True,
            }

    def _mock_response(self, messages: List[Dict[str, str]]) -> str:
        """Deterministic mock response for offline/local development."""
        user_msg = messages[-1]["content"].lower() if messages else ""
        sys_msg = messages[0]["content"].lower() if (messages and messages[0].get("role") == "system") else ""

        # Times in simulated output follow the real clock: the host booted
        # clock.uptime() ago, the current login started a few minutes ago and
        # earlier activity happened on previous days.
        now = clock.now()
        boot = clock.boot_time()
        login = now - timedelta(minutes=4, seconds=12)

        def day_at(days_back: int, hour: int, minute: int):
            return (now - timedelta(days=days_back)).replace(hour=hour, minute=minute, second=0, microsecond=0)

        deployed = day_at(1, 18, 30)
        composer = day_at(4, 14, 20)
        installed = boot + timedelta(minutes=2)

        # Check if incident report is requested
        if "incident report" in user_msg or "incident report" in sys_msg or "cyber incident response analyst" in sys_msg:
            return (
                "# Incident Response Report: Honeypot Session Analysis\n\n"
                "**Status:** Analysis Completed  \n"
                "**Attacker Classification:** Unauthorized Interactive Shell Probe  \n\n"
                "---\n\n"
                "## 1. Executive Summary\n"
                "An unauthorized remote entity established an interactive SSH session targeting the honeypot sensor. "
                "The observed session exhibited interactive host enumeration, permission reconnaissance, and credential harvesting attempts. "
                "All malicious operations were contained within isolated deception boundaries without host risk.\n\n"
                "---\n\n"
                "## 2. MITRE ATT&CK Matrix Mapping\n"
                "- **Discovery (TA0007)**: System Information Discovery (T1082), Account Discovery (T1087)\n"
                "- **Credential Access (TA0006)**: OS Credential Dumping (T1003)\n"
                "- **Execution (TA0002)**: Command and Scripting Interpreter (T1059.004)\n\n"
                "---\n\n"
                "## 3. Timeline of Significant Actions\n"
                "The remote actor performed sequential environment inspection commands to map local file hierarchies and retrieve service tokens.\n\n"
                "---\n\n"
                "## 4. Indicators of Compromise (IOCs)\n"
                "- Suspicious access attempts on administrative SSH credentials\n"
                "- Targeted exploration of local configuration directories\n\n"
                "---\n\n"
                "## 5. Recommended Defensive Remediations\n"
                "1. Enforce public-key authentication for SSH endpoints and disable interactive password authentication.\n"
                "2. Implement network ingress filtering on administrative ports.\n"
                "3. Revoke and rotate any decoy credentials accessed during this session.\n"
            )

        # Check if Doppel Security Intelligence Assistant is being queried
        if "security intelligence assistant" in sys_msg or "security assistant" in sys_msg:
            if "last attack" in user_msg or ("attack" in user_msg and "like" in user_msg):
                return (
                    "Based on recorded honeypot telemetry, the last intrusion was initiated from remote IP 100.81.22.95 targeting SSH on port 2222 with user 'ubuntu'.\n\n"
                    "Attacker Timeline & TTPs:\n"
                    "- Initial Access: Automated credential probing utilizing well-known service defaults.\n"
                    "- Reconnaissance: Enumerated system state via `whoami`, `id`, and examined `/etc/passwd`.\n"
                    "- Privilege Escalation: Attempted interactive `sudo passwd` password override.\n\n"
                    "Assessed Threat Level: High (Score: 85). All actions were captured and isolated within the deception boundary."
                )
            elif any(k in user_msg for k in ["suggestion", "recommend", "harden", "mitigat"]):
                return (
                    "Based on observed attacker behavior across recent honeypot sessions, here are prioritized defensive recommendations:\n\n"
                    "1. SSH Authentication: Disable password logins (`PasswordAuthentication no`) in `/etc/ssh/sshd_config` and mandate ED25519 SSH keys.\n"
                    "2. Sudoers Restriction: Audit `/etc/sudoers.d/` to eliminate passwordless privilege escalation paths and enforce command whitelisting.\n"
                    "3. Rate Limiting: Deploy fail2ban or firewall rate-limiting to ban IP addresses after 3 consecutive failed authentication handshakes.\n"
                    "4. Network Egress Filtering: Block unprompted outbound connections to external staging and C2 infrastructure."
                )
            elif any(k in user_msg for k in ["status", "subsystem", "software"]):
                return (
                    "Doppel Honeypot System Status:\n\n"
                    "- Daemon State: Operational and actively monitoring connection attempts.\n"
                    "- Listener: Active on port 2222 with OpenSSH 8.9p1 emulation.\n"
                    "- Persona Profile: Ubuntu 22.04 LTS (prod-api-node-01).\n"
                    "- Subsystems: LLM inference client is connected and isolated container sandbox is verified.\n"
                    "- Threat Telemetry: Real-time event streaming and MITRE ATT&CK mapping active."
                )
            elif any(k in user_msg for k in ["speed", "benchmark", "tokens"]):
                return (
                    "Model throughput benchmark completed successfully. The generation pipeline processed this response through the active inference engine. "
                    "Actual generation speed and round-trip latency are detailed in the telemetry metrics below. "
                    "This test verifies end-to-end communications between the dashboard and the local model worker."
                )
            else:
                return (
                    f"Security Assistant response received for query: '{messages[-1]['content']}'. "
                    "The system telemetry pipeline is active and monitoring session activity across all honeypot sensors. "
                    "You can query recent attacker profiles, request defensive remediations, or benchmark token throughput."
                )

        # Check if threat intelligence is requested
        if "mitre" in user_msg or "analyze command" in user_msg or ("threat" in user_msg and "score:" not in user_msg and "incident" not in user_msg):
            return json.dumps({
                "tactics": ["Discovery"],
                "technique_id": "T1087",
                "technique_name": "Account Discovery",
                "threat_score": 45,
                "attacker_intent": "Enumerating user accounts and credentials",
                "is_automated": False,
                "confidence": 0.85
            })

        # --- /etc/shadow ---
        if "cat /etc/shadow" in user_msg or ("shadow" in user_msg and "cat" in user_msg):
            return (
                "root:$6$rounds=656000$v1J8G1$zR2xXk5.9Y1Lw9yNqLc3PwKh7xY2m:19741:0:99999:7:::\n"
                "daemon:*:19065:0:99999:7:::\n"
                "bin:*:19065:0:99999:7:::\n"
                "sys:*:19065:0:99999:7:::\n"
                "sync:*:19065:0:99999:7:::\n"
                "games:*:19065:0:99999:7:::\n"
                "man:*:19065:0:99999:7:::\n"
                "lp:*:19065:0:99999:7:::\n"
                "mail:*:19065:0:99999:7:::\n"
                "news:*:19065:0:99999:7:::\n"
                "uucp:*:19065:0:99999:7:::\n"
                "proxy:*:19065:0:99999:7:::\n"
                "www-data:*:19065:0:99999:7:::\n"
                "backup:*:19065:0:99999:7:::\n"
                "list:*:19065:0:99999:7:::\n"
                "irc:*:19065:0:99999:7:::\n"
                "nobody:*:19065:0:99999:7:::\n"
                "systemd-network:!:19065::::::\n"
                "systemd-timesync:!:19065::::::\n"
                "messagebus:!:19065::::::\n"
                "syslog:!:19065::::::\n"
                "_apt:!:19065::::::\n"
                "sshd:!:19065::::::\n"
                "ubuntu:$6$rounds=656000$kL90Qx$4J.pZ19mF8LpX012H7m:19741:0:99999:7:::\n"
                "deploy:$6$rounds=656000$xY82Pq$1mN9.oP7Q2xV019kR4:19741:0:99999:7:::\n"
                "mysql:!:19065:0:99999:7:::\n"
                "redis:!:19065:0:99999:7:::"
            )

        # --- /etc/passwd ---
        if "/etc/passwd" in user_msg and ("cat" in user_msg or "head" in user_msg or "tail" in user_msg):
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                "sync:x:4:65534:sync:/bin:/bin/sync\n"
                "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
                "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
                "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
                "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
                "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
                "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
                "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
                "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
                "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
                "systemd-timesync:x:101:103:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin\n"
                "messagebus:x:102:105::/nonexistent:/usr/sbin/nologin\n"
                "syslog:x:103:106::/home/syslog:/usr/sbin/nologin\n"
                "_apt:x:104:65534::/nonexistent:/usr/sbin/nologin\n"
                "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
                "deploy:x:1001:1001:Deploy Bot:/home/deploy:/bin/bash\n"
                "mysql:x:114:120:MySQL Server:/nonexistent:/bin/false\n"
                "redis:x:115:121::/var/lib/redis:/usr/sbin/nologin"
            )

        # --- .env files ---
        if ".env" in user_msg and ("cat" in user_msg or "head" in user_msg or "less" in user_msg or "more" in user_msg or "strings" in user_msg):
            return (
                "APP_NAME=ProdAPI\n"
                "APP_ENV=production\n"
                "APP_KEY=base64:7L1x9Q5kJp99aX12mO98=\n"
                "APP_DEBUG=false\n"
                "APP_URL=https://api.prod-node-01.internal\n"
                "\n"
                "LOG_CHANNEL=stack\n"
                "LOG_LEVEL=error\n"
                "\n"
                "DB_CONNECTION=mysql\n"
                "DB_HOST=10.0.4.50\n"
                "DB_PORT=3306\n"
                "DB_DATABASE=app_production\n"
                "DB_USERNAME=api_prod\n"
                "DB_PASSWORD=P@ssw0rdProd2026!\n"
                "\n"
                "CACHE_DRIVER=redis\n"
                "QUEUE_CONNECTION=redis\n"
                "SESSION_DRIVER=redis\n"
                "REDIS_HOST=127.0.0.1\n"
                "REDIS_PASSWORD=null\n"
                "REDIS_PORT=6379\n"
                "\n"
                "MAIL_MAILER=smtp\n"
                "MAIL_HOST=smtp.mailgun.org\n"
                "MAIL_PORT=587\n"
                "MAIL_USERNAME=postmaster@mg.prod-node-01.internal\n"
                "MAIL_PASSWORD=key-3abc456def789ghi\n"
                "MAIL_ENCRYPTION=tls\n"
                "\n"
                "AWS_ACCESS_KEY_ID=AKIA5WQZT3LRXN7KHB2D\n"
                "AWS_SECRET_ACCESS_KEY=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\n"
                "AWS_DEFAULT_REGION=us-east-1\n"
                "AWS_BUCKET=prod-assets-20260101\n"
                "\n"
                "STRIPE_API_KEY=sk_live_51MzX90Lq8RkV2nWb7TcYp4DfH3sJu6GeR\n"
                "STRIPE_WEBHOOK_SECRET=whsec_Tz4Qm8Rk2Lw6Vb0Nc9Xp5Jd3Hs7GaYf1\n"
                "\n"
                "JWT_SECRET=s3cr3t_jwt_k3y_9921_production\n"
                "JWT_TTL=60"
            )

        # --- AWS credentials ---
        if ("aws" in user_msg and "credentials" in user_msg) or ".aws/credentials" in user_msg:
            return (
                "[default]\n"
                "aws_access_key_id = AKIA5WQZT3LRXN7KHB2D\n"
                "aws_secret_access_key = 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\n"
                "region = us-east-1\n"
                "\n"
                "[deploy-role]\n"
                "role_arn = arn:aws:iam::123456789012:role/DeployRole\n"
                "source_profile = default"
            )

        # --- nmap ---
        if "nmap" in user_msg:
            # Extract target host or IP if provided
            target = "10.0.4.50"
            m = re.search(r"nmap\s+.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+|[a-zA-Z0-9_\.\-]+)", user_msg)
            if m:
                cand = m.group(1).strip()
                if not cand.startswith("-") and cand not in ("sudo", "root"):
                    target = cand
            is_local = target in ("127.0.0.1", "localhost", "0.0.0.0")
            # Service/OS detection scans take noticeably longer than plain port scans
            thorough = bool(re.search(r"\s-(?:s[vV]|A|O)\b", user_msg, re.I))
            started, _, secs = clock.run_window(6.0, 16.0) if thorough else clock.run_window(0.6, 3.5)
            nmap_start = f"{started:%Y-%m-%d %H:%M} UTC"
            nmap_done = f"Nmap done: 1 IP address (1 host up) scanned in {secs:.2f} seconds"

            if is_local:
                return (
                    f"Starting Nmap 7.94SVN ( https://nmap.org ) at {nmap_start}\n"
                    f"Nmap scan report for {target} (127.0.0.1)\n"
                    "Host is up (0.000012s latency).\n"
                    "Not shown: 993 closed tcp ports (conn-refused)\n"
                    "PORT     STATE SERVICE  VERSION\n"
                    "22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)\n"
                    "80/tcp   open  http     nginx/1.18.0 (Ubuntu)\n"
                    "443/tcp  open  ssl/http nginx/1.18.0 (Ubuntu)\n"
                    "3000/tcp open  http     Node.js Express framework\n"
                    "3306/tcp open  mysql    MySQL 8.0.36-0ubuntu0.22.04.1\n"
                    "6379/tcp open  redis    Redis key-value store 6.0.16\n"
                    "9000/tcp open  cslistener?\n"
                    "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n\n"
                    "Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n"
                    f"{nmap_done}"
                )
            else:
                return (
                    f"Starting Nmap 7.94SVN ( https://nmap.org ) at {nmap_start}\n"
                    f"Nmap scan report for {target}\n"
                    "Host is up (0.000015s latency).\n"
                    "Not shown: 996 closed tcp ports (conn-refused)\n"
                    "PORT     STATE SERVICE  VERSION\n"
                    "22/tcp   open  ssh      OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)\n"
                    "80/tcp   open  http     nginx/1.18.0 (Ubuntu)\n"
                    "443/tcp  open  ssl/http nginx/1.18.0 (Ubuntu)\n"
                    "3306/tcp open  mysql    MySQL 8.0.36-0ubuntu0.22.04.1\n"
                    "Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel\n\n"
                    "Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n"
                    f"{nmap_done}"
                )

        # --- sqlmap ---
        if "sqlmap" in user_msg:
            started, _, _ = clock.run_window(4.0, 11.0)
            return (
                "    ___\n"
                "   __H__\n"
                " ___ ___[']_____ ___ ___  {1.7.11#stable}\n"
                "|_ -| . [,]     | .'| . |\n"
                "|___|_  [\"]_|_|_|__,|  _|\n"
                "      |_|V...       |_|   https://sqlmap.org\n\n"
                f"[*] starting @ {started:%H:%M:%S} /{started:%Y-%m-%d}/\n"
                "[INFO] testing connection to the target URL\n"
                "[INFO] checking if the target is protected by some kind of WAF/IPS\n"
                "[INFO] testing if the target URL content is stable\n"
                "[WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable\n"
                "[INFO] testing for SQL injection on GET parameter 'id'\n"
                "[INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'\n"
                "[INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable\n"
                "[INFO] target URL appears to be vulnerable"
            )

        # --- hydra ---
        if "hydra" in user_msg:
            started, ended, _ = clock.run_window(4.0, 28.0)
            return (
                "Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak\n\n"
                f"Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at {started:%Y-%m-%d %H:%M:%S}\n"
                "[DATA] max 16 tasks per 1 server, overall 16 tasks, 14 login tries (l:1/p:14), ~1 tries per task\n"
                "[DATA] attacking ssh://10.0.4.50:22/\n"
                "[22][ssh] host: 10.0.4.50   login: admin   password: password123\n"
                "1 of 1 target successfully completed, 1 valid password found\n"
                f"Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at {ended:%Y-%m-%d %H:%M:%S}"
            )

        # --- nikto ---
        if "nikto" in user_msg:
            started, ended, secs = clock.run_window(45.0, 140.0)
            return (
                "- Nikto v2.5.0\n"
                "---------------------------------------------------------------------------\n"
                "+ Target IP:          10.0.4.50\n"
                "+ Target Hostname:    10.0.4.50\n"
                "+ Target Port:        80\n"
                f"+ Start Time:         {started:%Y-%m-%d %H:%M:%S} (GMT0)\n"
                "---------------------------------------------------------------------------\n"
                "+ Server: nginx/1.18.0 (Ubuntu)\n"
                "+ The anti-clickjacking X-Frame-Options header is not present.\n"
                "+ The X-XSS-Protection header is not defined.\n"
                "+ The X-Content-Type-Options header is not set.\n"
                "+ Root page / redirects to /login\n"
                "+ 8048 requests: 0 error(s) and 4 item(s) reported on remote host\n"
                f"+ End Time:           {ended:%Y-%m-%d %H:%M:%S} (GMT0) ({int(secs)} seconds)"
            )

        # --- gobuster / dirsearch / ffuf ---
        if any(k in user_msg for k in ("gobuster", "dirsearch", "ffuf")):
            return (
                "===============================================================\n"
                "Gobuster v3.6\n"
                "by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)\n"
                "===============================================================\n"
                "[+] Url:                     http://10.0.4.50\n"
                "[+] Method:                  GET\n"
                "[+] Threads:                 10\n"
                "[+] Wordlist:                common.txt\n"
                "===============================================================\n"
                "Starting gobuster in directory enumeration mode\n"
                "===============================================================\n"
                "/admin                (Status: 301) [Size: 178] [--> http://10.0.4.50/admin/]\n"
                "/api                  (Status: 200) [Size: 42]\n"
                "/login                (Status: 200) [Size: 3412]\n"
                "/public               (Status: 301) [Size: 178]\n"
                "/.env                 (Status: 200) [Size: 512]\n"
                "===============================================================\n"
                "Finished"
            )

        # --- masscan ---
        if "masscan" in user_msg:
            started, _, _ = clock.run_window(2.0, 9.0)
            return (
                f"Starting masscan 1.3.2 (http://bit.ly/14GZzcT) at {started:%Y-%m-%d %H:%M:%S} GMT\n"
                "Initiating SYN Stealth Scan\n"
                "Scanning 1 hosts [4 ports/host]\n"
                "Discovered open port 22/tcp on 10.0.4.50\n"
                "Discovered open port 80/tcp on 10.0.4.50\n"
                "Discovered open port 443/tcp on 10.0.4.50\n"
                "Discovered open port 3306/tcp on 10.0.4.50"
            )

        # --- tcpdump / wireshark ---
        if any(k in user_msg for k in ("tcpdump", "wireshark")):
            t1 = clock.now()
            t2 = t1 + timedelta(microseconds=random.randint(250, 900))
            return (
                "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode\n"
                "listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n"
                f"{t1:%H:%M:%S.%f} IP 10.0.4.1.58420 > 10.0.4.15.22: Flags [.], ack 1, win 502, length 0\n"
                f"{t2:%H:%M:%S.%f} IP 10.0.4.15.22 > 10.0.4.1.58420: Flags [P.], seq 1:45, ack 1, win 501, length 44\n"
                "2 packets captured\n"
                "2 packets received by filter\n"
                "0 packets dropped by kernel"
            )

        # --- netcat / nc ---
        if re.search(r"\b(nc|netcat)\b", user_msg):
            return ""

        # --- metasploit / msfconsole ---
        if any(k in user_msg for k in ("metasploit", "msfconsole")):
            return (
                "       =[ metasploit v6.3.35-dev                          ]\n"
                "+ -- --=[ 2362 exploits - 1227 auxiliary - 413 post       ]\n"
                "+ -- --=[ 1391 payloads - 46 encoders - 11 nops           ]\n"
                "+ -- --=[ 9 evasion                                       ]\n\n"
                "msf6 > "
            )

        # --- SSH keys and authorized_keys ---
        if any(k in user_msg for k in ("id_rsa", "id_ed25519", "authorized_keys")):
            if "authorized_keys" in user_msg:
                return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1b9xP0L9Q8uN7Y2K3vW4rZ1mXo5P6qRsTuVwXyZaBc deploy-key-2026\n"
            return (
                "-----BEGIN OPENSSH PRIVATE KEY-----\n"
                "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
                "QyNTUxOQAAACDNXy3zQ06q5tE8pL9sV1bY7k2W3m4n5o6p7q8r9s0tAAAAJNhb8V/YW/Ff\n"
                "2AAAAtzc2gtZWQyNTUxOQAAACDNXy3zQ06q5tE8pL9sV1bY7k2W3m4n5o6p7q8r9s0tAA\n"
                "AEC3b2x1bXB1c0Bwcm9kLWFwaS1ub2RlLTAxAQIDBAU=\n"
                "-----END OPENSSH PRIVATE KEY-----"
            )

        # --- wp-config.php / config.php ---
        if "wp-config" in user_msg or "config.php" in user_msg:
            return (
                "<?php\n"
                "define( 'DB_NAME', 'app_production' );\n"
                "define( 'DB_USER', 'api_prod' );\n"
                "define( 'DB_PASSWORD', 'P@ssw0rdProd2026!' );\n"
                "define( 'DB_HOST', '10.0.4.50:3306' );\n"
                "define( 'DB_CHARSET', 'utf8mb4' );\n"
                "define( 'DB_COLLATE', '' );\n"
            )

        # --- linpeas / linenum / enum4linux ---
        if any(k in user_msg for k in ("linpeas", "linenum", "enum4linux")):
            return (
                "\n"
                "                            .--.  .-.\n"
                "Linux Privesc Checker v4.0.3\n"
                "\n"
                "[+] Current User: ubuntu\n"
                "[+] Hostname: prod-api-node-01\n"
                "[+] Kernel: 5.15.0-105-generic\n"
                "[+] OS: Ubuntu 22.04.4 LTS\n"
                "\n"
                "====================================( Basic information )====================================\n"
                "[+] sudo -l:\n"
                "    User ubuntu may run the following commands on prod-api-node-01:\n"
                "        (ALL : ALL) ALL\n"
                "\n"
                "====================================( Interesting Files )====================================\n"
                "[!] /var/www/html/.env (readable)\n"
                "[!] /home/ubuntu/.mysql_history (readable)\n"
                "[!] /home/ubuntu/.ssh/authorized_keys (readable)\n"
                "[+] /opt/scripts/backup.sh (readable, contains mysql credentials)\n"
                "\n"
                "====================================( Network Information )====================================\n"
                "[+] Listening ports:\n"
                "    22 (sshd), 80 (nginx), 443 (nginx), 3000 (node), 3306 (mysqld), 6379 (redis-server), 9000 (php-fpm)\n"
                "\n"
                "====================================( Users Information )====================================\n"
                "[+] Users with console: root, ubuntu, deploy\n"
                "[+] Users in sudo group: ubuntu\n"
                "[+] Users in docker group: (none)\n"
            )

        # --- uname ---
        if "uname" in user_msg:
            return "Linux prod-api-node-01 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"

        # --- /etc/os-release, /etc/issue, lsb_release ---
        if "os-release" in user_msg or "issue" in user_msg or "lsb_release" in user_msg:
            if "lsb_release" in user_msg:
                return (
                    "Distributor ID:\tUbuntu\n"
                    "Description:\tUbuntu 22.04.4 LTS\n"
                    "Release:\t22.04\n"
                    "Codename:\tjammy"
                )
            if "/etc/issue" in user_msg:
                return "Ubuntu 22.04.4 LTS \\n \\l\n"
            return (
                "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n"
                "NAME=\"Ubuntu\"\n"
                "VERSION_ID=\"22.04\"\n"
                "VERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\n"
                "VERSION_CODENAME=jammy\n"
                "ID=ubuntu\n"
                "ID_LIKE=debian\n"
                "HOME_URL=\"https://www.ubuntu.com/\"\n"
                "SUPPORT_URL=\"https://help.ubuntu.com/\"\n"
                "BUG_REPORT_URL=\"https://bugs.launchpad.net/ubuntu/\""
            )

        # --- /proc/version ---
        if "/proc/version" in user_msg:
            return "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-105) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024"

        # --- /proc/cpuinfo ---
        if "/proc/cpuinfo" in user_msg:
            return (
                "processor\t: 0\n"
                "vendor_id\t: GenuineIntel\n"
                "cpu family\t: 6\n"
                "model\t\t: 85\n"
                "model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz\n"
                "stepping\t: 4\n"
                "cpu MHz\t\t: 2499.998\n"
                "cache size\t: 33792 KB\n"
                "physical id\t: 0\n"
                "siblings\t: 2\n"
                "core id\t\t: 0\n"
                "cpu cores\t: 2\n"
                "bogomips\t: 4999.99\n"
                "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology\n"
                "\n"
                "processor\t: 1\n"
                "vendor_id\t: GenuineIntel\n"
                "cpu family\t: 6\n"
                "model\t\t: 85\n"
                "model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz\n"
                "stepping\t: 4\n"
                "cpu MHz\t\t: 2499.998\n"
                "cache size\t: 33792 KB\n"
                "physical id\t: 0\n"
                "siblings\t: 2\n"
                "core id\t\t: 1\n"
                "cpu cores\t: 2\n"
                "bogomips\t: 4999.99\n"
                "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology"
            )

        # --- /proc/meminfo ---
        if "/proc/meminfo" in user_msg:
            return (
                "MemTotal:        8011608 kB\n"
                "MemFree:         2145820 kB\n"
                "MemAvailable:    4718592 kB\n"
                "Buffers:          312480 kB\n"
                "Cached:          2480128 kB\n"
                "SwapCached:            0 kB\n"
                "SwapTotal:             0 kB\n"
                "SwapFree:              0 kB"
            )

        # --- ps / top ---
        if ("ps " in user_msg or user_msg.endswith("ps")) or "top" in user_msg:
            return (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                f"root           1  0.0  0.1 167528 11648 ?        Ss   {clock.ps_start(boot):<6}  0:14 /sbin/init\n"
                f"root         312  0.0  0.1  52432  9280 ?        Ss   {clock.ps_start(boot):<6}  0:08 /lib/systemd/systemd-journald\n"
                f"root         340  0.0  0.0  25544  5888 ?        Ss   {clock.ps_start(boot):<6}  0:02 /lib/systemd/systemd-udevd\n"
                f"systemd+     498  0.0  0.0  90168  6144 ?        Ssl  {clock.ps_start(boot):<6}  0:04 /lib/systemd/systemd-timesyncd\n"
                f"root         651  0.0  0.0  15420  7124 ?        Ss   {clock.ps_start(boot):<6}  0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\n"
                f"root         672  0.0  0.2 245120 18450 ?        Ss   {clock.ps_start(boot):<6}  1:12 nginx: master process /usr/sbin/nginx -g daemon on; master_process on;\n"
                f"www-data     673  0.0  0.1 245780 12340 ?        S    {clock.ps_start(boot):<6}  3:48 nginx: worker process\n"
                f"www-data     674  0.0  0.1 245620 11980 ?        S    {clock.ps_start(boot):<6}  3:42 nginx: worker process\n"
                f"mysql        812  0.1  3.2 1894200 258120 ?      Ssl  {clock.ps_start(boot):<6} 52:14 /usr/sbin/mysqld\n"
                f"redis        845  0.0  0.0  54632  5120 ?        Ssl  {clock.ps_start(boot):<6}  8:34 /usr/bin/redis-server 127.0.0.1:6379\n"
                f"root         890  0.0  0.0 199260  7508 ?        Ssl  {clock.ps_start(boot):<6}  0:00 /usr/sbin/php-fpm8.1 --nodaemonize --fpm-config /etc/php/8.1/fpm/php-fpm.conf\n"
                f"www-data     891  0.0  0.1 201420 12800 ?        S    {clock.ps_start(boot):<6}  2:18 php-fpm: pool www\n"
                f"ubuntu      1201  0.0  0.3 923452 28160 ?        Ssl  {clock.ps_start(boot):<6} 15:42 PM2 v5.3.0: God Daemon (/home/ubuntu/.pm2)\n"
                f"ubuntu      1215  0.1  0.4 1014580 35840 ?       Sl   {clock.ps_start(boot):<6} 48:30 node /var/www/api/index.js\n"
                f"ubuntu      1216  0.1  0.4 1014120 34960 ?       Sl   {clock.ps_start(boot):<6} 47:55 node /var/www/api/index.js\n"
                f"root        3201  0.0  0.0  15852  6480 ?        Ss   {clock.ps_start(login):<6}  0:00 sshd: ubuntu [priv]\n"
                f"ubuntu      3205  0.0  0.0  16044  5120 ?        S    {clock.ps_start(login):<6}  0:00 sshd: ubuntu@pts/0\n"
                f"ubuntu      3206  0.0  0.0   8672  5320 pts/0    Ss   {clock.ps_start(login):<6}  0:00 -bash\n"
                f"ubuntu      3421  0.0  0.0  10072  3360 pts/0    R+   {clock.ps_start(now):<6}  0:00 ps aux"
            )

        # --- shutdown / reboot / poweroff ---
        if "shutdown" in user_msg or "reboot" in user_msg or "poweroff" in user_msg:
            return (
                "Failed to set wall message, ignoring: Interactive authentication required.\n"
                "Failed to power off system via logind: Interactive authentication required.\n"
                "Failed to open initctl fifo: Permission denied\n"
                "Failed to talk to init daemon."
            )

        # --- ip a / ifconfig / ip addr ---
        if "ip a" in user_msg or "ifconfig" in user_msg or "ip addr" in user_msg:
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "       valid_lft forever preferred_lft forever\n"
                "    inet6 ::1/128 scope host\n"
                "       valid_lft forever preferred_lft forever\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n"
                "    link/ether 02:42:0a:00:04:0f brd ff:ff:ff:ff:ff:ff\n"
                "    inet 10.0.4.15/24 brd 10.0.4.255 scope global dynamic eth0\n"
                "       valid_lft 86350sec preferred_lft 86350sec\n"
                "    inet6 fe80::42:aff:fe00:40f/64 scope link\n"
                "       valid_lft forever preferred_lft forever"
            )

        # --- ss / netstat ---
        if "ss " in user_msg or user_msg.endswith("ss") or "netstat" in user_msg:
            return (
                "State      Recv-Q  Send-Q    Local Address:Port      Peer Address:Port   Process\n"
                "LISTEN     0       128       0.0.0.0:22              0.0.0.0:*           users:((\"sshd\",pid=651,fd=3))\n"
                "LISTEN     0       511       0.0.0.0:80              0.0.0.0:*           users:((\"nginx\",pid=672,fd=6))\n"
                "LISTEN     0       511       0.0.0.0:443             0.0.0.0:*           users:((\"nginx\",pid=672,fd=7))\n"
                "LISTEN     0       128       127.0.0.1:3000          0.0.0.0:*           users:((\"node\",pid=1215,fd=18))\n"
                "LISTEN     0       151       127.0.0.1:3306          0.0.0.0:*           users:((\"mysqld\",pid=812,fd=24))\n"
                "LISTEN     0       511       127.0.0.1:6379          0.0.0.0:*           users:((\"redis-server\",pid=845,fd=6))\n"
                "LISTEN     0       511       /run/php/php8.1-fpm.sock                    users:((\"php-fpm8.1\",pid=890,fd=7))\n"
                "ESTAB      0       0         10.0.4.15:22             10.0.4.1:58420      users:((\"sshd\",pid=3201,fd=4))"
            )

        # --- history ---
        if "history" in user_msg:
            return (
                "    1  cd /var/www/html\n"
                "    2  git pull origin main\n"
                "    3  cat .env\n"
                "    4  php artisan migrate --force\n"
                "    5  systemctl restart nginx\n"
                "    6  sudo mysql -u root -p\n"
                "    7  redis-cli FLUSHALL\n"
                "    8  tail -f /var/log/nginx/error.log\n"
                "    9  cd /var/www/api && npm run build\n"
                "   10  pm2 restart api-server\n"
                "   11  df -h\n"
                "   12  htop"
            )

        # --- crontab ---
        if "crontab" in user_msg:
            return (
                "# m h  dom mon dow   command\n"
                "0 3 * * * /opt/scripts/backup.sh >> /var/log/cron-backup.log 2>&1\n"
                "*/5 * * * * /usr/bin/curl -sf http://localhost:3000/health > /dev/null || /usr/bin/systemctl restart pm2-ubuntu\n"
                "0 0 * * 0 certbot renew --quiet"
            )

        # --- uptime / w ---
        if "uptime" in user_msg or ("w" == user_msg.split("$")[-1].strip().split("#")[-1].strip()):
            return clock.uptime_line()

        # --- free ---
        if "free" in user_msg:
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:         8011608     3291480     2145820      124568     2574308     4718592\n"
                "Swap:              0           0           0"
            )

        # --- df ---
        if "df" in user_msg:
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "tmpfs           784M  1.2M  783M   1% /run\n"
                "/dev/sda1        49G   18G   29G  38% /\n"
                "tmpfs           3.9G     0  3.9G   0% /dev/shm\n"
                "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
                "/dev/sda15      105M  6.1M   99M   6% /boot/efi\n"
                "tmpfs           784M  4.0K  784M   1% /run/user/1000"
            )

        # --- mount ---
        if "mount" in user_msg and "umount" not in user_msg:
            return (
                "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)\n"
                "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)\n"
                "/dev/sda1 on / type ext4 (rw,relatime,discard,errors=remount-ro)\n"
                "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n"
                "tmpfs on /run type tmpfs (rw,nosuid,nodev,size=802464k,nr_inodes=819200,mode=755)\n"
                "/dev/sda15 on /boot/efi type vfat (rw,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=iso8859-1,shortname=mixed,errors=remount-ro)"
            )

        # --- last ---
        if "last" in user_msg and "lastlog" not in user_msg:
            return (
                f"ubuntu   pts/0        10.0.4.1         {clock.short_date(login)}   still logged in\n"
                f"deploy   pts/1        10.0.4.5         {clock.short_date(deployed)} - {deployed + timedelta(minutes=42):%H:%M}  (00:42)\n"
                f"ubuntu   pts/0        10.0.4.1         {clock.short_date(day_at(1, 14, 15))} - 23:58  (09:43)\n"
                f"deploy   pts/1        10.0.4.5         {clock.short_date(day_at(2, 22, 0))} - 22:45  (00:45)\n"
                f"ubuntu   pts/0        10.0.4.1         {clock.short_date(day_at(2, 9, 30))} - 18:22  (08:52)\n"
                f"reboot   system boot  5.15.0-105-generi {clock.short_date(boot)}   still running\n"
                "\n"
                f"wtmp begins {clock.ctime(boot)}"
            )

        # --- sudo ---
        if "sudo" in user_msg:
            return "[sudo] password for ubuntu: "

        # --- systemctl / service ---
        if "systemctl" in user_msg or "service" in user_msg:
            if "nginx" in user_msg:
                return (
                    "nginx.service - A high performance web server and a reverse proxy server\n"
                    "     Loaded: loaded (/lib/systemd/system/nginx.service; enabled; vendor preset: enabled)\n"
                    f"     Active: active (running) since {boot + timedelta(seconds=23):%a %Y-%m-%d %H:%M:%S} UTC; {clock.days_ago_since(boot)}\n"
                    "       Docs: man:nginx(8)\n"
                    "    Process: 670 ExecStartPre=/usr/sbin/nginx -t -q -g daemon on; master_process on; (code=exited, status=0/SUCCESS)\n"
                    "    Process: 671 ExecStart=/usr/sbin/nginx -g daemon on; master_process on; (code=exited, status=0/SUCCESS)\n"
                    "   Main PID: 672 (nginx)\n"
                    "      Tasks: 3 (limit: 9448)\n"
                    "     Memory: 12.4M\n"
                    "        CPU: 1min 42.803s\n"
                    "     CGroup: /system.slice/nginx.service\n"
                    "             672 \"nginx: master process /usr/sbin/nginx -g daemon on; master_process on;\"\n"
                    "             673 \"nginx: worker process\" \"\" \"\" \"\" \"\" \"\" \"\" \"\" \"\"\n"
                    "             674 \"nginx: worker process\" \"\" \"\" \"\" \"\" \"\" \"\" \"\" \"\""
                )
            if "mysql" in user_msg:
                return (
                    "mysql.service - MySQL Community Server\n"
                    "     Loaded: loaded (/lib/systemd/system/mysql.service; enabled; vendor preset: enabled)\n"
                    f"     Active: active (running) since {boot + timedelta(seconds=30):%a %Y-%m-%d %H:%M:%S} UTC; {clock.days_ago_since(boot)}\n"
                    "    Process: 810 ExecStartPre=/usr/share/mysql/mysql-systemd-start pre (code=exited, status=0/SUCCESS)\n"
                    "   Main PID: 812 (mysqld)\n"
                    "     Status: \"Server is operational\"\n"
                    "      Tasks: 38 (limit: 9448)\n"
                    "     Memory: 412.8M\n"
                    "        CPU: 52min 14.206s\n"
                    "     CGroup: /system.slice/mysql.service\n"
                    "             812 /usr/sbin/mysqld"
                )
            if "ssh" in user_msg:
                return (
                    "ssh.service - OpenBSD Secure Shell server\n"
                    "     Loaded: loaded (/lib/systemd/system/ssh.service; enabled; vendor preset: enabled)\n"
                    f"     Active: active (running) since {boot + timedelta(seconds=20):%a %Y-%m-%d %H:%M:%S} UTC; {clock.days_ago_since(boot)}\n"
                    "       Docs: man:sshd(8)\n"
                    "              man:sshd_config(5)\n"
                    "   Main PID: 651 (sshd)\n"
                    "      Tasks: 1 (limit: 9448)\n"
                    "     Memory: 4.2M\n"
                    "        CPU: 12.401s\n"
                    "     CGroup: /system.slice/ssh.service\n"
                    "             651 \"sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups\""
                )
            # Generic systemctl list
            return (
                "  UNIT                        LOAD   ACTIVE SUB     DESCRIPTION\n"
                "  nginx.service               loaded active running A high performance web server\n"
                "  mysql.service               loaded active running MySQL Community Server\n"
                "  ssh.service                 loaded active running OpenBSD Secure Shell server\n"
                "  redis-server.service        loaded active running Advanced key-value store\n"
                "  php8.1-fpm.service          loaded active running The PHP 8.1 FastCGI Process Manager\n"
                "  pm2-ubuntu.service          loaded active running PM2 process manager for ubuntu\n"
                "  fail2ban.service            loaded active running Fail2Ban Service\n"
                "  ufw.service                 loaded active exited  Uncomplicated firewall\n"
                "  systemd-journald.service    loaded active running Journal Service\n"
                "  systemd-timesyncd.service   loaded active running Network Time Synchronization\n"
                "\n"
                "LOAD   = Reflects whether the unit definition was properly loaded.\n"
                "ACTIVE = The high-level unit activation state, i.e. generalization of SUB.\n"
                "SUB    = The low-level unit activation state, values depend on unit type.\n"
                "\n"
                "10 loaded units listed."
            )

        # --- id ---
        if "id" in user_msg and ("$ id" in user_msg or "# id" in user_msg or user_msg.strip().endswith("id")):
            return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)"

        # --- whoami ---
        if "whoami" in user_msg:
            return "ubuntu"

        # --- hostname ---
        if "hostname" in user_msg:
            return "prod-api-node-01"

        # --- env / printenv ---
        if "printenv" in user_msg or ("env" in user_msg and ("$ env" in user_msg or "# env" in user_msg)):
            return (
                "SHELL=/bin/bash\n"
                "USER=ubuntu\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin\n"
                "HOME=/home/ubuntu\n"
                "LOGNAME=ubuntu\n"
                "LANG=en_US.UTF-8\n"
                "TERM=xterm-256color\n"
                "SSH_CLIENT=10.0.4.1 58420 22\n"
                "SSH_CONNECTION=10.0.4.1 58420 10.0.4.15 22\n"
                "SSH_TTY=/dev/pts/0\n"
                "XDG_SESSION_ID=14\n"
                "XDG_RUNTIME_DIR=/run/user/1000\n"
                "MAIL=/var/mail/ubuntu"
            )

        # --- apt ---
        if "apt" in user_msg:
            if "update" in user_msg:
                return (
                    "Hit:1 http://us-east-1.ec2.archive.ubuntu.com/ubuntu jammy InRelease\n"
                    "Hit:2 http://us-east-1.ec2.archive.ubuntu.com/ubuntu jammy-updates InRelease\n"
                    "Hit:3 http://us-east-1.ec2.archive.ubuntu.com/ubuntu jammy-backports InRelease\n"
                    "Hit:4 http://security.ubuntu.com/ubuntu jammy-security InRelease\n"
                    "Reading package lists... Done\n"
                    "Building dependency tree... Done\n"
                    "Reading state information... Done\n"
                    "All packages are up to date."
                )
            return "Reading package lists... Done\nBuilding dependency tree... Done\nAll packages are up to date."

        # --- pwd ---
        if "pwd" in user_msg:
            if ":" in user_msg and ("$" in user_msg or "#" in user_msg):
                prefix = user_msg.split("$")[0].split("#")[0]
                return prefix.split(":")[-1]
            return "/home/ubuntu"

        # --- silent commands ---
        if any(c in user_msg for c in ["mkdir", "touch", "chmod", "chown", "rm", "mv", "cp", "export "]):
            return ""

        # --- ls ---
        if "ls" in user_msg:
            if "/var/www/html" in user_msg:
                if "-la" in user_msg or "-l" in user_msg:
                    return (
                        "total 268\n"
                        f"drwxr-xr-x 12 ubuntu www-data  4096 {clock.ls_time(deployed)} .\n"
                        f"drwxr-xr-x  4 root   root      4096 {clock.ls_time(installed)} ..\n"
                        f"-rw-r--r--  1 ubuntu www-data   712 {clock.ls_time(deployed)} .env\n"
                        f"drwxr-xr-x  8 ubuntu www-data  4096 {clock.ls_time(deployed - timedelta(minutes=1))} .git\n"
                        f"-rw-r--r--  1 ubuntu www-data   258 {clock.ls_time(installed)} .gitignore\n"
                        f"drwxr-xr-x  6 ubuntu www-data  4096 {clock.ls_time(installed)} app\n"
                        f"-rw-r--r--  1 ubuntu www-data  1743 {clock.ls_time(installed)} artisan\n"
                        f"drwxr-xr-x  3 ubuntu www-data  4096 {clock.ls_time(installed)} bootstrap\n"
                        f"-rw-r--r--  1 ubuntu www-data  2134 {clock.ls_time(composer)} composer.json\n"
                        f"-rw-r--r--  1 ubuntu www-data 211450 {clock.ls_time(composer)} composer.lock\n"
                        f"drwxr-xr-x  2 ubuntu www-data  4096 {clock.ls_time(installed)} config\n"
                        f"drwxr-xr-x  5 ubuntu www-data  4096 {clock.ls_time(installed)} database\n"
                        f"-rw-r--r--  1 ubuntu www-data   473 {clock.ls_time(installed)} package.json\n"
                        f"drwxr-xr-x  2 ubuntu www-data  4096 {clock.ls_time(installed)} public\n"
                        f"drwxr-xr-x  6 ubuntu www-data  4096 {clock.ls_time(installed)} resources\n"
                        f"drwxr-xr-x  2 ubuntu www-data  4096 {clock.ls_time(installed)} routes\n"
                        f"drwxr-xr-x  5 ubuntu www-data  4096 {clock.ls_time(installed)} storage\n"
                        f"drwxr-xr-x 41 ubuntu www-data  4096 {clock.ls_time(composer + timedelta(minutes=1))} vendor"
                    )
                return "app  artisan  bootstrap  composer.json  composer.lock  config  database  package.json  public  resources  routes  storage  vendor"
            if "-la" in user_msg or "-l" in user_msg or "-al" in user_msg:
                return (
                    "total 44\n"
                    f"drwxr-xr-x 6 ubuntu ubuntu 4096 {clock.ls_time(login)} .\n"
                    f"drwxr-xr-x 4 root   root   4096 {clock.ls_time(boot)} ..\n"
                    f"-rw------- 1 ubuntu ubuntu 2841 {clock.ls_time(login)} .bash_history\n"
                    "-rw-r--r-- 1 ubuntu ubuntu  220 Apr 15  2024 .bash_logout\n"
                    "-rw-r--r-- 1 ubuntu ubuntu 3771 Apr 15  2024 .bashrc\n"
                    f"drwx------ 2 ubuntu ubuntu 4096 {clock.ls_time(installed)} .cache\n"
                    f"-rw------- 1 ubuntu ubuntu  124 {clock.ls_time(composer - timedelta(minutes=5))} .mysql_history\n"
                    f"drwxrwxr-x 6 ubuntu ubuntu 4096 {clock.ls_time(installed + timedelta(minutes=95))} .pm2\n"
                    "-rw-r--r-- 1 ubuntu ubuntu  807 Apr 15  2024 .profile\n"
                    f"drwx------ 2 ubuntu ubuntu 4096 {clock.ls_time(boot)} .ssh\n"
                    f"drwxrwxr-x 3 ubuntu ubuntu 4096 {clock.ls_time(installed)} .local"
                )
            return ".bash_history  .bash_logout  .bashrc  .cache  .local  .mysql_history  .pm2  .profile  .ssh"

        # --- cat / head / tail generic files ---
        if "authorized_keys" in user_msg:
            return "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK7mQ2vR9tL4xW8bN3zP6cH1jF5sD0aG2eY9uT4iO7rM deploy@ci-runner-01"

        if ".bash_history" in user_msg or "bash_history" in user_msg:
            return (
                "cd /var/www/html\n"
                "git pull origin main\n"
                "cat .env\n"
                "php artisan migrate --force\n"
                "systemctl restart nginx\n"
                "sudo mysql -u root -p\n"
                "redis-cli FLUSHALL\n"
                "tail -f /var/log/nginx/error.log\n"
                "npm run build\n"
                "pm2 restart api-server"
            )

        # --- dpkg ---
        if "dpkg" in user_msg:
            return (
                "ii  nginx                     1.18.0-6ubuntu14.4     amd64  high performance web server\n"
                "ii  mysql-server-8.0           8.0.36-0ubuntu0.22.04.1 amd64  MySQL database server\n"
                "ii  php8.1-fpm                8.1.27-1ubuntu0.1      amd64  server-side, HTML-embedded scripting language\n"
                "ii  php8.1-mysql              8.1.27-1ubuntu0.1      amd64  MySQL module for PHP\n"
                "ii  nodejs                    18.19.0-1nodesource1   amd64  Node.js event-based server-side javascript engine\n"
                "ii  redis-server              5:6.0.16-1ubuntu1      amd64  Persistent key-value database\n"
                "ii  openssh-server            1:8.9p1-3ubuntu0.6     amd64  secure shell (SSH) server\n"
                "ii  certbot                   2.9.0-1                all    automatically configure HTTPS\n"
                "ii  fail2ban                  0.11.2-6               all    ban hosts that cause multiple authentication errors\n"
                "ii  ufw                       0.36.1-4ubuntu0.1      all    program for managing a Netfilter firewall\n"
                "ii  git                       1:2.34.1-1ubuntu1.10   amd64  fast, scalable, distributed revision control system\n"
                "ii  curl                      7.81.0-1ubuntu1.15     amd64  command line tool for transferring data with URL syntax"
            )

        # --- docker / dockerenv ---
        if "dockerenv" in user_msg or "/proc/1/cgroup" in user_msg:
            if "/proc/1/cgroup" in user_msg:
                return (
                    "0::/init.scope"
                )
            return "cat: /.dockerenv: No such file or directory"

        # --- journalctl ---
        if "journalctl" in user_msg:
            def j(minutes_ago):
                t = (now - timedelta(minutes=minutes_ago)).replace(microsecond=0)
                return f"{t:%b} {t.day:2d} {t:%H:%M:%S}"

            return (
                f"-- Journal begins at {boot:%a %Y-%m-%d %H:%M:%S} UTC, ends at {now:%a %Y-%m-%d %H:%M:%S} UTC. --\n"
                f"{j(9)} prod-api-node-01 CRON[4012]: (ubuntu) CMD (/usr/bin/curl -sf http://localhost:3000/health > /dev/null || /usr/bin/systemctl restart pm2-ubuntu)\n"
                f"{j(4)} prod-api-node-01 sshd[3201]: Accepted publickey for ubuntu from 10.0.4.1 port 58420 ssh2: ED25519 SHA256:q3Vt8mK1zR6wL9xN2bP5cH7jF0sD4aG1eY8uT3iO6rM\n"
                f"{j(4)} prod-api-node-01 sshd[3201]: pam_unix(sshd:session): session opened for user ubuntu(uid=1000) by (uid=0)\n"
                f"{j(4)} prod-api-node-01 systemd-logind[498]: New session 14 of user ubuntu.\n"
                f"{j(0)} prod-api-node-01 CRON[4098]: (ubuntu) CMD (/usr/bin/curl -sf http://localhost:3000/health > /dev/null || /usr/bin/systemctl restart pm2-ubuntu)"
            )

        # --- find ---
        if "find" in user_msg and "password" in user_msg:
            return (
                "/var/www/html/.env\n"
                "/var/www/api/.env\n"
                "/home/ubuntu/.mysql_history"
            )

        # Extract binary name from prompt format (e.g. 'ubuntu:/home/ubuntu$ command')
        cmd_text = user_msg
        if "$ " in cmd_text:
            cmd_text = cmd_text.split("$ ", 1)[1]
        elif "# " in cmd_text:
            cmd_text = cmd_text.split("# ", 1)[1]
        tokens = cmd_text.strip().split()
        binary = tokens[0] if tokens else "command"
        if binary == "echo":
            import shlex
            try:
                return " ".join(shlex.split(cmd_text.strip())[1:])
            except ValueError:
                return " ".join(tokens[1:])
        # Same rule as the live fallback: claiming cat or grep is missing would
        # expose the honeypot, so standard utilities print nothing instead
        from doppel.router.hybrid_router import COMMON_BINARIES
        if binary.rsplit("/", 1)[-1].lower() in COMMON_BINARIES:
            return ""
        return f"bash: {binary}: command not found"



def clients_from_config(llm_settings) -> "tuple[LLMClient, LLMClient]":
    """
    (terminal client, analysis client) from the `llm` config section.

    The terminal client answers attacker commands and must be fast; the
    analysis client tags commands and writes reports in the background and
    may use a different, slower model (`analysis_model`).
    """
    def make(model: str, timeout: float) -> LLMClient:
        return LLMClient(
            base_url=llm_settings.base_url,
            model=model,
            api_key=llm_settings.api_key,
            timeout=timeout,
            temperature=llm_settings.temperature,
            mock_mode=llm_settings.mock_mode,
        )

    analysis_model = getattr(llm_settings, "analysis_model", "") or llm_settings.model
    analysis_timeout = getattr(llm_settings, "analysis_timeout_seconds", None) or llm_settings.timeout_seconds
    return make(llm_settings.model, llm_settings.timeout_seconds), make(analysis_model, analysis_timeout)
