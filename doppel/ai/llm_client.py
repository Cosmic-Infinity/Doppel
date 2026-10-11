import json
import logging
from typing import List, Dict, Any, Optional
import httpx

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

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: int = 1024,
        response_format: Optional[Dict[str, str]] = None,
    ) -> str:
        """Send chat messages and return the assistant reply string."""
        if self.mock_mode:
            return self._mock_response(messages)

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

        url = f"{self.base_url}/chat/completions"
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.warning(f"LLM request to {url} failed: {e}. Falling back to mock generator.")
            return self._mock_response(messages)

    def _mock_response(self, messages: List[Dict[str, str]]) -> str:
        """Deterministic mock response for offline/local development."""
        user_msg = messages[-1]["content"].lower() if messages else ""

        # Check if threat intelligence is requested
        if "mitre" in user_msg or "analyze command" in user_msg or "threat" in user_msg:
            return json.dumps({
                "tactics": ["Discovery"],
                "technique_id": "T1087",
                "technique_name": "Account Discovery",
                "threat_score": 45,
                "attacker_intent": "Enumerating user accounts and credentials",
                "is_automated": False,
                "confidence": 0.85
            })

        # Intercepted commands
        if "cat /etc/shadow" in user_msg or "shadow" in user_msg:
            return (
                "root:$6$v1J8G1$zR2xXk5.9Y1Lw9yN:19741:0:99999:7:::\n"
                "daemon:*:19065:0:99999:7:::\n"
                "ubuntu:$6$kL90Qx$4J.pZ19mF8LpX012:19741:0:99999:7:::\n"
                "deploy:$6$xY82Pq$1mN9.oP7Q2xV019:19741:0:99999:7:::"
            )
        elif ".env" in user_msg:
            return (
                "APP_ENV=production\n"
                "APP_KEY=base64:7L1x9Q5kJp99aX12mO98=\n"
                "DB_HOST=10.0.4.50\n"
                "DB_DATABASE=app_production\n"
                "DB_USERNAME=doppel_db_user\n"
                "DB_PASSWORD=P@ssw0rdProd2026!\n"
                "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
                "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "STRIPE_API_KEY=sk_live_51MzX90fakeStripeKey2026"
            )
        elif "aws" in user_msg or "credentials" in user_msg:
            return (
                "[default]\n"
                "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
                "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
                "region = us-east-1"
            )
        elif "linpeas" in user_msg or "nmap" in user_msg:
            return (
                "Starting Nmap 7.94 ( https://nmap.org )\n"
                "Nmap scan report for localhost (127.0.0.1)\n"
                "Host is up (0.00012s latency).\n"
                "PORT     STATE SERVICE\n"
                "22/tcp   open  ssh\n"
                "80/tcp   open  http\n"
                "3306/tcp open  mysql\n"
                "Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds"
            )
        elif "uname" in user_msg:
            return "Linux prod-api-node-01 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
        elif "os-release" in user_msg or "issue" in user_msg or "lsb_release" in user_msg:
            return (
                "PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\n"
                "NAME=\"Ubuntu\"\n"
                "VERSION_ID=\"22.04\"\n"
                "VERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\n"
                "VERSION_CODENAME=jammy\n"
                "ID=ubuntu\n"
                "ID_LIKE=debian"
            )
        elif "ps" in user_msg or "top" in user_msg:
            return (
                "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root           1  0.0  0.1 167528 11648 ?        Ss   01:10   0:01 /sbin/init\n"
                "root         412  0.0  0.1  89240  8912 ?        Ss   01:10   0:00 /lib/systemd/systemd-journald\n"
                "root         788  0.0  0.1  15428  7124 ?        Ss   01:10   0:00 /usr/sbin/sshd -D\n"
                "root         890  0.0  0.2 245120 18450 ?        Ss   01:10   0:00 nginx: master process /usr/sbin/nginx\n"
                "www-data     891  0.0  0.1 245780 12340 ?        S    01:10   0:01 nginx: worker process\n"
                "mysql       1040  0.1  3.2 1894200 240120 ?      Ssl  01:10   0:15 /usr/sbin/mysqld\n"
                "ubuntu      2450  0.0  0.0  14500  4210 pts/0    Ss   02:15   0:00 -bash\n"
                "ubuntu      2810  0.0  0.0  18900  3120 pts/0    R+   02:30   0:00 ps aux"
            )
        elif "shutdown" in user_msg or "reboot" in user_msg or "poweroff" in user_msg:
            return "Failed to set wall message, ignoring: Access denied\nFailed to call org.freedesktop.login1.Manager.PowerOff: Access denied"
        elif "ip a" in user_msg or "ifconfig" in user_msg or "ip addr" in user_msg:
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "       valid_lft forever preferred_lft forever\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000\n"
                "    link/ether 02:42:0a:00:04:0f brd ff:ff:ff:ff:ff:ff\n"
                "    inet 10.0.4.15/24 brd 10.0.4.255 scope global dynamic eth0\n"
                "       valid_lft 86350sec preferred_lft 86350sec"
            )
        elif "history" in user_msg:
            return (
                "    1  cd /var/www/html\n"
                "    2  git pull origin main\n"
                "    3  cat .env\n"
                "    4  systemctl restart nginx\n"
                "    5  sudo mysql -u root -p\n"
                "    6  docker ps -a"
            )
        elif "sudo" in user_msg:
            return "[sudo] password for ubuntu: "
        elif "id" in user_msg:
            return "uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)"
        elif "whoami" in user_msg:
            return "ubuntu"
        elif "apt" in user_msg:
            return "Reading package lists... Done\nBuilding dependency tree... Done\nAll packages are up to date."
        elif "systemctl" in user_msg or "service" in user_msg:
            return "System has not been booted with systemd as init system (PID 1). Can't operate."

        # Extract binary name from prompt format (e.g. 'ubuntu:/home/ubuntu$ command')
        cmd_text = user_msg
        if "$ " in cmd_text:
            cmd_text = cmd_text.split("$ ", 1)[1]
        elif "# " in cmd_text:
            cmd_text = cmd_text.split("# ", 1)[1]
        tokens = cmd_text.strip().split()
        binary = tokens[0] if tokens else "command"
        return f"bash: {binary}: command not found"
