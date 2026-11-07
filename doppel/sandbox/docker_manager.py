import re
import logging
import threading
from pathlib import Path
from typing import Optional, Tuple, Dict
from dataclasses import dataclass

from doppel.core import clock

logger = logging.getLogger("doppel.sandbox")

# Image built from the Dockerfile next to this module (Ubuntu 22.04 userland)
BUNDLED_IMAGE = "doppel-sandbox:ubuntu-22.04"
BUNDLED_DOCKERFILE_DIR = Path(__file__).parent

try:
    import docker
    from docker.errors import DockerException
    DOCKER_INSTALLED = True
except ImportError:
    docker = None
    DockerException = Exception
    DOCKER_INSTALLED = False


@dataclass
class ExecutionResult:
    stdout: str
    stderr: str
    exit_code: int


class DockerSandboxManager:
    """Manages ephemeral, network-isolated containers for executing safe utility commands."""

    def __init__(
        self,
        image: str = "alpine:latest",
        network_disabled: bool = True,
        memory_limit: str = "256m",
        enabled: bool = True,
        hostname: str = "prod-api-node-01",
    ):
        self.image = image
        self.network_disabled = network_disabled
        self.memory_limit = memory_limit
        self.enabled = enabled
        # Without this, `hostname` inside the container prints the container ID
        self.hostname = hostname
        self.client = None
        self.is_available = False
        # Set once the sandbox image exists locally; until then sessions use
        # simulated execution instead of waiting for a pull or build
        self.image_ready = threading.Event()
        self._image_thread: Optional[threading.Thread] = None

        if self.enabled and DOCKER_INSTALLED:
            try:
                self.client = docker.from_env()
                self.client.ping()
                self.is_available = True
                logger.info(f"Docker sandbox initialized successfully. Base image: {self.image}")
                self.cleanup_orphans()
                self.prepare_image_async()
            except Exception as e:
                logger.warning(f"Docker daemon not reachable ({e}). Sandbox will fall back to simulated execution.")
                self.is_available = False
        else:
            if not DOCKER_INSTALLED:
                logger.info("Docker python library not installed; running in simulation fallback mode.")

    def check_availability(self) -> bool:
        """Dynamically re-verify if Docker daemon has become reachable."""
        if not self.enabled or not DOCKER_INSTALLED:
            self.is_available = False
            return False
        # Test existing client if already instantiated
        if self.client:
            try:
                self.client.ping()
                self.is_available = True
                return True
            except Exception:
                pass
        # Re-acquire fresh client from environment (e.g. Docker Desktop pipe created after boot)
        try:
            client = docker.from_env()
            client.ping()
            self.client = client
            self.is_available = True
            logger.info("Docker daemon connection established dynamically.")
            self.cleanup_orphans()
            self.prepare_image_async()
            return True
        except Exception:
            self.is_available = False
            return False

    def ensure_image(self) -> bool:
        """
        Make sure the sandbox image exists locally: build the bundled image from
        its Dockerfile, or pull any other configured image. Blocking.
        """
        if not self.client:
            return False
        try:
            self.client.images.get(self.image)
            self.image_ready.set()
            return True
        except docker.errors.ImageNotFound:
            pass
        except Exception as e:
            logger.warning(f"Could not inspect sandbox image {self.image}: {e}")
            return False
        try:
            if self.image == BUNDLED_IMAGE:
                logger.info(f"Building sandbox image {self.image} (one-time, needs network access)...")
                self.client.images.build(
                    path=str(BUNDLED_DOCKERFILE_DIR), dockerfile="Dockerfile", tag=self.image, rm=True,
                )
            else:
                logger.info(f"Pulling sandbox image: {self.image}")
                self.client.images.pull(self.image)
            self.image_ready.set()
            logger.info(f"Sandbox image {self.image} is ready")
            return True
        except Exception as e:
            logger.error(f"Sandbox image {self.image} is unavailable: {e}. Using simulated execution.")
            return False

    def prepare_image_async(self):
        """Prepare the image in the background so no session waits on it."""
        if self.image_ready.is_set() or (self._image_thread and self._image_thread.is_alive()):
            return
        self._image_thread = threading.Thread(target=self.ensure_image, name="sandbox-image", daemon=True)
        self._image_thread.start()

    def create_sandbox_session(self, session_id: str, username: str = "ubuntu", preset: Optional[Dict[str, Any]] = None) -> Optional[str]:
        """Spawn a new isolated container for an attacker session."""
        if not self.is_available:
            self.check_availability()
        if not self.is_available or not self.client:
            return None
        if not self.image_ready.is_set():
            self.prepare_image_async()
            return None

        container_name = f"doppel_sandbox_{session_id[:8]}"
        active_preset = preset or {}
        persona = active_preset.get("persona_context", "ubuntu_web_server")
        default_user = active_preset.get("default_user", username or "ubuntu")
        user_uid = active_preset.get("user_uid", 1000)
        home_dir = active_preset.get("home_dir", f"/home/{default_user}")
        admin_ip = active_preset.get("admin_ip", "10.0.4.1")
        container_hostname = active_preset.get("hostname", self.hostname)

        try:
            # Check if container already exists
            try:
                existing = self.client.containers.get(container_name)
                if existing.status == "running":
                    return existing.id
                existing.remove(force=True)
            except Exception:
                pass

            container = self.client.containers.run(
                image=self.image,
                name=container_name,
                hostname=container_hostname,
                detach=True,
                tty=True,
                stdin_open=True,
                network_mode="none" if self.network_disabled else "bridge",
                mem_limit=self.memory_limit,
                command="/bin/sh",
                remove=True,
            )

            # Bootstrap standard Linux layout, user accounts, distro release markers, aliases, and env file
            try:
                user_cmds = (
                    f"mkdir -p /home/{username} && "
                    f"(id -u '{username}' >/dev/null 2>&1 || adduser -D -s /bin/sh '{username}' 2>/dev/null || useradd -m -s /bin/sh '{username}' 2>/dev/null || true) && "
                    f"chown -R '{username}' /home/{username} 2>/dev/null || true; "
                ) if username and username != "root" and username != default_user else ""

                # who reports the session's login time (container creation) and
                # the persona's boot time, both from the simulated clock
                login_stamp = f"{clock.now():%Y-%m-%d %H:%M}"
                boot_stamp = f"{clock.boot_time():%Y-%m-%d %H:%M}"
                who_wrapper = (
                    "printf '#!/bin/sh\\n' > /usr/local/bin/who && "
                    "printf 'if [ $# -eq 0 ] || [ \"$1\" = \"-m\" ] || { [ $# -eq 2 ] && { [ \"$1 $2\" = \"am i\" ] || [ \"$1 $2\" = \"am I\" ] || [ \"$1 $2\" = \"mom likes\" ]; }; }; then\\n' >> /usr/local/bin/who && "
                    f"printf '    printf \"{default_user}   pts/0        {login_stamp} ({admin_ip})\\n\"\\n' >> /usr/local/bin/who && "
                    "printf '    exit 0\\n' >> /usr/local/bin/who && "
                    "printf 'fi\\n' >> /usr/local/bin/who && "
                    f"printf 'if [ \"$1\" = \"-q\" ]; then\\n    printf \"{default_user}\\n# users=1\\n\"\\n    exit 0\\nfi\\n' >> /usr/local/bin/who && "
                    "printf 'if [ \"$1\" = \"-b\" ]; then\\n    printf \"         system boot  " + boot_stamp + "\\n\"\\n    exit 0\\nfi\\n' >> /usr/local/bin/who && "
                    "printf 'if [ \"$1\" = \"-r\" ]; then\\n    printf \"         run-level 5  " + boot_stamp + "\\n\"\\n    exit 0\\nfi\\n' >> /usr/local/bin/who && "
                    "printf 'if [ $# -gt 0 ]; then\\n    printf \"who: extra operand '\''%%s'\''\\nTry '\''who --help'\'' for more information.\\n\" \"$1\"\\n    exit 1\\nfi\\n' >> /usr/local/bin/who && "
                    "chmod +x /usr/local/bin/who 2>/dev/null || true; "
                )

                if persona == "fintech_api":
                    os_release = "printf 'PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\\nNAME=\"Debian GNU/Linux\"\\nVERSION_ID=\"12\"\\nVERSION=\"12 (bookworm)\"\\nVERSION_CODENAME=bookworm\\nID=debian\\nHOME_URL=\"https://www.debian.org/\"\\n' > /etc/os-release 2>/dev/null || true; "
                    issue_text = "echo 'Debian GNU/Linux 12 \\n \\l' > /etc/issue 2>/dev/null || true; "
                    decoy_seed = (
                        f"mkdir -p {home_dir}/.ssh /var/log/payments /opt/gateway && "
                        f"printf 'GATEWAY_ENV=staging\\nAPI_KEY=live_sec_99318a0f9b2c\\nDB_HOST=10.0.10.20\\n' > /opt/gateway/.env && "
                        f"printf 'git status\\nsudo systemctl status payment-gw\\n' > {home_dir}/.bash_history && "
                        f"chmod 600 {home_dir}/.bash_history 2>/dev/null || true; "
                        f"chown -R {user_uid}:{user_uid} /opt/gateway {home_dir} 2>/dev/null || true; "
                    )
                elif persona == "cloud_worker":
                    os_release = "printf 'NAME=\"Amazon Linux\"\\nVERSION=\"2023\"\\nID=\"amzn\"\\nID_LIKE=\"fedora\"\\nVERSION_ID=\"2023\"\\nPLATFORM_ID=\"platform:al2023\"\\nPRETTY_NAME=\"Amazon Linux 2023\"\\nANSI_COLOR=\"0;33\"\\nCPE_NAME=\"cpe:2.3:o:amazon:amazon_linux:2023\"\\nHOME_URL=\"https://aws.amazon.com/linux/amazon-linux-2023/\"\\n' > /etc/os-release 2>/dev/null || true; "
                    issue_text = "echo 'Amazon Linux 2023 \\n \\l' > /etc/issue 2>/dev/null || true; "
                    decoy_seed = (
                        f"mkdir -p {home_dir}/.ssh {home_dir}/.kube && "
                        f"printf 'AWS_REGION=us-east-1\\nCLUSTER_NAME=k8s-prod-worker\\n' > {home_dir}/.env && "
                        f"printf 'kubectl get nodes\\nkubectl get pods -A\\n' > {home_dir}/.bash_history && "
                        f"chmod 600 {home_dir}/.bash_history 2>/dev/null || true; "
                        f"chown -R {user_uid}:{user_uid} {home_dir} 2>/dev/null || true; "
                    )
                else:
                    # Standard Ubuntu 22.04 LTS layout
                    os_release = "printf 'PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\\nNAME=\"Ubuntu\"\\nVERSION_ID=\"22.04\"\\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\\nID=ubuntu\\nID_LIKE=debian\\n' > /etc/os-release 2>/dev/null || true; "
                    issue_text = "echo 'Ubuntu 22.04.4 LTS \\n \\l' > /etc/issue 2>/dev/null || true; "
                    decoy_seed = (
                        "mkdir -p /var/www/html/app /var/www/html/config /var/www/html/routes /var/www/html/public /var/www/html/storage && "
                        f"mkdir -p {home_dir}/.ssh && "
                        "printf 'APP_NAME=Laravel\\nAPP_ENV=production\\nAPP_KEY=base64:1+gXW62vAIAHAOTr6pYCvZvHuLp14YQdD3OPrj8iOPE=\\nAPP_DEBUG=false\\nAPP_URL=http://prod-api-node-01.internal\\n\\nDB_CONNECTION=mysql\\nDB_HOST=127.0.0.1\\nDB_PORT=3306\\nDB_DATABASE=app_production\\nDB_USERNAME=app_user\\nDB_PASSWORD=P@ssw0rd_ProdDb_2026!\\n\\nREDIS_HOST=127.0.0.1\\nREDIS_PASSWORD=null\\nREDIS_PORT=6379\\n\\nAWS_ACCESS_KEY_ID=AKIA5WQZT3LRXN7KHB2D\\nAWS_SECRET_ACCESS_KEY=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\\nAWS_DEFAULT_REGION=us-east-1\\n' > /var/www/html/.env && "
                        "printf \"{\\n    \\\"name\\\": \\\"laravel/laravel\\\",\\n    \\\"type\\\": \\\"project\\\",\\n    \\\"require\\\": {\\n        \\\"php\\\": \\\"^8.2\\\",\\n        \\\"laravel/framework\\\": \\\"^10.10\\\"\\n    }\\n}\\n\" > /var/www/html/composer.json && "
                        f"printf 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIG1b9xP0L9Q8uN7Y2K3vW4rZ1mXo5P6qRsTuVwXyZaBc deploy-key-2026\\n' > {home_dir}/.ssh/authorized_keys && "
                        f"printf 'SELECT user, host FROM mysql.user;\\nGRANT ALL PRIVILEGES ON app_production.* TO '\''api_prod'\''@'\''10.0.4.%%'\'' IDENTIFIED BY '\''P@ssw0rdProd2026!'\'';\\nFLUSH PRIVILEGES;\\n' > {home_dir}/.mysql_history && "
                        f"printf 'git status\\ngit pull origin main\\nphp artisan migrate --force\\nsystemctl restart php8.2-fpm\\nsudo systemctl reload nginx\\n' > {home_dir}/.bash_history && "
                        "chmod 644 /var/www/html/.env /var/www/html/composer.json 2>/dev/null || true; "
                        f"chmod 700 {home_dir}/.ssh 2>/dev/null || true; "
                        f"chmod 600 {home_dir}/.ssh/authorized_keys {home_dir}/.mysql_history {home_dir}/.bash_history 2>/dev/null || true; "
                        f"chown -R {user_uid}:{user_uid} /var/www/html {home_dir} 2>/dev/null || true; "
                    )

                bootstrap_script = (
                    f"mkdir -p {home_dir} /root /var/log /tmp /usr/local/bin && "
                    f"(id -u '{default_user}' >/dev/null 2>&1 || adduser -D -u {user_uid} '{default_user}' 2>/dev/null || useradd -m -u {user_uid} '{default_user}' 2>/dev/null || true) && "
                    f"chown -R {user_uid}:{user_uid} {home_dir} 2>/dev/null || true; "
                    f"{user_cmds}"
                    "rm -f /.dockerenv 2>/dev/null || true; "
                    f"{os_release}"
                    f"{issue_text}"
                    "which apk >/dev/null 2>&1 && apk add --no-cache bash 2>/dev/null || true; "
                    "printf '#!/bin/sh\\nexec ls -la \"$@\"\\n' > /bin/ll 2>/dev/null && chmod +x /bin/ll 2>/dev/null || true; "
                    "printf '#!/bin/sh\\nexec ls -A \"$@\"\\n' > /bin/la 2>/dev/null && chmod +x /bin/la 2>/dev/null || true; "
                    "printf '#!/bin/sh\\nexec ls -CF \"$@\"\\n' > /bin/l 2>/dev/null && chmod +x /bin/l 2>/dev/null || true; "
                    f"which sudo >/dev/null 2>&1 || (printf '#!/bin/sh\\nif [ \"$#\" -eq 0 ]; then echo \"usage: sudo -h | -K | -k | -V\"; exit 1; fi\\nif [ \"$1\" = \"-l\" ]; then echo \"Matching Defaults entries for {default_user} on $(hostname 2>/dev/null || echo {container_hostname}):\\n    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\\n\\nUser {default_user} may run the following commands on $(hostname 2>/dev/null || echo {container_hostname}):\\n    (ALL : ALL) ALL\"; exit 0; fi\\nexec \"$@\"\\n' > /usr/local/bin/sudo && chmod 755 /usr/local/bin/sudo || true); "
                    f"mkdir -p /etc/sudoers.d 2>/dev/null; echo '{default_user} ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/{default_user} 2>/dev/null || true; chmod 0440 /etc/sudoers.d/{default_user} 2>/dev/null || true; "
                    "touch /dev/shm/.bash_env && chmod 666 /dev/shm/.bash_env 2>/dev/null || true; "
                    f"{who_wrapper}"
                    f"{decoy_seed}"
                )
                container.exec_run(["/bin/sh", "-c", bootstrap_script])
            except Exception as init_err:
                logger.debug(f"Container bootstrap notice: {init_err}")

            logger.info(f"Created sandbox container {container.short_id} for session {session_id}")
            return container.id
        except Exception as e:
            logger.error(f"Failed to spawn container for session {session_id}: {e}")
            return None

    @classmethod
    def normalize_error(cls, stderr: str) -> str:
        """Normalize container shell error messages to standard bash format."""
        if not stderr:
            return ""
        return re.sub(
            r"/bin/(?:sh|bash):\s*(?:line\s*\d+:\s*)?([a-zA-Z0-9_\-\.]+):\s*(?:not found|command not found)",
            r"bash: \1: command not found",
            stderr,
        )

    _normalize_error = normalize_error

    def execute_in_sandbox(
        self,
        container_id: str,
        command: str,
        workdir: str = "/root",
        user: str = "ubuntu",
    ) -> ExecutionResult:
        """Run a command inside the session's container."""
        if not self.is_available or not self.client or not container_id:
            return ExecutionResult(stdout="", stderr="Sandbox unavailable", exit_code=1)

        try:
            container = self.client.containers.get(container_id)
            # Safe execution: source shell env, ensure target directory exists, navigate inside shell
            # If command exports a variable or alias, persist it in /dev/shm/.bash_env
            persist_env = ""
            stripped = command.strip()
            if stripped.startswith(("export ", "alias ")):
                safe_val = stripped.replace("'", "'\\''")
                persist_env = f"; echo '{safe_val}' >> /dev/shm/.bash_env 2>/dev/null || true"

            safe_script = (
                f"[ -f /dev/shm/.bash_env ] && . /dev/shm/.bash_env 2>/dev/null; "
                f"mkdir -p '{workdir}' 2>/dev/null; cd '{workdir}' 2>/dev/null || cd /; "
                f"{command}{persist_env}"
            )

            # Prefer /bin/bash if available in the container, otherwise fallback to /bin/sh
            shell_bin = "/bin/bash" if container.exec_run(["which", "bash"]).exit_code == 0 else "/bin/sh"
            exec_user = user if user != "root" else "0:0"

            try:
                exec_res = container.exec_run(
                    cmd=[shell_bin, "-c", safe_script],
                    user=exec_user,
                    demux=True,
                )
            except Exception as user_err:
                err_str = str(user_err).lower()
                if "unable to find user" in err_str or "no matching entries" in err_str:
                    logger.debug(f"User {user} missing in container; creating and retrying")
                    container.exec_run([
                        "/bin/sh",
                        "-c",
                        f"id -u '{user}' >/dev/null 2>&1 || (adduser -D '{user}' 2>/dev/null || useradd -m '{user}' 2>/dev/null || true)",
                    ])
                    try:
                        exec_res = container.exec_run(
                            cmd=[shell_bin, "-c", safe_script],
                            user=exec_user,
                            demux=True,
                        )
                    except Exception:
                        # Fallback to root execution
                        exec_res = container.exec_run(
                            cmd=[shell_bin, "-c", safe_script],
                            user="0:0",
                            demux=True,
                        )
                else:
                    raise user_err

            stdout_bytes, stderr_bytes = exec_res.output
            stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""

            # Normalize error messages so missing binaries output standard bash format
            if stderr:
                stderr = self.normalize_error(stderr)

            return ExecutionResult(stdout=stdout, stderr=stderr, exit_code=exec_res.exit_code)
        except Exception as e:
            logger.error(f"Error executing command in container {container_id}: {e}")
            return ExecutionResult(stdout="", stderr=str(e), exit_code=1)

    def sync_file_to_sandbox(self, container_id: str, path: str, content: str = "") -> bool:
        """Synchronize a file created or modified in FakeFS into the active container."""
        if not self.is_available or not self.client or not container_id:
            return False

        try:
            import base64
            import posixpath
            container = self.client.containers.get(container_id)
            parent_dir = posixpath.dirname(path)
            if parent_dir:
                container.exec_run(["mkdir", "-p", parent_dir], user="0:0")

            b64_content = base64.b64encode(content.encode("utf-8")).decode("ascii")
            container.exec_run(
                ["/bin/sh", "-c", f"echo '{b64_content}' | base64 -d > '{path}'"],
                user="0:0",
            )
            logger.debug(f"Synced FakeFS file '{path}' into container {container_id[:8]}")
            return True
        except Exception as e:
            logger.debug(f"Failed to sync file '{path}' into container {container_id[:8]}: {e}")
            return False

    def cleanup_orphans(self) -> int:
        """Find and remove any stale Doppel sandbox containers left over from prior runs."""
        if not self.is_available or not self.client:
            return 0
        removed = 0
        try:
            containers = self.client.containers.list(all=True, filters={"name": "doppel_sandbox_"})
            for c in containers:
                try:
                    c.remove(force=True, v=True)
                    removed += 1
                except Exception:
                    pass
            if removed > 0:
                logger.info(f"Cleaned up {removed} orphaned sandbox container(s)")
        except Exception as e:
            logger.debug(f"Notice while cleaning up orphaned containers: {e}")
        return removed

    def destroy_sandbox_session(self, container_id: str):
        """Stop and remove the container on session termination."""
        if not self.is_available or not self.client or not container_id:
            return

        try:
            container = self.client.containers.get(container_id)
            try:
                container.kill()
            except Exception:
                pass
            try:
                container.remove(force=True, v=True)
            except Exception:
                pass
            logger.info(f"Cleaned up sandbox container {container_id[:12]}")
        except Exception as e:
            logger.debug(f"Container cleanup notice for {container_id[:12]}: {e}")

