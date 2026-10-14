import re
import logging
from typing import Optional, Tuple, Dict
from dataclasses import dataclass

logger = logging.getLogger("doppel.sandbox")

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
    ):
        self.image = image
        self.network_disabled = network_disabled
        self.memory_limit = memory_limit
        self.enabled = enabled
        self.client = None
        self.is_available = False

        if self.enabled and DOCKER_INSTALLED:
            try:
                self.client = docker.from_env()
                self.client.ping()
                self.is_available = True
                logger.info(f"Docker sandbox initialized successfully. Base image: {self.image}")
                self.cleanup_orphans()
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
            return True
        except Exception:
            self.is_available = False
            return False

    def create_sandbox_session(self, session_id: str, username: str = "ubuntu") -> Optional[str]:
        """Spawn a new isolated container for an attacker session."""
        if not self.is_available:
            self.check_availability()
        if not self.is_available or not self.client:
            return None

        container_name = f"doppel_sandbox_{session_id[:8]}"
        try:
            # Ensure base image exists
            try:
                self.client.images.get(self.image)
            except docker.errors.ImageNotFound:
                logger.info(f"Pulling base sandbox image: {self.image}")
                self.client.images.pull(self.image)

            container = self.client.containers.run(
                image=self.image,
                name=container_name,
                detach=True,
                tty=True,
                stdin_open=True,
                network_mode="none" if self.network_disabled else "bridge",
                mem_limit=self.memory_limit,
                command="/bin/sh",
                remove=True,
            )

            # Bootstrap standard Linux layout, user accounts, Ubuntu release markers, aliases, and env file
            try:
                user_cmds = (
                    f"mkdir -p /home/{username} && "
                    f"(id -u '{username}' >/dev/null 2>&1 || adduser -D -s /bin/sh '{username}' 2>/dev/null || useradd -m -s /bin/sh '{username}' 2>/dev/null || true) && "
                    f"chown -R '{username}' /home/{username} 2>/dev/null || true; "
                ) if username and username != "root" else ""

                bootstrap_script = (
                    "mkdir -p /home/ubuntu /var/www/html /root /var/log /tmp && "
                    "(id -u ubuntu >/dev/null 2>&1 || adduser -D -u 1000 ubuntu 2>/dev/null || useradd -m -u 1000 ubuntu 2>/dev/null || true) && "
                    "chown -R 1000:1000 /home/ubuntu 2>/dev/null || true; "
                    f"{user_cmds}"
                    "rm -f /.dockerenv 2>/dev/null || true; "
                    "printf 'PRETTY_NAME=\"Ubuntu 22.04.4 LTS\"\\nNAME=\"Ubuntu\"\\nVERSION_ID=\"22.04\"\\nVERSION=\"22.04.4 LTS (Jammy Jellyfish)\"\\nID=ubuntu\\nID_LIKE=debian\\n' > /etc/os-release 2>/dev/null || true; "
                    "echo 'Ubuntu 22.04.4 LTS \\n \\l' > /etc/issue 2>/dev/null || true; "
                    "which apk >/dev/null 2>&1 && apk add --no-cache bash 2>/dev/null || true; "
                    "printf '#!/bin/sh\\nexec ls -la \"$@\"\\n' > /bin/ll 2>/dev/null && chmod +x /bin/ll 2>/dev/null || true; "
                    "printf '#!/bin/sh\\nexec ls -A \"$@\"\\n' > /bin/la 2>/dev/null && chmod +x /bin/la 2>/dev/null || true; "
                    "printf '#!/bin/sh\\nexec ls -CF \"$@\"\\n' > /bin/l 2>/dev/null && chmod +x /bin/l 2>/dev/null || true; "
                    "touch /tmp/.doppel_env && chmod 666 /tmp/.doppel_env 2>/dev/null || true"
                )
                container.exec_run(["/bin/sh", "-c", bootstrap_script])
            except Exception as init_err:
                logger.debug(f"Container bootstrap notice: {init_err}")

            logger.info(f"Created sandbox container {container.short_id} for session {session_id}")
            return container.id
        except Exception as e:
            logger.error(f"Failed to spawn container for session {session_id}: {e}")
            return None

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
            # If command exports a variable or alias, persist it in /tmp/.doppel_env
            persist_env = ""
            stripped = command.strip()
            if stripped.startswith(("export ", "alias ")):
                safe_val = stripped.replace("'", "'\\''")
                persist_env = f"; echo '{safe_val}' >> /tmp/.doppel_env 2>/dev/null || true"

            safe_script = (
                f"[ -f /tmp/.doppel_env ] && . /tmp/.doppel_env 2>/dev/null; "
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
                stderr = re.sub(
                    r"/bin/(sh|bash):\s*([a-zA-Z0-9_\-\.]+):\s*(not found|command not found)",
                    r"bash: \2: command not found",
                    stderr
                )

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

