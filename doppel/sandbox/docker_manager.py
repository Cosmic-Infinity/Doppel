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
            except Exception as e:
                logger.warning(f"Docker daemon not reachable ({e}). Sandbox will fall back to simulated execution.")
                self.is_available = False
        else:
            if not DOCKER_INSTALLED:
                logger.info("Docker python library not installed; running in simulation fallback mode.")

    def create_sandbox_session(self, session_id: str) -> Optional[str]:
        """Spawn a new isolated container for an attacker session."""
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

            # Bootstrap standard Linux filesystem layout and ubuntu user (uid 1000)
            try:
                container.exec_run(
                    "/bin/sh -c 'mkdir -p /home/ubuntu /var/www/html /root && "
                    "(id -u ubuntu >/dev/null 2>&1 || adduser -D -u 1000 ubuntu 2>/dev/null || true) && "
                    "chown -R 1000:1000 /home/ubuntu 2>/dev/null || true'"
                )
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
            # Safe execution: ensure target directory exists, navigate inside shell rather than failing OCI
            safe_script = f"mkdir -p '{workdir}' 2>/dev/null; cd '{workdir}' 2>/dev/null || cd /; {command}"
            exec_res = container.exec_run(
                cmd=["/bin/sh", "-c", safe_script],
                user=user if user != "root" else "0:0",
                demux=True,
            )
            stdout_bytes, stderr_bytes = exec_res.output
            stdout = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
            stderr = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
            return ExecutionResult(stdout=stdout, stderr=stderr, exit_code=exec_res.exit_code)
        except Exception as e:
            logger.error(f"Error executing command in container {container_id}: {e}")
            return ExecutionResult(stdout="", stderr=str(e), exit_code=1)

    def destroy_sandbox_session(self, container_id: str):
        """Stop and remove the container on session termination."""
        if not self.is_available or not self.client or not container_id:
            return

        try:
            container = self.client.containers.get(container_id)
            container.kill()
            logger.info(f"Cleaned up sandbox container {container_id[:12]}")
        except Exception as e:
            logger.debug(f"Container cleanup notice for {container_id[:12]}: {e}")
