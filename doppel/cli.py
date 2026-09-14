import sys
import time
import asyncio
import logging
from typing import Optional
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from doppel.config import get_config, DoppelConfig
from doppel.ai.llm_client import LLMClient
from doppel.ai.deception_engine import DeceptionEngine
from doppel.sandbox.docker_manager import DockerSandboxManager
from doppel.router.hybrid_router import HybridRouter
from doppel.analytics.db import TelemetryDB
from doppel.analytics.observer import ThreatObserver
from doppel.analytics.reporter import IncidentReporter
from doppel.core.session_manager import SessionManager
from doppel.core.ssh_server import start_ssh_server

app = typer.Typer(help="Doppel: AI-Augmented Hybrid Deception Honeypot System")
console = Console()


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        level=level,
    )


def build_system_stack(config: DoppelConfig) -> SessionManager:
    llm_client = LLMClient(
        base_url=config.llm.base_url,
        model=config.llm.model,
        api_key=config.llm.api_key,
        timeout=config.llm.timeout_seconds,
        temperature=config.llm.temperature,
        mock_mode=config.llm.mock_mode,
    )
    deception_engine = DeceptionEngine(llm_client=llm_client, persona=config.deception.persona)
    sandbox_manager = DockerSandboxManager(
        image=config.sandbox.image,
        network_disabled=config.sandbox.network_disabled,
        memory_limit=config.sandbox.memory_limit,
        enabled=config.sandbox.enabled,
    )
    router = HybridRouter(
        intercept_sensitive_files=config.deception.intercept_sensitive_files,
        intercept_missing_tools=config.deception.intercept_missing_tools,
        sandbox_available=sandbox_manager.is_available,
    )
    db = TelemetryDB(db_path=config.analytics.db_path)
    observer = ThreatObserver(llm_client=llm_client, db=db)
    reporter = IncidentReporter(llm_client=llm_client, db=db, reports_dir=config.analytics.reports_dir)

    return SessionManager(
        config=config,
        deception_engine=deception_engine,
        sandbox_manager=sandbox_manager,
        router=router,
        db=db,
        observer=observer,
        reporter=reporter,
    )


@app.command()
def run(
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
):
    """Start the Doppel SSH Honeypot daemon."""
    setup_logging(verbose)
    config = get_config(config_path)

    console.print(Panel.fit(
        f"[bold green]Doppel Honeypot System[/bold green]\n"
        f"[cyan]Listening on:[/cyan] {config.honeypot.host}:{config.honeypot.port}\n"
        f"[cyan]LLM Backend:[/cyan] {config.llm.base_url} ({config.llm.model})\n"
        f"[cyan]Mock Mode:[/cyan] {'Enabled' if config.llm.mock_mode else 'Disabled'}\n"
        f"[cyan]Persona:[/cyan] {config.deception.persona}\n"
        f"[cyan]Sandbox:[/cyan] {'Active' if config.sandbox.enabled else 'Disabled'}",
        title="🍯 Doppel Initialized",
        border_style="green"
    ))

    async def main():
        session_mgr = build_system_stack(config)
        await session_mgr.db.initialize()
        server = await start_ssh_server(session_mgr, config)
        try:
            await server.wait_closed()
        except (KeyboardInterrupt, asyncio.CancelledError):
            console.print("\n[yellow]Shutting down honeypot...[/yellow]")
            server.close()
            await server.wait_closed()

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


@app.command()
def test_model(
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
):
    """Test latency and connectivity to the remote LLM endpoint (e.g. over Tailscale)."""
    config = get_config(config_path)
    console.print(f"[cyan]Connecting to LLM endpoint:[/cyan] {config.llm.base_url}")
    console.print(f"[cyan]Model target:[/cyan] {config.llm.model}")

    client = LLMClient(
        base_url=config.llm.base_url,
        model=config.llm.model,
        api_key=config.llm.api_key,
        timeout=config.llm.timeout_seconds,
        mock_mode=config.llm.mock_mode,
    )

    async def test():
        start = time.time()
        test_messages = [
            {"role": "system", "content": "You are a Linux bash emulator. Output raw CLI output only."},
            {"role": "user", "content": "ubuntu:/home/ubuntu# uname -a"}
        ]
        try:
            resp = await client.chat_completion(test_messages)
            elapsed = time.time() - start
            console.print(f"[bold green]✓ Connection Successful![/bold green] (Latency: {elapsed:.3f}s)")
            console.print(Panel(resp.strip(), title="Model Output"))
        except Exception as e:
            console.print(f"[bold red]✗ Connection Failed:[/bold red] {e}")

    asyncio.run(test())


@app.command()
def sim(
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
):
    """Launch an interactive terminal simulation to test routing and deception locally."""
    config = get_config(config_path)
    # Enable mock mode if no endpoint is reachable locally
    config.llm.mock_mode = True

    console.print(Panel.fit(
        "[bold yellow]Doppel Terminal Simulator (Local Interactive Test)[/bold yellow]\n"
        "Type commands to test hybrid routing, bait injection, and mock output.\n"
        "Type 'exit' to quit.",
        title="🖥️ Interactive Simulation"
    ))

    async def run_sim():
        session_mgr = build_system_stack(config)
        await session_mgr.db.initialize()
        session = await session_mgr.create_session(
            remote_ip="127.0.0.1",
            remote_port=54321,
            username=config.honeypot.default_user,
        )

        while True:
            prompt = f"{session.username}@{config.honeypot.hostname}:{session.cwd}$ "
            try:
                cmd = console.input(f"[bold green]{prompt}[/bold green]")
            except (EOFError, KeyboardInterrupt):
                break

            if cmd.strip() in ("exit", "logout"):
                break

            output = await session_mgr.process_command(session.session_id, cmd)
            if output:
                console.print(output)

        report_file = await session_mgr.close_session(session.session_id)
        if report_file:
            console.print(f"\n[green]Generated session report at:[/green] {report_file}")

    asyncio.run(run_sim())


@app.command()
def report(
    session_id: str = typer.Argument(..., help="Session ID to generate report for"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
):
    """Generate an incident response report for a completed session ID."""
    config = get_config(config_path)

    async def run_report():
        session_mgr = build_system_stack(config)
        report_file = await session_mgr.reporter.generate_session_report(session_id)
        if report_file:
            console.print(f"[bold green]Report successfully generated:[/bold green] {report_file}")
        else:
            console.print(f"[bold red]Failed to generate report for session:[/bold red] {session_id}")

    asyncio.run(run_report())


@app.command()
def dashboard(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host to bind dashboard to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to serve dashboard on"),
    config_path: Optional[str] = typer.Option(None, "--config", "-c", help="Path to config.yaml"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose debug logging"),
):
    """Start the Doppel Web SOC Dashboard & GUI Control Center."""
    setup_logging(verbose)
    import uvicorn
    from doppel.dashboard.app import app as fastapi_app, controller

    if config_path:
        controller.config_path = config_path
        controller.config = get_config(config_path)

    console.print(Panel.fit(
        f"[bold green]Doppel Control Center[/bold green]\n"
        f"[cyan]Dashboard URL:[/cyan] http://{host if host != '0.0.0.0' else 'localhost'}:{port}\n"
        f"[cyan]Controls:[/cyan] Start/Stop honeypot & configure directly via browser\n"
        f"[cyan]Telemetry:[/cyan] Live multi-session fleet monitor and terminal streams",
        title="🖥️ Web Dashboard",
        border_style="cyan"
    ))

    uvicorn.run(fastapi_app, host=host, port=port, log_level="debug" if verbose else "info")


if __name__ == "__main__":
    app()
