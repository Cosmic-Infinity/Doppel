import pytest
from doppel.router.hybrid_router import HybridRouter, RouteDecision


def test_builtin_routing():
    router = HybridRouter(sandbox_available=True)

    decision, reason = router.classify_command("cd /var/www")
    assert decision == RouteDecision.BUILTIN
    assert reason == "cd"

    decision, reason = router.classify_command("clear")
    assert decision == RouteDecision.BUILTIN

    decision, reason = router.classify_command("")
    assert decision == RouteDecision.BUILTIN


def test_sensitive_file_interception():
    router = HybridRouter(intercept_sensitive_files=True, sandbox_available=True)

    decision, reason = router.classify_command("cat /etc/shadow")
    assert decision == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    decision, reason = router.classify_command("head -n 20 .env")
    assert decision == RouteDecision.LLM_DECEPTION

    decision, reason = router.classify_command("cat ~/.aws/credentials")
    assert decision == RouteDecision.LLM_DECEPTION


def test_credential_harvesting_regex():
    router = HybridRouter(intercept_sensitive_files=True, sandbox_available=True)

    decision, reason = router.classify_command("grep -ri 'password' /var/www")
    assert decision == RouteDecision.LLM_DECEPTION
    assert reason == "credential_harvesting"


def test_missing_tools_interception():
    router = HybridRouter(intercept_missing_tools=True, sandbox_available=True)

    decision, reason = router.classify_command("nmap -sV localhost")
    assert decision == RouteDecision.LLM_DECEPTION
    assert reason == "deception_tool"

    decision, reason = router.classify_command("./linpeas.sh")
    assert decision == RouteDecision.LLM_DECEPTION


def test_sandbox_vs_simulation_fallback():
    # When sandbox is available, standard command routes to SANDBOX
    router_with_sandbox = HybridRouter(sandbox_available=True)
    decision, reason = router_with_sandbox.classify_command("ls -la /tmp")
    assert decision == RouteDecision.SANDBOX

    # When sandbox is unavailable, standard command falls back to LLM_DECEPTION
    router_without_sandbox = HybridRouter(sandbox_available=False)
    decision, reason = router_without_sandbox.classify_command("ls -la /tmp")
    assert decision == RouteDecision.LLM_DECEPTION


def test_system_discovery_and_fingerprinting_routing():
    router = HybridRouter(sandbox_available=True)

    # System queries must intercept to LLM deception
    for cmd in ["uname -a", "ps aux", "shutdown", "reboot", "ip a", "netstat -tlpn", "apt update"]:
        decision, reason = router.classify_command(cmd)
        assert decision == RouteDecision.LLM_DECEPTION
        assert "system_discovery" in reason

    # Release / container file targets must intercept to LLM deception
    for target in ["cat /etc/os-release", "cat /proc/version", "cat /.dockerenv"]:
        decision, reason = router.classify_command(target)
        assert decision == RouteDecision.LLM_DECEPTION
        assert "sensitive_file" in reason


def test_benign_commands_routing_and_priority():
    router = HybridRouter(
        sandbox_available=True,
        intercept_sensitive_files=True,
        intercept_missing_tools=True,
        benign_commands={"ls", "cat", "pwd", "grep", "whoami"},
    )

    # Benign commands with non-sensitive arguments route to SANDBOX
    dec, reason = router.classify_command("cat readme.txt")
    assert dec == RouteDecision.SANDBOX
    assert reason == "benign_command"

    dec, reason = router.classify_command("ls -la /home/ubuntu")
    assert dec == RouteDecision.SANDBOX
    assert reason == "benign_command"

    dec, reason = router.classify_command("pwd")
    assert dec == RouteDecision.SANDBOX
    assert reason == "benign_command"

    # CRITICAL: Even though 'cat' and 'grep' are in benign_commands,
    # sensitive file access and credential harvesting MUST be intercepted by LLM!
    dec, reason = router.classify_command("cat /etc/shadow")
    assert dec == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    dec, reason = router.classify_command("cat .env")
    assert dec == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    dec, reason = router.classify_command("grep -i password /var/www/html/app.py")
    assert dec == RouteDecision.LLM_DECEPTION
    assert reason == "credential_harvesting"


def test_safe_ip_passthrough():
    router = HybridRouter(
        sandbox_available=True,
        intercept_sensitive_files=True,
        intercept_missing_tools=True,
        benign_commands={"ls"},
    )

    # Untrusted session (is_safe_ip=False): intercepts sensitive targets
    dec, reason = router.classify_command("cat /etc/shadow", is_safe_ip=False)
    assert dec == RouteDecision.LLM_DECEPTION

    # Trusted session (is_safe_ip=True): passes through to sandbox
    dec, reason = router.classify_command("cat /etc/shadow", is_safe_ip=True)
    assert dec == RouteDecision.SANDBOX
    assert reason == "safe_ip_passthrough"

    # Shell built-in still handled as built-in even for safe IP
    dec, reason = router.classify_command("cd /tmp", is_safe_ip=True)
    assert dec == RouteDecision.BUILTIN
