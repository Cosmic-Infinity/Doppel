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
