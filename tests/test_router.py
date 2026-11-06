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
    # Sensitive credential and honeytoken targets route directly to LLM_DECEPTION
    router = HybridRouter(intercept_sensitive_files=True, sandbox_available=True)

    decision, reason = router.classify_command("cat /etc/shadow")
    assert decision == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    decision, reason = router.classify_command("head -n 20 .env")
    assert decision == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    decision, reason = router.classify_command("cat ~/.aws/credentials")
    assert decision == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    decision, reason = router.classify_command("grep PASSWORD .env")
    assert decision == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    # Tier 3 fallback: Without sandbox, sensitive files also route to LLM_DECEPTION
    router_offline = HybridRouter(intercept_sensitive_files=True, sandbox_available=False)
    decision, reason = router_offline.classify_command("cat /etc/shadow")
    assert decision == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason


def test_credential_harvesting_regex():
    router = HybridRouter(intercept_sensitive_files=True, sandbox_available=True)

    decision, reason = router.classify_command("grep -ri 'password' /var/www")
    assert decision == RouteDecision.GROUNDED_DECEPTION
    assert reason == "credential_harvesting_grounded"

    router_offline = HybridRouter(intercept_sensitive_files=True, sandbox_available=False)
    decision, reason = router_offline.classify_command("grep -ri 'password' /var/www")
    assert decision == RouteDecision.LLM_DECEPTION
    assert reason == "credential_harvesting"


def test_missing_tools_interception():
    # Penetration testing tools (Tier 3) always route to LLM_DECEPTION
    router = HybridRouter(intercept_missing_tools=True, sandbox_available=True)

    decision, reason = router.classify_command("nmap -sV localhost")
    assert decision == RouteDecision.LLM_DECEPTION
    assert reason == "deception_tool"

    decision, reason = router.classify_command("./linpeas.sh")
    assert decision == RouteDecision.LLM_DECEPTION


def test_sandbox_vs_simulation_fallback():
    # When sandbox is available, standard command routes to SANDBOX (Tier 1)
    router_with_sandbox = HybridRouter(sandbox_available=True)
    decision, reason = router_with_sandbox.classify_command("ls -la /tmp")
    assert decision == RouteDecision.SANDBOX

    # When sandbox is unavailable, standard command falls back to LLM_DECEPTION (Tier 3)
    router_without_sandbox = HybridRouter(sandbox_available=False)
    decision, reason = router_without_sandbox.classify_command("ls -la /tmp")
    assert decision == RouteDecision.LLM_DECEPTION


def test_system_discovery_and_fingerprinting_routing():
    router = HybridRouter(sandbox_available=True)

    # Process and network discovery commands route to GROUNDED_DECEPTION (Tier 2) when sandbox available
    for cmd in ["ps aux", "ip a", "netstat -tlpn"]:
        decision, reason = router.classify_command(cmd)
        assert decision == RouteDecision.GROUNDED_DECEPTION
        assert "grounded_discovery" in reason

    # Release / container file targets route to GROUNDED_DECEPTION (Tier 2)
    for target in ["cat /etc/os-release", "cat /proc/version", "cat /.dockerenv"]:
        decision, reason = router.classify_command(target)
        assert decision == RouteDecision.GROUNDED_DECEPTION
        assert "sensitive_file" in reason


def test_dos_containment_routing():
    router = HybridRouter(sandbox_available=True)

    # Fork bombs and disk destruction route to LLM_DECEPTION (Tier 3 containment)
    fork_bomb = ":(){ :|:& };:"
    decision, reason = router.classify_command(fork_bomb)
    assert decision == RouteDecision.LLM_DECEPTION
    assert reason == "dos_containment"

    dd_zero = "dd if=/dev/zero of=/dev/sda"
    decision, reason = router.classify_command(dd_zero)
    assert decision == RouteDecision.LLM_DECEPTION
    assert reason == "dos_containment"


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

    dec, reason = router.classify_command("whoami")
    assert dec == RouteDecision.SANDBOX
    assert reason == "benign_command"

    # pwd is answered from the session's own working directory
    dec, reason = router.classify_command("pwd")
    assert dec == RouteDecision.BUILTIN

    # Even though 'cat' and 'grep' are in benign_commands,
    # sensitive file access MUST be intercepted directly by LLM_DECEPTION,
    # and generic credential searches across files by Grounded Deception.
    dec, reason = router.classify_command("cat /etc/shadow")
    assert dec == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    dec, reason = router.classify_command("cat .env")
    assert dec == RouteDecision.LLM_DECEPTION
    assert "sensitive_file" in reason

    dec, reason = router.classify_command("grep -i password /var/www/html/app.py")
    assert dec == RouteDecision.GROUNDED_DECEPTION
    assert reason == "credential_harvesting_grounded"


def test_required_routing_scenarios():
    """Verify the core routing scenarios specified in the system audit."""
    router = HybridRouter(
        sandbox_available=True,
        intercept_sensitive_files=True,
        intercept_missing_tools=True,
        benign_commands={"ls", "whoami", "pwd", "grep", "cat"},
    )

    # 1. whoami -> SANDBOX
    dec, _ = router.classify_command("whoami")
    assert dec == RouteDecision.SANDBOX

    # 2. pwd -> BUILTIN
    dec, _ = router.classify_command("pwd")
    assert dec == RouteDecision.BUILTIN

    # 3. cat .env -> LLM_DECEPTION
    dec, _ = router.classify_command("cat .env")
    assert dec == RouteDecision.LLM_DECEPTION

    # 4. cat ~/.aws/credentials -> LLM_DECEPTION
    dec, _ = router.classify_command("cat ~/.aws/credentials")
    assert dec == RouteDecision.LLM_DECEPTION

    # 5. grep PASSWORD .env -> LLM_DECEPTION
    dec, _ = router.classify_command("grep PASSWORD .env")
    assert dec == RouteDecision.LLM_DECEPTION

    # 6. nmap -sV 10.0.4.50 -> LLM_DECEPTION
    dec, _ = router.classify_command("nmap -sV 10.0.4.50")
    assert dec == RouteDecision.LLM_DECEPTION

    # 7. sudo nmap -sS localhost -> LLM_DECEPTION
    dec, _ = router.classify_command("sudo nmap -sS localhost")
    assert dec == RouteDecision.LLM_DECEPTION

    # 8. /usr/bin/nmap -A localhost -> LLM_DECEPTION
    dec, _ = router.classify_command("/usr/bin/nmap -A localhost")
    assert dec == RouteDecision.LLM_DECEPTION

    # 9. sqlmap -u http://example.com -> LLM_DECEPTION
    dec, _ = router.classify_command("sqlmap -u http://example.com")
    assert dec == RouteDecision.LLM_DECEPTION
