import json
import pytest
from doppel.ai.llm_client import LLMClient


@pytest.mark.asyncio
async def test_mock_llm_sensitive_file_generation():
    client = LLMClient(mock_mode=True)
    messages = [{"role": "user", "content": "ubuntu:/var/www/html# cat .env"}]
    output = await client.chat_completion(messages)

    assert "DB_PASSWORD" in output
    assert "AWS_ACCESS_KEY_ID" in output


@pytest.mark.asyncio
async def test_mock_llm_threat_analysis_json():
    client = LLMClient(mock_mode=True)
    messages = [
        {"role": "system", "content": "You are a threat observer."},
        {"role": "user", "content": "analyze command: cat /etc/passwd"}
    ]
    output = await client.chat_completion(messages)
    data = json.loads(output)

    assert "tactics" in data
    assert "threat_score" in data
    assert data["technique_id"].startswith("T")


@pytest.mark.asyncio
async def test_mock_llm_unknown_command_fallback():
    client = LLMClient(mock_mode=True)
    messages = [{"role": "user", "content": "ubuntu:/home/ubuntu$ foobar123 --some-flag"}]
    output = await client.chat_completion(messages)

    assert "bash: foobar123: command not found" in output
    assert "Simulated output for:" not in output


def test_deception_clean_output_collapses_repeats():
    from doppel.ai.deception_engine import DeceptionEngine
    engine = DeceptionEngine(LLMClient(mock_mode=True))

    raw = "Sorry, try again.\n" * 50
    cleaned = engine._clean_output(raw, command="sudo passwd")
    lines = cleaned.strip().splitlines()
    assert len(lines) == 2
    assert lines[0] == "Sorry, try again."
    assert lines[1] == "Sorry, try again."


def test_deception_clean_output_truncates_hallucinated_prompts():
    from doppel.ai.deception_engine import DeceptionEngine
    engine = DeceptionEngine(LLMClient(mock_mode=True))

    raw = (
        "[sudo] password for ubuntu: \n"
        "Sorry, try again.\n"
        "ubuntu@prod-api-node-01:~$ sudo shutdown\n"
        "Failed to set wall message\n"
    )
    cleaned = engine._clean_output(raw, command="sudo passwd")
    assert "[sudo] password for ubuntu:" in cleaned
    assert "Sorry, try again." in cleaned
    assert "sudo shutdown" not in cleaned
    assert "Failed to set wall message" not in cleaned


def test_deception_clean_output_strips_echoed_first_line():
    from doppel.ai.deception_engine import DeceptionEngine
    engine = DeceptionEngine(LLMClient(mock_mode=True))

    raw = (
        "ubuntu@prod-api-node-01:~$ sudo psswd\n"
        "[sudo] password for ubuntu: "
    )
    cleaned = engine._clean_output(raw, command="sudo psswd")
    assert "ubuntu@prod-api-node-01:~$" not in cleaned
    assert cleaned.strip() == "[sudo] password for ubuntu:"


@pytest.mark.asyncio
async def test_llm_client_extracts_reasoning_when_content_empty():
    from unittest.mock import patch, MagicMock

    client = LLMClient(mock_mode=False)

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "",
                "reasoning_content": "Detailed thinking about the last 5 attacks..."
            }
        }],
        "usage": {"completion_tokens": 1024}
    }

    with patch("httpx.AsyncClient.post", return_value=fake_resp):
        res = await client.chat_completion_with_metrics([{"role": "user", "content": "tell me about attacks"}])
        assert res["tokens"] == 1024
        assert "Detailed thinking about the last 5 attacks" in res["content"]
        assert "<think>" in res["content"]


@pytest.mark.asyncio
async def test_llm_client_combines_reasoning_and_content():
    from unittest.mock import patch, MagicMock

    client = LLMClient(mock_mode=False)

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "choices": [{
            "message": {
                "role": "assistant",
                "content": "Here is the summary of the attacks.",
                "reasoning_content": "Analyzing IP and telemetry."
            }
        }],
        "usage": {"completion_tokens": 1500}
    }

    with patch("httpx.AsyncClient.post", return_value=fake_resp):
        res = await client.chat_completion_with_metrics([{"role": "user", "content": "summary"}])
        assert res["tokens"] == 1500
        assert "<think>" in res["content"]
        assert "Analyzing IP and telemetry" in res["content"]
        assert "Here is the summary of the attacks." in res["content"]


