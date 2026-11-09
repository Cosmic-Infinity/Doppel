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


@pytest.mark.asyncio
async def test_llm_client_mock_streaming():
    client = LLMClient(mock_mode=True)
    chunks = []
    async for chunk in client.chat_completion_stream([{"role": "user", "content": "Run a speed benchmark test"}]):
        chunks.append(chunk)

    assert len(chunks) > 1
    assert any(c["delta"] for c in chunks[:-1])
    last = chunks[-1]
    assert last["done"] is True
    assert last["tokens"] > 0
    assert last["latency_seconds"] >= 0
    assert last["tokens_per_second"] >= 0


@pytest.mark.asyncio
async def test_llm_client_streaming_sse_with_reasoning():
    from unittest.mock import patch, MagicMock

    client = LLMClient(mock_mode=False, base_url="http://localhost:11434/v1")

    # Simulate SSE chunk sequence
    sse_lines = [
        'data: {"choices":[{"delta":{"reasoning_content":"Thinking about honeypot..."}}]}\n',
        'data: {"choices":[{"delta":{"reasoning_content":" done thinking."}}]}\n',
        'data: {"choices":[{"delta":{"content":"Here is the result."}}]}\n',
        'data: [DONE]\n'
    ]

    class FakeAiterLines:
        def __aiter__(self):
            self.iter = iter(sse_lines)
            return self

        async def __anext__(self):
            try:
                return next(self.iter)
            except StopIteration:
                raise StopAsyncIteration

    class FakeStreamContext:
        async def __aenter__(self):
            mock_resp = MagicMock()
            mock_resp.raise_for_status = MagicMock()
            mock_resp.aiter_lines = MagicMock(return_value=FakeAiterLines())
            return mock_resp

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    class FakeAsyncClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

        def stream(self, method, url, **kwargs):
            return FakeStreamContext()

    with patch("httpx.AsyncClient", FakeAsyncClient):
        chunks = []
        async for chunk in client.chat_completion_stream([{"role": "user", "content": "analyze"}]):
            chunks.append(chunk)

        combined = "".join(c["delta"] for c in chunks)
        assert "<think>" in combined
        assert "</think>" in combined
        assert "Thinking about honeypot" in combined
        assert "Here is the result." in combined
        assert chunks[-1]["done"] is True




@pytest.mark.asyncio
@pytest.mark.parametrize("finish_reason, truncated", [("length", True), ("stop", False)])
async def test_llm_client_reports_token_limit_stops(finish_reason, truncated):
    from unittest.mock import patch, MagicMock

    client = LLMClient(mock_mode=False)
    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.json.return_value = {
        "choices": [{"message": {"role": "assistant", "content": "partial"}, "finish_reason": finish_reason}],
    }

    with patch("httpx.AsyncClient.post", return_value=fake_resp):
        res = await client.chat_completion_with_metrics([{"role": "user", "content": "ps aux"}])
    assert res["truncated"] is truncated
