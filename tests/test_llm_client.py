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
