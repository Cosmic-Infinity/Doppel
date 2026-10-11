import re
import logging
from typing import TYPE_CHECKING, List, Dict, Any, Optional
from doppel.ai.llm_client import LLMClient
from doppel.ai.prompts.deception_prompts import build_deception_system_prompt
if TYPE_CHECKING:
    from doppel.core.fake_filesystem import FakeFilesystem

logger = logging.getLogger("doppel.ai.deception")


class DeceptionEngine:
    """Orchestrates LLM-based terminal emulation, persona camouflage, and dynamic bait injection."""

    def __init__(self, llm_client: LLMClient, persona: str = "ubuntu_web_server"):
        self.llm_client = llm_client
        self.persona = persona
        self.system_prompt = build_deception_system_prompt(persona)

    def _clean_output(self, raw_output: str, command: str = "") -> str:
        """Strip markdown fences, hallucinated prompts, conversational preambles, and repeating loops."""
        text = raw_output.strip()

        # Remove ```bash ... ``` or ``` ... ```
        if text.startswith("```"):
            lines = text.splitlines()
            if len(lines) >= 2 and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()

        # Strip any quotes if the entire string is enclosed in them
        if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
            text = text[1:-1].strip()

        lines = text.splitlines()
        cleaned_lines: List[str] = []
        prompt_pattern = re.compile(r"^[\w\.\-]+(?:@[\w\.\-]+)?:.*?[$#]")

        # 1. Drop leading line if it just echoes the prompt and current command
        start_idx = 0
        if lines and command:
            first_line = lines[0].strip()
            if prompt_pattern.match(first_line) and command.strip() in first_line:
                start_idx = 1

        # 2. Iterate through lines, truncating if a subsequent prompt is hallucinated
        for i in range(start_idx, len(lines)):
            line = lines[i]
            # If the model starts hallucinating a new command prompt (e.g. ubuntu@hostname:~$ or ubuntu:/home/ubuntu$), truncate
            if prompt_pattern.match(line.strip()):
                break
            cleaned_lines.append(line)

        # 3. Collapse runaway consecutive identical lines (e.g. repeating "Sorry, try again.")
        collapsed_lines: List[str] = []
        consecutive_count = 0
        last_line: Optional[str] = None

        for line in cleaned_lines:
            stripped = line.strip()
            if stripped and stripped == last_line:
                consecutive_count += 1
                if consecutive_count <= 2:
                    collapsed_lines.append(line)
            else:
                consecutive_count = 1
                last_line = stripped if stripped else None
                collapsed_lines.append(line)

        return "\n".join(collapsed_lines)

    async def generate_command_output(
        self,
        command: str,
        cwd: str,
        user: str,
        session_history: Optional[List[Dict[str, str]]] = None,
        fake_fs: Optional["FakeFilesystem"] = None,
    ) -> str:
        """Generate authentic simulated output for a command in the current session context."""
        # Build system prompt — append fake filesystem state when it exists
        system_prompt = self.system_prompt
        if fake_fs:
            fs_block = fake_fs.build_context_block()
            if fs_block:
                system_prompt = system_prompt + "\n\n" + fs_block

        messages: List[Dict[str, str]] = [
            {"role": "system", "content": system_prompt}
        ]

        # Add recent conversation turns for terminal state continuity (last 5 commands)
        prompt_symbol = "#" if user == "root" else "$"
        if session_history:
            for turn in session_history[-5:]:
                messages.append({"role": "user", "content": f"{user}:{turn.get('cwd', '/')}{prompt_symbol} {turn.get('command')}"})
                hist_out = turn.get("output", "")
                if len(hist_out) > 400:
                    hist_out = hist_out[:400] + "\n..."
                messages.append({"role": "assistant", "content": hist_out})

        # Add current command
        messages.append({"role": "user", "content": f"{user}:{cwd}{prompt_symbol} {command}"})

        # Stop sequences to prevent prompt hallucination
        stop_tokens = [
            f"\n{user}@",
            f"\n{user}:",
            "\nroot@",
            "\nroot:",
            "\nubuntu@",
            "\nubuntu:",
        ]

        try:
            raw_response = await self.llm_client.chat_completion(
                messages=messages,
                temperature=0.2,
                frequency_penalty=0.4,
                stop=stop_tokens,
            )
            cleaned = self._clean_output(raw_response, command=command)
            return cleaned
        except Exception as e:
            logger.error(f"Error generating deception output: {e}")
            return f"bash: {command.split()[0]}: command not found"
