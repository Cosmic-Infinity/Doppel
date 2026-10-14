import re
import logging
from typing import TYPE_CHECKING, List, Dict, Any, Optional, Tuple, Union
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

    @staticmethod
    def extract_reasoning(raw_output: str) -> Tuple[str, Optional[str]]:
        """Extract <think> or <thought> reasoning blocks from model output.
        Returns:
            Tuple[cleaned_text_without_thoughts, reasoning_content_or_None]
        """
        text = raw_output or ""
        think_blocks: List[str] = []

        # 1. Closed tags: <think>...</think> or <thought>...</thought>
        closed_pattern = re.compile(r"<(think|thought)>([\s\S]*?)<\/\1>", flags=re.IGNORECASE)
        for match in closed_pattern.finditer(text):
            content = match.group(2).strip()
            if content:
                think_blocks.append(content)
        stripped = closed_pattern.sub("", text).strip()

        # 2. Unclosed tag if model was truncated mid-thought: <think>...
        unclosed_pattern = re.compile(r"<(think|thought)>([\s\S]*)$", flags=re.IGNORECASE)
        unclosed_match = unclosed_pattern.search(stripped)
        if unclosed_match:
            content = unclosed_match.group(2).strip()
            if content:
                think_blocks.append(content)
            stripped = unclosed_pattern.sub("", stripped).strip()

        reasoning = "\n\n".join(think_blocks) if think_blocks else None
        return stripped, reasoning

    def _clean_output(self, raw_output: str, command: str = "", user: str = "ubuntu") -> str:
        """Strip markdown fences, thinking tags, hallucinated prompts, conversational preambles, and repeating loops."""
        # Strip thinking tags if present
        text, _ = self.extract_reasoning(raw_output)
        text = text.strip()

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

        result = "\n".join(collapsed_lines)
        return self._sanitize_conversational_leak(result, command=command, user=user)

    def deterministic_posix_response(self, command: str, user: str = "ubuntu") -> Optional[str]:
        """Produce authentic POSIX responses for standard utilities, conversational queries, or non-binaries."""
        cmd_clean = command.strip()
        if not cmd_clean:
            return ""

        tokens = cmd_clean.split()
        binary = tokens[0].lower()

        # 1. who / whoami / id / hostname / uname
        if binary == "who":
            # who am i / who am I
            if len(tokens) >= 3 and tokens[1].lower() == "am" and tokens[2].lower() == "i":
                return f"{user}   pts/0        2026-10-15 02:40 (10.0.4.1)"
            # who with no arguments
            if len(tokens) == 1:
                return f"{user}   pts/0        2026-10-15 02:40 (10.0.4.1)"
            # Valid standard flags
            if len(tokens) == 2 and tokens[1] in ("-a", "-b", "-d", "-h", "-H", "-l", "-m", "-p", "-q", "-r", "-s", "-t", "-T", "-u"):
                if tokens[1] == "-q":
                    return f"{user}\n# users=1"
                if tokens[1] == "-b":
                    return "         system boot  2026-08-30 18:20"
                if tokens[1] == "-r":
                    return "         run-level 5  2026-08-30 18:20"
                return f"{user}   pts/0        2026-10-15 02:40 (10.0.4.1)"
            # Invalid flags / conversational queries: e.g. 'who are you', 'who is this'
            extra = tokens[1]
            return f"who: extra operand '{extra}'\nTry 'who --help' for more information."

        if binary == "whoami":
            return user

        if binary == "id":
            return f"uid=1000({user}) gid=1000({user}) groups=1000({user}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)"

        if binary == "hostname":
            return "prod-api-node-01"

        if binary == "uname":
            if any(t in ("-a", "--all") for t in tokens[1:]):
                return "Linux prod-api-node-01 5.15.0-105-generic #115-Ubuntu SMP Mon Apr 15 17:33:04 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux"
            if any("-r" in t for t in tokens[1:]):
                return "5.15.0-105-generic"
            if any("-m" in t for t in tokens[1:]):
                return "x86_64"
            if any(t in ("-s", "-o") for t in tokens[1:]):
                return "Linux" if "-s" in tokens[1:] else "GNU/Linux"
            return "Linux"

        # 2. Conversational non-binaries: bash strictly prints command not found
        conversational_non_binaries = {
            "what", "why", "how", "when", "where", "tell", "say", "describe",
            "explain", "repeat", "hello", "hi", "hey", "are", "is", "can",
            "could", "would", "please", "ignore", "system", "assistant", "ai",
            "whoami?", "help?", "what?", "who?", "why?"
        }
        if binary in conversational_non_binaries:
            return f"bash: {tokens[0]}: command not found"

        return None

    def _sanitize_conversational_leak(self, text: str, command: str = "", user: str = "ubuntu") -> str:
        """Detect and eliminate conversational AI speech or persona prompt leakage.

        Replaces conversational paragraphs with authentic POSIX bash syntax errors.
        """
        trimmed = text.strip()
        lower = trimmed.lower()

        # If user explicitly executed echo or printf, preserve it if output is just the echoed argument
        tokens = command.strip().split()
        if tokens and tokens[0].lower() in ("echo", "printf"):
            arg_str = " ".join(tokens[1:]).strip('\'"')
            if trimmed == arg_str or trimmed.strip('\'"') == arg_str:
                return text

        conversational_patterns = [
            r"\b(?:i\s+am|i'm|i\s+was|i\s+have\s+been|i\s+am\s+configured|i\s+cannot|i\s+can\s+not|i\s+will\s+not|i\s+don't|i\s+do\s+not)\b",
            r"\b(?:as\s+an?\s+(?:ubuntu|linux|debian|server|system|ai|language|model|assistant|virtual))\b",
            r"\b(?:my\s+(?:primary\s+user|system|hostname|purpose|creator|instructions|configuration|services\s+include|role\s+is))\b",
            r"\b(?:i\s+have\s+several\s+service\s+accounts|configured\s+to\s+handle\s+web\s+traffic|provide\s+a\s+backend\s+api)\b",
            r"\b(?:large\s+language\s+model|openai|anthropic|chatgpt|deepmind|qwen|claude|llama)\b",
            r"\b(?:certainly[!.]|sure,[ \t]|here\s+(?:is|are)\s+(?:the|some|details)|of\s+course[!.]|hello!|hi!|as\s+requested)\b",
            r"\b(?:running\s+on\s+a\s+cloud\s+provider|services\s+including\s+nginx|backend\s+api\s+for\s+a\s+laravel)\b",
            r"\b(?:in\s+accordance\s+with\s+my|as\s+per\s+my\s+instructions|my\s+system\s+prompt)\b",
            r"\b(?:an?\s+ubuntu\s+\d+\.\d+(?:\.\d+)?\s+lts\s+server)\b",
            r"\b(?:how\s+can\s+i\s+(?:help|assist)|what\s+can\s+i\s+do\s+for\s+you)\b",
            r"\b(?:feel\s+free\s+to\s+ask|let\s+me\s+know\s+if\s+you\s+need)\b",
            r"\b(?:system\s+prompt|operating\s+mode:|instruction\s+set|honeytokens)\b",
        ]

        is_conversational = any(re.search(pat, lower) for pat in conversational_patterns)
        if not is_conversational:
            return text

        logger.warning(f"Intercepted and suppressed conversational AI leak: {trimmed[:120]!r}")

        # Generate authentic POSIX error for this command
        deterministic = self.deterministic_posix_response(command, user=user)
        if deterministic is not None:
            return deterministic

        if not tokens:
            return ""

        return f"bash: {tokens[0]}: command not found"

    async def generate_command_output(
        self,
        command: str,
        cwd: str,
        user: str,
        session_history: Optional[List[Dict[str, str]]] = None,
        fake_fs: Optional["FakeFilesystem"] = None,
        session_id: Optional[str] = None,
        return_reasoning: bool = False,
    ) -> Union[str, Tuple[str, Optional[str]]]:
        """Generate authentic simulated output for a command in the current session context."""
        # Fast path: Check deterministic POSIX response first (no LLM call needed)
        deterministic = self.deterministic_posix_response(command, user=user)
        if deterministic is not None:
            if return_reasoning:
                return deterministic, None
            return deterministic
        # Build system prompt — append fake filesystem state when it exists
        system_prompt = self.system_prompt
        if fake_fs:
            fs_block = fake_fs.build_context_block()
            if fs_block:
                system_prompt = system_prompt + "\n\n" + fs_block

        # Inject dynamic canary honeytokens if accessing sensitive files or credentials
        cmd_lower = command.lower()
        sensitive_patterns = [".env", "aws", "credential", "config", "token", "secret", "key", "password", "cat", "grep", "id_rsa"]
        if any(pat in cmd_lower for pat in sensitive_patterns):
            try:
                from doppel.deception.honeytokens import get_honeytoken_manager
                ht_mgr = get_honeytoken_manager()
                ht_block = ht_mgr.build_injection_prompt_block(session_id or "default")
                system_prompt = system_prompt + "\n\n" + ht_block
            except Exception as e:
                logger.debug(f"Failed to inject dynamic honeytokens: {e}")

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
            stripped_text, reasoning = self.extract_reasoning(raw_response)
            cleaned = self._clean_output(stripped_text, command=command, user=user)
            if return_reasoning:
                return cleaned, reasoning
            return cleaned
        except Exception as e:
            logger.error(f"Error generating deception output: {e}")
            fallback = f"bash: {command.split()[0]}: command not found"
            if return_reasoning:
                return fallback, None
            return fallback

    async def transform_grounded_output(
        self,
        command: str,
        real_stdout: str,
        real_stderr: str,
        exit_code: int,
        user: str = "ubuntu",
        cwd: str = "/home/ubuntu",
        session_id: Optional[str] = None,
        return_reasoning: bool = False,
    ) -> Union[str, Tuple[str, Optional[str]]]:
        """Tier 2: Transform real Linux sandbox output with persona camouflage and canary honeytokens."""
        from doppel.ai.prompts.deception_prompts import build_grounded_transformation_prompt

        transformation_prompt = build_grounded_transformation_prompt(
            persona_name=self.persona,
            command=command,
            real_stdout=real_stdout,
            real_stderr=real_stderr,
            exit_code=exit_code,
        )

        # Inject dynamic canary honeytokens if applicable
        cmd_lower = command.lower()
        sensitive_patterns = [".env", "aws", "credential", "config", "token", "secret", "key", "password", "cat", "grep", "id_rsa"]
        if any(pat in cmd_lower for pat in sensitive_patterns):
            try:
                from doppel.deception.honeytokens import get_honeytoken_manager
                ht_mgr = get_honeytoken_manager()
                ht_block = ht_mgr.build_injection_prompt_block(session_id or "default")
                transformation_prompt = transformation_prompt + "\n\n" + ht_block
            except Exception as e:
                logger.debug(f"Failed to inject dynamic honeytokens in grounded transformation: {e}")

        messages = [
            {"role": "system", "content": transformation_prompt},
            {"role": "user", "content": f"Transform command output for: {command}"},
        ]

        try:
            raw_response = await self.llm_client.chat_completion(
                messages=messages,
                temperature=0.1,
                frequency_penalty=0.2,
                stop=[f"\n{user}@", f"\n{user}:", "\nroot@", "\nroot:", "\nubuntu@", "\nubuntu:"],
            )
            stripped_text, reasoning = self.extract_reasoning(raw_response)
            cleaned = self._clean_output(stripped_text, command=command, user=user)
            # If model produced nothing or broke, fall back to real stdout/stderr
            if not cleaned.strip() and (real_stdout or real_stderr):
                cleaned = (real_stdout + real_stderr).strip()
            if return_reasoning:
                return cleaned, reasoning
            return cleaned
        except Exception as e:
            logger.error(f"Error in grounded transformation: {e}")
            fallback = (real_stdout + real_stderr).strip() or f"bash: {command.split()[0]}: command not found"
            if return_reasoning:
                return fallback, None
            return fallback
