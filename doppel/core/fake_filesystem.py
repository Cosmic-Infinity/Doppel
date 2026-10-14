"""
Fake Filesystem
===============
A lightweight per-session in-memory filesystem that tracks file and directory
operations performed by the attacker via LLM-routed commands.

Why this matters:
    The LLM has no state between calls.  If an attacker runs:

        echo "10.0.4.50 root root_pass" > /tmp/targets.txt
        cat /tmp/targets.txt                   # two turns later

    ...the second call produces a generic "file not found"-style error unless
    we inject the existence and content of /tmp/targets.txt into the prompt.

How it works:
    1. After every LLM-routed command, `update_from_command()` is called.
       It uses regex heuristics to detect file-creating/modifying shell idioms
       and records them in the in-memory store.
    2. `build_context_block()` produces a compact text block that is prepended
       to the LLM system prompt so the model "knows" what the attacker already
       created.
    3. `DeceptionEngine.generate_command_output()` is updated to call this.

Tracked operations (heuristic, not a real shell parser):
    - Redirects:      echo|printf|cat … > file   (create/overwrite)
    - Appends:        echo … >> file
    - Touch:          touch <file>
    - Mkdir:          mkdir [-p] <dirs>
    - Cp:             cp <src> <dst>
    - Mv:             mv <src> <dst>           (renames src → dst)
    - Rm / Rmdir:     rm [-rf] / rmdir
    - Wget/curl -o:   download → create file
    - chmod/chown:    update metadata only
    - Script writes:  python3 -c "…" > file
"""

import re
import logging
from typing import Dict, Optional, List

logger = logging.getLogger("doppel.core.fake_filesystem")

# Maximum characters stored per file (truncated for prompt budget)
_MAX_FILE_CONTENT = 512
# Maximum total files tracked per session
_MAX_FILES = 128


class FakeFile:
    __slots__ = ("content", "size_hint", "is_executable")

    def __init__(
        self,
        content: str = "",
        size_hint: Optional[int] = None,
        is_executable: bool = False,
    ):
        self.content = content[:_MAX_FILE_CONTENT]
        self.size_hint = size_hint or len(content)
        self.is_executable = is_executable


class FakeFilesystem:
    """
    Lightweight in-memory store of attacker-created filesystem artefacts.
    One instance lives on the session; it is NOT shared between sessions.
    """

    def __init__(self):
        # path → FakeFile
        self._files: Dict[str, FakeFile] = {}
        # set of known directories the attacker created
        self._dirs: set[str] = set()

    # ------------------------------------------------------------------
    # Public API used by DeceptionEngine
    # ------------------------------------------------------------------

    def update_from_command(self, command: str, output: str, cwd: str = "/home/ubuntu") -> List[str]:
        """
        Parse a shell command and update the in-memory filesystem state.
        `output` is the LLM's response (used to infer content for downloads).
        Returns a list of file paths that were created or modified.
        """
        mutated_paths: List[str] = []
        if len(self._files) >= _MAX_FILES:
            return mutated_paths  # cap memory usage

        cmd = command.strip()

        # ---- mkdir ---------------------------------------------------------
        for m in re.finditer(
            r"\bmkdir\b(?:\s+-[pP])?\s+([^\s;&|]+)", cmd
        ):
            path = self._resolve(m.group(1), cwd=cwd)
            self._dirs.add(path)
            mutated_paths.append(path)
            logger.debug(f"FakeFS: mkdir {path}")

        # ---- touch ---------------------------------------------------------
        for m in re.finditer(r"\btouch\b\s+([^\s;&|>]+)", cmd):
            path = self._resolve(m.group(1), cwd=cwd)
            if path not in self._files:
                self._files[path] = FakeFile()
            mutated_paths.append(path)
            logger.debug(f"FakeFS: touch {path}")

        # ---- redirect (create/overwrite): … > file -------------------------
        m = re.search(r"(?<![>])\s>+\s*([^\s;&|]+)\s*$", cmd)
        if m and ">>" not in cmd[:m.start() + 2]:
            path = self._resolve(m.group(1), cwd=cwd)
            content = self._extract_redirect_content(cmd, operator=">")
            self._files[path] = FakeFile(content=content)
            mutated_paths.append(path)
            logger.debug(f"FakeFS: write {path!r} ({len(content)} chars)")

        # ---- append: … >> file ---------------------------------------------
        m = re.search(r">>\s*([^\s;&|]+)\s*$", cmd)
        if m:
            path = self._resolve(m.group(1), cwd=cwd)
            content = self._extract_redirect_content(cmd, operator=">>")
            if path in self._files:
                existing = self._files[path].content
                self._files[path] = FakeFile(content=existing + "\n" + content)
            else:
                self._files[path] = FakeFile(content=content)
            mutated_paths.append(path)
            logger.debug(f"FakeFS: append {path!r}")

        # ---- cp src dst ----------------------------------------------------
        m = re.match(r"\bcp\b(?:\s+-[^\s]+)?\s+(\S+)\s+(\S+)\s*$", cmd)
        if m:
            src, dst = self._resolve(m.group(1), cwd=cwd), self._resolve(m.group(2), cwd=cwd)
            if src in self._files:
                self._files[dst] = FakeFile(
                    content=self._files[src].content,
                    size_hint=self._files[src].size_hint,
                )
            else:
                self._files[dst] = FakeFile()
            mutated_paths.append(dst)
            logger.debug(f"FakeFS: cp {src} → {dst}")

        # ---- mv src dst ----------------------------------------------------
        m = re.match(r"\bmv\b\s+(\S+)\s+(\S+)\s*$", cmd)
        if m:
            src, dst = self._resolve(m.group(1), cwd=cwd), self._resolve(m.group(2), cwd=cwd)
            entry = self._files.pop(src, FakeFile())
            self._files[dst] = entry
            mutated_paths.append(dst)
            logger.debug(f"FakeFS: mv {src} → {dst}")

        # ---- rm / rmdir ----------------------------------------------------
        for m in re.finditer(r"\brm\b(?:\s+-[rfRF]+)?\s+([^\s;&|]+)", cmd):
            path = self._resolve(m.group(1), cwd=cwd)
            self._files.pop(path, None)
            self._dirs.discard(path)
            logger.debug(f"FakeFS: rm {path}")

        # ---- wget -O / curl -o  (downloaded file) --------------------------
        m = re.search(r"\bwget\b.*-O\s+(\S+)", cmd) or re.search(
            r"\bcurl\b.*-o\s+(\S+)", cmd
        )
        if m:
            path = self._resolve(m.group(1), cwd=cwd)
            # Store a placeholder so the file "exists"; real content unknown
            url_m = re.search(r"https?://\S+", cmd)
            stub = f"# Downloaded from {url_m.group(0) if url_m else 'remote'}\n"
            self._files[path] = FakeFile(content=stub, is_executable=True)
            mutated_paths.append(path)
            logger.debug(f"FakeFS: download → {path}")

        # ---- chmod +x -------------------------------------------------------
        m = re.search(r"\bchmod\b[^+]*\+x\s+(\S+)", cmd)
        if m:
            path = self._resolve(m.group(1), cwd=cwd)
            if path in self._files:
                self._files[path].is_executable = True
            else:
                self._files[path] = FakeFile(is_executable=True)
            mutated_paths.append(path)

        return mutated_paths

    def build_context_block(self) -> str:
        """
        Return a compact text block for injection into the LLM system prompt.
        Returns an empty string when no attacker-created artefacts exist.
        """
        if not self._files and not self._dirs:
            return ""

        lines: List[str] = [
            "ATTACKER SESSION FILESYSTEM STATE (files and directories created this session):",
        ]

        if self._dirs:
            lines.append("Directories: " + ", ".join(sorted(self._dirs)))

        for path, ffile in sorted(self._files.items()):
            perm = "-rwxr-xr-x" if ffile.is_executable else "-rw-r--r--"
            if ffile.content:
                content_preview = ffile.content.replace("\n", "\\n")
                if len(content_preview) > 120:
                    content_preview = content_preview[:120] + "…"
                lines.append(f"  {perm}  {path}  [content: {content_preview!r}]")
            else:
                lines.append(f"  {perm}  {path}  [empty]")

        lines.append(
            "When the attacker accesses these paths, return the stored content exactly."
        )
        return "\n".join(lines)

    def file_exists(self, path: str, cwd: str = "/home/ubuntu") -> bool:
        return self._resolve(path, cwd=cwd) in self._files

    def get_content(self, path: str, cwd: str = "/home/ubuntu") -> Optional[str]:
        f = self._files.get(self._resolve(path, cwd=cwd))
        return f.content if f else None

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _resolve(self, path: str, cwd: str = "/home/ubuntu") -> str:
        """Normalise a path string (strip quotes, trailing slash) against current working directory."""
        path = path.strip("'\"").rstrip("/")
        if not path:
            return cwd
        if not path.startswith("/"):
            path = cwd.rstrip("/") + "/" + path
        # Collapse // and simple /./ segments
        parts = []
        for seg in path.split("/"):
            if seg in ("", "."):
                continue
            if seg == "..":
                if parts:
                    parts.pop()
            else:
                parts.append(seg)
        return "/" + "/".join(parts) if parts else "/"

    @staticmethod
    def _extract_redirect_content(cmd: str, operator: str) -> str:
        """
        Try to extract what is being written.  Only handles common idioms;
        returns empty string when content cannot be determined.
        """
        # echo "…" > file  OR  echo '…' > file  OR  echo literal > file
        m = re.match(
            r"""\becho\b\s+(?P<q>['"]?)(?P<txt>.*?)(?P=q)\s*""" + re.escape(operator),
            cmd,
        )
        if m:
            return m.group("txt").replace("\\n", "\n")

        # printf "…" > file
        m = re.match(
            r"""\bprintf\b\s+(?P<q>['"]?)(?P<txt>.*?)(?P=q)\s*""" + re.escape(operator),
            cmd,
        )
        if m:
            return m.group("txt").replace("\\n", "\n")

        return ""
