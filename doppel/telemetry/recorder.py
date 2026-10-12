import json
import time
import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger("doppel.telemetry.recorder")


class SessionRecording:
    """Manages an active asciinema v2 recording buffer for a single session."""

    def __init__(
        self,
        session_id: str,
        width: int = 100,
        height: int = 30,
        title: Optional[str] = None,
        save_dir: str = "replays",
    ):
        self.session_id = session_id
        self.width = width
        self.height = height
        self.title = title or f"Doppel SSH Session {session_id[:8]}"
        self.start_time = time.time()
        self.save_dir = Path(save_dir)
        self.events: List[str] = []

        header = {
            "version": 2,
            "width": self.width,
            "height": self.height,
            "timestamp": int(self.start_time),
            "title": self.title,
            "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        }
        self.header_json = json.dumps(header)

    def record_output(self, text: str):
        """Append a terminal output chunk with relative timestamp."""
        if not text:
            return
        elapsed = round(time.time() - self.start_time, 4)
        event = json.dumps([elapsed, "o", text])
        self.events.append(event)

    def to_cast(self) -> str:
        """Produce the full v2 asciicast file content."""
        lines = [self.header_json] + self.events
        return "\n".join(lines) + "\n"

    def save_to_disk(self) -> Optional[Path]:
        """Save .cast file to disk for long-term replay storage."""
        try:
            self.save_dir.mkdir(parents=True, exist_ok=True)
            cast_path = self.save_dir / f"{self.session_id}.cast"
            cast_path.write_text(self.to_cast(), encoding="utf-8")
            return cast_path
        except Exception as e:
            logger.error(f"Failed to save asciinema recording to disk: {e}")
            return None


class AsciinemaRecorder:
    """Registry and coordinator for honeypot asciinema terminal session recordings."""

    def __init__(self, save_dir: str = "replays"):
        self.save_dir = Path(save_dir)
        self.save_dir.mkdir(parents=True, exist_ok=True)
        self._active_recordings: Dict[str, SessionRecording] = {}

    def start_recording(
        self,
        session_id: str,
        width: int = 100,
        height: int = 30,
        title: Optional[str] = None,
    ) -> SessionRecording:
        recording = SessionRecording(
            session_id=session_id,
            width=width,
            height=height,
            title=title,
            save_dir=str(self.save_dir),
        )
        self._active_recordings[session_id] = recording
        return recording

    def record_chunk(self, session_id: str, text: str):
        """Record raw text written to the attacker terminal."""
        rec = self._active_recordings.get(session_id)
        if rec:
            rec.record_output(text)

    def close_recording(self, session_id: str) -> Optional[str]:
        """Finalize and persist .cast file to disk."""
        rec = self._active_recordings.pop(session_id, None)
        if rec:
            saved = rec.save_to_disk()
            return str(saved) if saved else None
        return None

    def get_cast(self, session_id: str) -> Optional[str]:
        """Retrieve cast string from active buffer or persisted disk file."""
        # 1. Check active memory
        if session_id in self._active_recordings:
            return self._active_recordings[session_id].to_cast()

        # 2. Check disk file
        disk_file = self.save_dir / f"{session_id}.cast"
        if disk_file.exists():
            try:
                return disk_file.read_text(encoding="utf-8")
            except Exception as e:
                logger.error(f"Failed to read cast file {disk_file}: {e}")

        return None

    def synthesize_cast_from_history(
        self,
        session_id: str,
        commands: List[Dict[str, Any]],
        username: str = "ubuntu",
        hostname: str = "prod-api-node-01",
        motd: Optional[str] = None,
    ) -> str:
        """Synthesize a valid .cast file from historical DB commands if live recording was absent."""
        header = {
            "version": 2,
            "width": 100,
            "height": 30,
            "timestamp": int(time.time()),
            "title": f"Replay: {username}@{hostname} (Session {session_id[:8]})",
            "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
        }
        lines = [json.dumps(header)]

        cur_time = 0.5
        if motd:
            lines.append(json.dumps([cur_time, "o", motd.replace("\n", "\r\n") + "\r\n"]))
            cur_time += 1.0

        for cmd in commands:
            cwd = cmd.get("cwd", "/home/ubuntu")
            symbol = "#" if username == "root" else "$"
            prompt = f"{username}@{hostname}:{cwd}{symbol} "
            lines.append(json.dumps([round(cur_time, 2), "o", prompt]))
            cur_time += 0.4

            raw_cmd = cmd.get("command", "")
            # Simulate typing character by character
            for char in raw_cmd:
                cur_time += 0.05
                lines.append(json.dumps([round(cur_time, 2), "o", char]))

            cur_time += 0.2
            lines.append(json.dumps([round(cur_time, 2), "o", "\r\n"]))

            output = cmd.get("output", "")
            if output:
                cur_time += 0.3
                formatted = output.replace("\r\n", "\n").replace("\n", "\r\n").rstrip("\r\n") + "\r\n"
                lines.append(json.dumps([round(cur_time, 2), "o", formatted]))

            cur_time += 1.0

        # Return synthesized cast
        cast_content = "\n".join(lines) + "\n"
        # Save to disk so subsequent reads are cached
        try:
            (self.save_dir / f"{session_id}.cast").write_text(cast_content, encoding="utf-8")
        except Exception:
            pass
        return cast_content


_GLOBAL_RECORDER: Optional[AsciinemaRecorder] = None


def get_recorder() -> AsciinemaRecorder:
    global _GLOBAL_RECORDER
    if _GLOBAL_RECORDER is None:
        _GLOBAL_RECORDER = AsciinemaRecorder()
    return _GLOBAL_RECORDER
