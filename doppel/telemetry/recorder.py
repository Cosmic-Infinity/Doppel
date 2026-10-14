"""
Asciinema Recorder Stub
=======================
Non-blocking stub implementation for backward compatibility.
Terminal streams are rendered directly over WebSockets and persisted to SQLite.
"""
from typing import Optional, List, Dict, Any


class NoOpSessionRecording:
    def __init__(self, *args, **kwargs):
        pass

    def record_output(self, text: str):
        pass

    def to_cast(self) -> str:
        return ""

    def save_to_disk(self) -> Optional[str]:
        return None


class NoOpAsciinemaRecorder:
    def __init__(self, *args, **kwargs):
        pass

    def start_recording(self, *args, **kwargs) -> NoOpSessionRecording:
        return NoOpSessionRecording()

    def record_chunk(self, session_id: str, text: str):
        pass

    def close_recording(self, session_id: str) -> Optional[str]:
        return None

    def get_cast(self, session_id: str) -> Optional[str]:
        return None

    def synthesize_cast_from_history(self, *args, **kwargs) -> str:
        return ""


_RECORDER_INSTANCE = NoOpAsciinemaRecorder()


def get_recorder() -> NoOpAsciinemaRecorder:
    return _RECORDER_INSTANCE
