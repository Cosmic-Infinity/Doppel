"""
Background model work (ATT&CK tagging, incident reports) that gives way to the terminal.

A local model server such as Ollama answers one request at a time per model, so
a long analysis call makes the attacker's next command wait behind it. Here the
terminal always wins: a terminal request cancels the running background job
(closing its HTTP request stops generation on the server) and the job goes back
to the front of the queue. Queued jobs run one at a time once the terminal has
been quiet for `idle_seconds`, or straight away after run_now().
"""

import asyncio
import contextlib
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Deque, Dict, Optional

logger = logging.getLogger("doppel.ai.background_queue")


@dataclass
class _Job:
    kind: str  # "tagging" or "report"
    session_id: str
    factory: Callable[[], Awaitable[Any]]
    future: "asyncio.Future[Any]"
    interruptions: int = 0
    queued_at: float = field(default_factory=time.time)


class BackgroundQueue:
    def __init__(self, idle_seconds: float = 20.0, on_change: Optional[Callable[[Dict[str, Any]], None]] = None):
        self.idle_seconds = max(0.0, float(idle_seconds))
        # Disabled (mock mode): jobs run at once, as if there were no queue
        self.enabled = True
        self.on_change = on_change
        self._jobs: Deque[_Job] = deque()
        self._running: Optional[_Job] = None
        self._running_task: Optional[asyncio.Task] = None
        self._terminal_active = 0
        self._last_terminal = 0.0  # monotonic; 0 means the terminal has been quiet since start
        self._forced = False
        self._wake: Optional[asyncio.Event] = None
        self._worker: Optional[asyncio.Task] = None

    # ------------------------------------------------------------ public API

    async def submit(self, kind: str, session_id: str, factory: Callable[[], Awaitable[Any]]) -> Any:
        """Queue a job and wait for its result. `factory` is called again if the job is interrupted."""
        if not self.enabled:
            return await factory()
        self._ensure_worker()
        job = _Job(kind=kind, session_id=session_id, factory=factory, future=asyncio.get_running_loop().create_future())
        self._jobs.append(job)
        self._changed()
        self._wake.set()
        return await job.future

    @contextlib.asynccontextmanager
    async def terminal(self):
        """Wrap a terminal (attacker-facing) model request: background work stops for it."""
        self._terminal_active += 1
        if self._running_task and not self._running_task.done():
            self._running.interruptions += 1
            logger.info(f"Interrupting background {self._running.kind} for a terminal request")
            self._running_task.cancel()
        try:
            yield
        finally:
            self._terminal_active -= 1
            self._last_terminal = time.monotonic()
            if self._wake:
                self._wake.set()

    def run_now(self):
        """Process the queue without waiting for idle time (terminal requests still come first)."""
        self._forced = True
        if self._wake:
            self._wake.set()
        self._changed()

    def status(self) -> Dict[str, Any]:
        pending = list(self._jobs)
        if self._running:
            pending.insert(0, self._running)
        return {
            "queued": len(pending),
            "running": self._running.kind if self._running else None,
            "running_session": self._running.session_id if self._running else None,
            "report_sessions": sorted({j.session_id for j in pending if j.kind == "report"}),
            "reports": sum(1 for j in pending if j.kind == "report"),
            "tagging": sum(1 for j in pending if j.kind == "tagging"),
            "sessions": sorted({j.session_id for j in pending}),
            "forced": self._forced,
            "idle_seconds": self.idle_seconds,
        }

    def pending_for(self, session_id: str) -> Dict[str, int]:
        jobs = list(self._jobs) + ([self._running] if self._running else [])
        mine = [j for j in jobs if j.session_id == session_id]
        return {
            "reports": sum(1 for j in mine if j.kind == "report"),
            "tagging": sum(1 for j in mine if j.kind == "tagging"),
        }

    async def shutdown(self):
        """Stop the worker; the running job and jobs still waiting are cancelled."""
        running, task = self._running, self._running_task
        if task and not task.done():
            task.cancel()
        if running and not running.future.done():
            running.future.cancel()
        if self._worker:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._worker
            self._worker = None
        while self._jobs:
            job = self._jobs.popleft()
            if not job.future.done():
                job.future.cancel()
        self._changed()

    # ------------------------------------------------------------- internals

    def _ensure_worker(self):
        if self._wake is None:
            self._wake = asyncio.Event()
        if self._worker is None or self._worker.done():
            self._worker = asyncio.create_task(self._run())

    def _changed(self):
        if self.on_change:
            try:
                self.on_change(self.status())
            except Exception as e:
                logger.debug(f"Queue status listener failed: {e}")

    async def _sleep_until_woken(self, timeout: Optional[float] = None):
        self._wake.clear()
        try:
            await asyncio.wait_for(self._wake.wait(), timeout)
        except asyncio.TimeoutError:
            pass

    async def _run(self):
        while True:
            if not self._jobs:
                if self._forced:
                    self._forced = False
                    self._changed()
                await self._sleep_until_woken()
                continue
            if self._terminal_active:
                await self._sleep_until_woken()
                continue
            if not self._forced and self._last_terminal:
                remaining = self.idle_seconds - (time.monotonic() - self._last_terminal)
                if remaining > 0:
                    await self._sleep_until_woken(remaining)
                    continue

            job = self._jobs.popleft()
            if job.future.done():  # the waiter went away
                continue
            self._running = job
            self._running_task = asyncio.create_task(job.factory())
            self._changed()
            try:
                await asyncio.wait({self._running_task})
            finally:
                task, self._running, self._running_task = self._running_task, None, None

            if task.cancelled():
                # Interrupted by a terminal request: first in line once the GPU is free again
                self._jobs.appendleft(job)
            elif task.exception() is not None:
                job.future.set_exception(task.exception())
            else:
                job.future.set_result(task.result())
            self._changed()
