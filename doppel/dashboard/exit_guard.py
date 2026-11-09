import os
import signal
import time

import uvicorn

CONFIRM_WINDOW_SECONDS = 10.0


class ConfirmingServer(uvicorn.Server):
    """Asks for a second Ctrl+C before quitting would interrupt work on the model.

    A prompt that waits for input would freeze the event loop, and with it every
    live attacker session, so the confirmation is a repeated key press.
    """

    def __init__(self, config: uvicorn.Config, controller):
        super().__init__(config)
        self.controller = controller
        self._warned_at = None

    def handle_exit(self, sig, frame):
        if sig == signal.SIGINT and not self.should_exit:
            now = time.monotonic()
            confirmed = self._warned_at is not None and now - self._warned_at <= CONFIRM_WINDOW_SECONDS
            busy = self.controller.model_busy_work(stopping=True)
            if busy and not confirmed:
                self._warned_at = now
                os.write(2, (f"\nQuitting will interrupt: {', '.join(busy)}.\n"
                             f"Press Ctrl+C again within {CONFIRM_WINDOW_SECONDS:.0f} seconds to quit anyway.\n").encode())
                return
        super().handle_exit(sig, frame)
