"""Background analysis gives way to terminal requests."""
import asyncio
import time

from doppel.ai.background_queue import BackgroundQueue


def test_terminal_request_interrupts_and_requeues_the_running_job():
    async def scenario():
        q = BackgroundQueue(idle_seconds=0.2)
        starts, events = [], []

        async def job():
            starts.append(time.monotonic())
            await asyncio.sleep(0.3)
            return "tagged"

        waiter = asyncio.create_task(q.submit("tagging", "s1", job))
        await asyncio.sleep(0.05)
        assert q.status()["running"] == "tagging"

        async with q.terminal():
            events.append("terminal")
            await asyncio.sleep(0.1)
            assert q.status()["running"] is None  # stopped for the terminal
            assert q.status()["queued"] == 1
        assert await asyncio.wait_for(waiter, 3) == "tagged"
        return starts, q

    starts, q = asyncio.run(scenario())
    assert len(starts) == 2  # run again from the start
    assert starts[1] - starts[0] >= 0.3  # 0.1 s terminal + 0.2 s idle time
    assert q.status()["queued"] == 0


def test_jobs_wait_for_idle_time_unless_run_now():
    async def scenario(force):
        q = BackgroundQueue(idle_seconds=5)
        async with q.terminal():
            pass
        t = time.monotonic()
        waiter = asyncio.create_task(q.submit("report", "s1", lambda: asyncio.sleep(0, result="done")))
        await asyncio.sleep(0.1)
        if not force:
            assert not waiter.done()
            assert q.status() | {"sessions": None} == q.status() | {"sessions": None}
            assert q.pending_for("s1") == {"reports": 1, "tagging": 0}
            await q.shutdown()
            return None
        q.run_now()
        assert await asyncio.wait_for(waiter, 2) == "done"
        return time.monotonic() - t

    assert asyncio.run(scenario(force=False)) is None
    assert asyncio.run(scenario(force=True)) < 1


def test_jobs_run_one_at_a_time_in_order():
    async def scenario():
        q = BackgroundQueue(idle_seconds=0)
        order, running = [], []

        def make(i):
            async def job():
                running.append(i)
                assert len(running) == 1
                await asyncio.sleep(0.02)
                order.append(i)
                running.remove(i)
                return i
            return job

        return await asyncio.gather(*(q.submit("tagging", "s", make(i)) for i in range(4))), order

    results, order = asyncio.run(scenario())
    assert results == [0, 1, 2, 3] and order == [0, 1, 2, 3]


def test_disabled_queue_runs_jobs_directly():
    async def scenario():
        q = BackgroundQueue(idle_seconds=60)
        q.enabled = False
        async with q.terminal():
            pass
        return await asyncio.wait_for(q.submit("report", "s", lambda: asyncio.sleep(0, result=7)), 1)

    assert asyncio.run(scenario()) == 7


def test_job_errors_reach_the_caller():
    async def scenario():
        q = BackgroundQueue(idle_seconds=0)

        async def bad():
            raise ValueError("model said no")

        try:
            await q.submit("tagging", "s", bad)
        except ValueError as e:
            return str(e)

    assert asyncio.run(scenario()) == "model said no"
