import pytest
import threading
import time
from unittest.mock import MagicMock
from app.pipeline.scheduler import SyncScheduler


class TestScheduler:
    def test_interval_updated_before_start(self):
        """update_interval should change attr without touching scheduler."""
        callback = MagicMock()
        s = SyncScheduler(callback, interval_minutes=60)
        s.update_interval(120)
        assert s.interval_minutes == 120

    def test_interval_updated_while_running(self):
        """update_interval should reschedule the job while running."""
        callback = MagicMock()
        s = SyncScheduler(callback, interval_minutes=60)
        s.start(run_immediately=False)

        s.update_interval(120)
        assert s.interval_minutes == 120

        # Verify job exists with new interval
        job = s.scheduler.get_job("sync_job")
        assert job is not None
        assert job.trigger.interval.total_seconds() == 120 * 60

        s.shutdown()

    def test_run_now_triggers_callback(self):
        callback = MagicMock()
        s = SyncScheduler(callback, interval_minutes=60)
        s.run_now()
        callback.assert_called_once()

    def test_pause_prevents_run(self):
        callback = MagicMock()
        s = SyncScheduler(callback, interval_minutes=60)
        s.pause()
        s._run()
        callback.assert_not_called()

    def test_shutdown_idempotent(self):
        callback = MagicMock()
        s = SyncScheduler(callback, interval_minutes=60)
        s.shutdown()
        s.shutdown()  # should not raise


class TestSyncLock:
    def test_concurrent_calls_blocked(self):
        """Second call while lock held should set pending, not run."""
        lock = threading.Lock()
        pending = [False]
        run_count = [0]

        def work():
            run_count[0] += 1
            time.sleep(0.2)

        def run_sync_locked():
            if not lock.acquire(blocking=False):
                pending[0] = True
                return
            try:
                work()
            finally:
                lock.release()

        threads = []
        for _ in range(3):
            t = threading.Thread(target=run_sync_locked)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert run_count[0] == 1  # only first call executed
        assert pending[0] is True  # subsequent calls blocked
