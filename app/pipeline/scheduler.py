from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.schedulers.base import SchedulerNotRunningError
from loguru import logger


class SyncScheduler:
    """Manages periodic sync jobs using APScheduler."""

    def __init__(self, sync_func, interval_minutes: int = 60):
        self.scheduler = BackgroundScheduler()
        self.sync_func = sync_func
        self.interval_minutes = interval_minutes
        self._paused = False
        self._is_running = False

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def is_running(self) -> bool:
        return self._is_running

    def start(self, run_immediately: bool = True):
        """Start the scheduler."""
        self.scheduler.add_job(
            self._run,
            IntervalTrigger(minutes=self.interval_minutes),
            id="sync_job",
            name="Vulnerability Sync",
            replace_existing=True,
        )
        self.scheduler.start()
        self._is_running = True
        logger.info(f"Scheduler started (interval: {self.interval_minutes}min)")

        if run_immediately:
            self.run_now()

    def run_now(self):
        """Trigger a sync immediately."""
        logger.info("Manual sync triggered")
        try:
            self.sync_func()
        except Exception as e:
            logger.error(f"Manual sync failed: {e}")

    def _run(self):
        if self._paused:
            logger.debug("Sync skipped (paused)")
            return
        try:
            self.sync_func()
        except Exception as e:
            logger.error(f"Scheduled sync failed: {e}")

    def pause(self):
        self._paused = True
        logger.info("Sync paused")

    def resume(self):
        self._paused = False
        logger.info("Sync resumed")

    def update_interval(self, interval_minutes: int):
        """Update the scheduler interval in-place."""
        self.interval_minutes = interval_minutes
        if not self._is_running:
            return
        try:
            self.scheduler.reschedule_job(
                "sync_job",
                trigger=IntervalTrigger(minutes=interval_minutes),
            )
            logger.info(f"Scheduler interval updated: {interval_minutes}min")
        except Exception as e:
            logger.warning(f"Failed to reschedule sync job: {e}")

    def shutdown(self):
        """Idempotent shutdown, safe to call multiple times."""
        if not self._is_running:
            return
        try:
            self.scheduler.shutdown(wait=False)
        except SchedulerNotRunningError:
            pass
        finally:
            self._is_running = False
        logger.info("Scheduler shut down")
