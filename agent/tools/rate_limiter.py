"""Token-bucket rate limiter for HTTP calls."""

import logging
import time
import threading

logger = logging.getLogger(__name__)


class RateLimiter:
    def __init__(self, requests_per_second: float = 5.0):
        self._base_rate = requests_per_second
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.max_tokens = requests_per_second
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def configure(self, requests_per_second: float) -> None:
        """Update the rate limit (called on startup from config)."""
        with self._lock:
            self._base_rate = requests_per_second
            self.rate = requests_per_second
            self.max_tokens = requests_per_second
            self.tokens = min(self.tokens, requests_per_second)

    def wait(self):
        """Block until a token is available."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last
                self._last = now
                self.tokens = min(self.max_tokens, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
            time.sleep(0.05)

    def on_rate_limited(self) -> None:
        """Reduce rate by 75% session-wide when any tool receives a 429."""
        with self._lock:
            new_rate = max(0.1, self.rate * 0.25)
            if new_rate < self.rate:
                self.rate = new_rate
                self.max_tokens = new_rate
                logger.warning(
                    "Rate limited — global request rate reduced to %.2f req/s", new_rate
                )

    def reset_rate(self) -> None:
        """Restore the original configured rate."""
        with self._lock:
            self.rate = self._base_rate
            self.max_tokens = self._base_rate
            logger.info("Rate limiter reset to %.2f req/s", self._base_rate)


limiter = RateLimiter()
