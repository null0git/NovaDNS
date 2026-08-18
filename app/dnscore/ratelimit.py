"""Simple in-memory token-bucket rate limiter, keyed by client IP.
Used to protect the DNS server from query floods (misbehaving devices,
open-resolver abuse, basic DoS) without needing an external dependency."""
import threading
import time


class RateLimiter:
    def __init__(self, capacity=100, refill_per_sec=50):
        self.capacity = capacity
        self.refill_per_sec = refill_per_sec
        self._buckets = {}  # ip -> [tokens, last_refill_ts]
        self._lock = threading.Lock()

    def configure(self, capacity, refill_per_sec):
        with self._lock:
            self.capacity = capacity
            self.refill_per_sec = refill_per_sec

    def allow(self, client_ip):
        if self.refill_per_sec <= 0:
            return True  # 0/disabled = unlimited
        now = time.time()
        with self._lock:
            bucket = self._buckets.get(client_ip)
            if bucket is None:
                bucket = [self.capacity - 1, now]
                self._buckets[client_ip] = bucket
                return True
            tokens, last = bucket
            tokens = min(self.capacity, tokens + (now - last) * self.refill_per_sec)
            if tokens < 1:
                bucket[0] = tokens
                bucket[1] = now
                return False
            bucket[0] = tokens - 1
            bucket[1] = now
            return True

    def prune(self, max_entries=20000):
        with self._lock:
            if len(self._buckets) > max_entries:
                # drop the oldest half by last-seen time
                items = sorted(self._buckets.items(), key=lambda kv: kv[1][1])
                for ip, _ in items[: len(items) // 2]:
                    del self._buckets[ip]
