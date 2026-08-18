"""Thread-safe in-memory DNS cache with TTL expiry, negative caching,
and hit/miss statistics for the monitoring dashboard.

Also tracks whether each cached answer originated from this server's
own authoritative data or from a forwarded upstream response -- this
is what lets a cache *hit* still set the DNS header's AA (Authoritative
Answer) bit correctly. A cached authoritative answer is still
authoritative; a cached forwarded answer never is, no matter how it
was served."""
import threading
import time


class DNSCache:
    def __init__(self, max_entries=50000, negative_ttl=60):
        self._store = {}   # key -> (expires_at, records_or_None, rcode, authority, origin)
        self._lock = threading.Lock()
        self.max_entries = max_entries
        self.negative_ttl = negative_ttl
        self.hits = 0
        self.misses = 0

    @staticmethod
    def _key(name, rtype):
        return (name.rstrip(".").lower(), rtype)

    def get(self, name, rtype):
        key = self._key(name, rtype)
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                self.misses += 1
                return None
            expires_at, records, rcode, authority, origin = entry
            if time.time() > expires_at:
                del self._store[key]
                self.misses += 1
                return None
            self.hits += 1
            remaining = int(expires_at - time.time())
            return {"records": records, "rcode": rcode, "ttl_remaining": max(remaining, 0),
                    "authority": authority, "origin": origin}

    def set(self, name, rtype, records, rcode=0, ttl=None, authority=None, origin="forward"):
        with self._lock:
            if len(self._store) >= self.max_entries:
                # evict ~oldest 5% (simple approximation, avoids unbounded growth)
                for k in list(self._store.keys())[: max(1, self.max_entries // 20)]:
                    del self._store[k]
            if records:
                effective_ttl = ttl if ttl is not None else min((r.ttl for r in records), default=300)
            else:
                effective_ttl = self.negative_ttl
            self._store[self._key(name, rtype)] = (time.time() + effective_ttl, records, rcode, authority or [], origin)

    def clear(self):
        with self._lock:
            self._store.clear()
            self.hits = 0
            self.misses = 0

    def stats(self):
        with self._lock:
            total = self.hits + self.misses
            return {
                "entries": len(self._store),
                "hits": self.hits,
                "misses": self.misses,
                "hit_ratio": round(100 * self.hits / total, 1) if total else 0.0,
            }

    def inspect(self, limit=200):
        with self._lock:
            now = time.time()
            rows = []
            for (name, rtype), (expires_at, records, rcode, authority, origin) in list(self._store.items())[:limit]:
                rows.append({
                    "name": name, "rtype": rtype,
                    "ttl_remaining": max(int(expires_at - now), 0),
                    "answers": len(records) if records else 0,
                    "rcode": rcode, "origin": origin,
                })
            return rows
