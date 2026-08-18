import threading
import time


def run_benchmark(resolver, target_name="example.com.", qtype="A", total_queries=500, concurrency=20):
    """Fires `total_queries` real queries at the live resolver (in-process,
    same code path a real UDP query takes) across `concurrency` worker
    threads, and reports QPS + latency percentiles. The first query
    populates the cache; the rest mostly measure cache-hit speed unless
    the target isn't cacheable -- both numbers are useful, so we report
    the cache hit ratio observed during the run alongside timing."""
    latencies = []
    lock = threading.Lock()
    cache_before = resolver.cache.stats()

    def worker(n):
        client_ip = "127.0.0.100"
        for _ in range(n):
            t0 = time.time()
            resolver.resolve(target_name, qtype, client_ip)
            elapsed_ms = (time.time() - t0) * 1000
            with lock:
                latencies.append(elapsed_ms)

    per_thread = total_queries // concurrency
    remainder = total_queries % concurrency
    threads = []
    start = time.time()
    for i in range(concurrency):
        n = per_thread + (1 if i < remainder else 0)
        if n == 0:
            continue
        t = threading.Thread(target=worker, args=(n,))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    duration = time.time() - start

    latencies.sort()
    n = len(latencies)
    avg = sum(latencies) / n if n else 0
    p95 = latencies[int(n * 0.95) - 1] if n else 0
    p99 = latencies[int(n * 0.99) - 1] if n else 0
    cache_after = resolver.cache.stats()
    hits_during = cache_after["hits"] - cache_before["hits"]
    misses_during = cache_after["misses"] - cache_before["misses"]
    total_during = hits_during + misses_during
    cache_hit_ratio = round(100 * hits_during / total_during, 1) if total_during else 0.0

    return {
        "queries": n, "duration_sec": round(duration, 3),
        "qps": round(n / duration, 1) if duration > 0 else 0,
        "avg_latency_ms": round(avg, 3), "p95_latency_ms": round(p95, 3), "p99_latency_ms": round(p99, 3),
        "cache_hit_ratio": cache_hit_ratio,
    }


def recommendations(result):
    tips = []
    if result["avg_latency_ms"] > 20:
        tips.append("Average latency is elevated for what should mostly be cache/local answers — check disk I/O and whether SQLite is on slow storage.")
    if result["cache_hit_ratio"] < 50:
        tips.append("Low cache hit ratio during the run — expected for a fresh cache or highly varied query set; re-run to see steady-state performance.")
    if result["qps"] < 200:
        tips.append("Throughput is below what a single-core Python resolver typically achieves — check CPU contention from other processes.")
    if not tips:
        tips.append("Performance looks healthy for the current load.")
    return tips
