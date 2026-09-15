# Benchmark runner baseline

import time

def run_benchmark(operation):
    start = time.perf_counter()
    result = operation()
    elapsed = time.perf_counter() - start
    return {
        "duration_seconds": elapsed,
        "result": result,
    }
