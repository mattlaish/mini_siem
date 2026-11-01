# Benchmark runtime reference

import time

def measure(operation):
    start = time.time()
    result = operation()
    elapsed = time.time() - start

    return {
        "duration_seconds": elapsed,
        "result": result,
    }
