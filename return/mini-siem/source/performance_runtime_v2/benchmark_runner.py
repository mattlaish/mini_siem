"""Compatibility entry point for the measured qualification runner."""
from __future__ import annotations

import time


def run_benchmark(operation):
    start = time.perf_counter()
    result = operation()
    elapsed = time.perf_counter() - start
    return {"duration_seconds": elapsed, "result": result}


def main():
    from performance_runtime_v2.qualification_runner import main as qualification_main
    return qualification_main()


if __name__ == "__main__":
    raise SystemExit(main())
