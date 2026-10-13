#!/usr/bin/env python3
"""
HorusEye — performance benchmark.

Measures each pipeline stage on synthetic domains of increasing size, so
performance claims are backed by numbers rather than guesses. Deterministic
(fixed seed); no network, no external tools, no real data.

    python scripts/benchmark.py            # default sizes
    python scripts/benchmark.py 500 5000   # custom user counts
"""
import gc
import sys
import time
import tracemalloc
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from horuseye.core.attack_detector import AttackDetector      # noqa: E402
from horuseye.core.graph import AttackGraph                    # noqa: E402
from horuseye.core.knowledge import enrich                     # noqa: E402
from horuseye.core.path_scorer import PathScorer               # noqa: E402
from horuseye.reports.report_generator import ReportGenerator  # noqa: E402
from horuseye.synthetic import generate_domain                 # noqa: E402


def _time(fn):
    gc.collect()
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1000.0  # ms


def bench(n_users: int) -> dict:
    computers = max(10, n_users // 5)
    groups = max(5, n_users // 20)
    tracemalloc.start()
    data, _ = generate_domain(seed=1, users=n_users, computers=computers, groups=groups)

    findings, t_detect = _time(lambda: AttackDetector(data).detect_all())
    scored, t_score = _time(lambda: PathScorer().score(findings))
    _, t_enrich = _time(lambda: enrich(scored))
    _, t_graph = _time(lambda: AttackGraph(data).shortest_paths(max_paths=5))

    import tempfile, os

    class _Quiet:
        def print(self, *a, **k):  # swallow the reporter's status line
            pass

    fd, path = tempfile.mkstemp(suffix=".html"); os.close(fd)
    rep = ReportGenerator(scored, data, console=_Quiet(), generated_at="2026-01-01 00:00:00")
    _, t_report = _time(lambda: rep.export_html(path))
    os.unlink(path)

    peak = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
    tracemalloc.stop()
    return {"users": n_users, "acls": len(data["acls"]), "findings": len(findings),
            "detect": t_detect, "score": t_score, "enrich": t_enrich,
            "graph": t_graph, "report": t_report, "peak_mb": peak}


def main():
    sizes = [int(a) for a in sys.argv[1:]] or [100, 1000, 5000, 20000]
    rows = [bench(n) for n in sizes]
    cols = ["users", "acls", "findings", "detect", "score", "enrich", "graph", "report", "peak_mb"]
    hdr = f"{'users':>8} {'acls':>8} {'finds':>6} {'detect':>9} {'score':>8} " \
          f"{'enrich':>8} {'graph':>9} {'report':>9} {'peakMB':>8}"
    print(hdr); print("-" * len(hdr))
    for r in rows:
        print(f"{r['users']:>8} {r['acls']:>8} {r['findings']:>6} "
              f"{r['detect']:>8.1f}m {r['score']:>7.1f}m {r['enrich']:>7.1f}m "
              f"{r['graph']:>8.1f}m {r['report']:>8.1f}m {r['peak_mb']:>8.1f}")
    print("\n(times in ms; peak is tracemalloc peak during the run)")


if __name__ == "__main__":
    main()
