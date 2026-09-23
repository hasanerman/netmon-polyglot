import random
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]

from conftest import normal_flows, scan_flows  # noqa: E402

from analytics.config import Config  # noqa: E402
from analytics.features import host_features  # noqa: E402
from analytics.model import AnomalyModel  # noqa: E402

FLOWS_PER_BATCH = 5_000
ROUNDS = 40
READY_TIMEOUT = 60.0


def peak_rss_mb() -> float:
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        class Counters(ctypes.Structure):
            _fields_ = [
                ("cb", wintypes.DWORD),
                ("PageFaultCount", wintypes.DWORD),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        c = Counters()
        c.cb = ctypes.sizeof(c)
        psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(c), c.cb)
        return c.PeakWorkingSetSize / 2**20
    import resource

    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def batch(rng: random.Random) -> list:  # type: ignore[type-arg]
    flows = []
    while len(flows) < FLOWS_PER_BATCH - 250:
        flows.extend(normal_flows(rng))
    return flows[: FLOWS_PER_BATCH - 250] + scan_flows(1, 250)


def main() -> int:
    rng = random.Random(1)
    model = AnomalyModel(Config(warmup_samples=200, warmup_batches=5))
    try:
        for _ in range(8):
            m = host_features(normal_flows(rng))
            model.process(m.hosts, m.values)
        if not model.wait_until_ready(READY_TIMEOUT):
            print("model did not become ready", file=sys.stderr)
            return 1

        batches = [batch(rng) for _ in range(ROUNDS)]
        started = time.perf_counter()
        for flows in batches:
            m = host_features(flows)
            model.process(m.hosts, m.values)
        elapsed = time.perf_counter() - started
        rate = ROUNDS * FLOWS_PER_BATCH / elapsed
        per_batch_ms = elapsed / ROUNDS * 1000
        peak = peak_rss_mb()
        print(f"python scoring         : {rate:,.0f} flows/s, {per_batch_ms:.1f} ms per batch, peak {peak:.0f} MB")
        return 0
    finally:
        model.close()


if __name__ == "__main__":
    sys.exit(main())
