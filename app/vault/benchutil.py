"""Shared helpers for the benchmark tools: the `bench_crypto` management command and
`scripts/benchmark.py`. Deliberately has NO Django imports so the standalone script can use it
(it adds app/ to sys.path) without Django being installed.

Conventions (state them in the report):
  * Sizes are DECIMAL: 1 MB = 1,000,000 bytes, 1 GB = 1,000,000,000 bytes (the app's limit is
    1 GiB = 1,073,741,824 bytes, so a 1 GB test file stays under it).
  * Standard deviation is the SAMPLE standard deviation (n-1) over the runs.
  * Throughput is computed per run (size / time) and then averaged, not derived from the mean time.
"""
from __future__ import annotations

import csv
import datetime
import os
import platform
import re
import statistics
import subprocess
import sys

DEFAULT_SIZES = "10MB,100MB,500MB,1GB"
_UNITS = {"KB": 10**3, "MB": 10**6, "GB": 10**9}

CSV_FIELDS = [
    "timestamp_utc", "environment", "target",
    "cpu_model", "logical_cores", "physical_cores", "ram_gib", "os", "python", "cryptography", "openssl",
    "size_label", "size_bytes", "operation", "runs",
    "mean_s", "stdev_s", "mean_MBps", "stdev_MBps", "run_times_s",
]


def parse_sizes(spec: str) -> list[tuple[str, int]]:
    """'10MB,100MB,1GB' -> [('10MB', 10000000), ...]. Units: KB, MB, GB (decimal)."""
    out = []
    for part in spec.split(","):
        part = part.strip().upper()
        if not part:
            continue
        m = re.fullmatch(r"(\d+)\s*(KB|MB|GB)", part)
        if not m:
            raise ValueError(f"Bad size '{part}': use e.g. 10MB, 100MB, 500MB, 1GB")
        out.append((f"{m.group(1)}{m.group(2)}", int(m.group(1)) * _UNITS[m.group(2)]))
    if not out:
        raise ValueError("No sizes given")
    return out


# --------------------------------------------------------------------------- statistics / CSV
def summarize(times: list[float], size_bytes: int) -> dict:
    sd = statistics.stdev(times) if len(times) > 1 else 0.0
    speeds = [size_bytes / 1e6 / t for t in times]
    return {
        "runs": len(times),
        "mean_s": statistics.fmean(times),
        "stdev_s": sd,
        "mean_MBps": statistics.fmean(speeds),
        "stdev_MBps": statistics.stdev(speeds) if len(speeds) > 1 else 0.0,
        "run_times_s": ";".join(f"{t:.6f}" for t in times),
    }


def make_row(info: dict, environment: str, target: str, size_label: str, size_bytes: int,
             operation: str, times: list[float]) -> dict:
    row = {
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "environment": environment, "target": target,
        "cpu_model": info["cpu_model"], "logical_cores": info["logical_cores"],
        "physical_cores": info["physical_cores"] if info["physical_cores"] is not None else "",
        "ram_gib": info["ram_gib"] if info["ram_gib"] is not None else "",
        "os": info["os"], "python": info["python"], "cryptography": info["cryptography"], "openssl": info["openssl"],
        "size_label": size_label, "size_bytes": size_bytes, "operation": operation,
    }
    row.update(summarize(times, size_bytes))
    return row


def write_csv(dest, rows: list[dict]) -> None:
    """dest: a path, or '-' for stdout."""
    def fmt(r):
        return {k: (f"{v:.6f}" if isinstance(v, float) else v) for k, v in r.items()}
    if dest == "-":
        w = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(fmt(r) for r in rows)
        sys.stdout.flush()
        return
    os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
    with open(dest, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        w.writerows(fmt(r) for r in rows)


# --------------------------------------------------------------------------- machine info
def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def _lscpu() -> dict:
    out = {}
    for line in _run(["lscpu"]).splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _openssl_version() -> str:
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
        return backend.openssl_version_text()
    except Exception:
        import ssl
        return f"{ssl.OPENSSL_VERSION} (Python's, not cryptography's)"


def system_info() -> dict:
    """CPU model, core counts and RAM of the machine this runs on (no third-party deps)."""
    system = platform.system()
    cpu, physical, ram = "", None, None
    logical = os.cpu_count() or 0

    if system == "Darwin":
        cpu = _run(["sysctl", "-n", "machdep.cpu.brand_string"])
        p = _run(["sysctl", "-n", "hw.physicalcpu"])
        physical = int(p) if p.isdigit() else None
        m = _run(["sysctl", "-n", "hw.memsize"])
        ram = int(m) / 2**30 if m.isdigit() else None
    elif system == "Linux":
        lscpu = _lscpu()
        try:
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.lower().startswith("model name"):
                        cpu = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
        if not cpu or cpu == "-":
            cpu = lscpu.get("Model name", "")
        if not cpu or cpu == "-":      # ARM VMs often expose only vendor/part ids: report those
            ids = {}
            try:
                with open("/proc/cpuinfo") as fh:
                    for line in fh:
                        if line.startswith(("CPU implementer", "CPU part")) and ":" in line:
                            k, v = line.split(":", 1)
                            ids.setdefault(k.strip(), v.strip())
            except OSError:
                pass
            cpu = " ".join(x for x in (
                lscpu.get("Vendor ID"), lscpu.get("Architecture") or platform.machine(),
                f"implementer {ids['CPU implementer']} part {ids['CPU part']}" if len(ids) == 2 else "",
                "(set BENCH_CPU_MODEL to name it)") if x)
        if lscpu.get("Core(s) per socket", "").isdigit() and lscpu.get("Socket(s)", "").isdigit():
            physical = int(lscpu["Core(s) per socket"]) * int(lscpu["Socket(s)"])
        try:
            with open("/proc/meminfo") as fh:
                for line in fh:
                    if line.startswith("MemTotal:"):
                        ram = int(line.split()[1]) / 2**20      # kB -> GiB
                        break
        except (OSError, ValueError):
            pass
    cpu = os.environ.get("BENCH_CPU_MODEL") or cpu or platform.processor() or platform.machine() or "unknown"

    try:
        import cryptography
        crypto_ver = cryptography.__version__
    except Exception:
        crypto_ver = "n/a"
    return {
        "cpu_model": cpu, "logical_cores": logical, "physical_cores": physical,
        "ram_gib": round(ram, 1) if ram is not None else None,
        "os": platform.platform(), "python": platform.python_version(),
        "cryptography": crypto_ver, "openssl": _openssl_version() if crypto_ver != "n/a" else "n/a",
    }


def format_system_info(info: dict) -> str:
    phys = f" ({info['physical_cores']} physical)" if info["physical_cores"] else ""
    ram = f"{info['ram_gib']} GiB" if info["ram_gib"] is not None else "unknown"
    return (
        f"  CPU model : {info['cpu_model']}\n"
        f"  CPU cores : {info['logical_cores']} logical{phys}\n"
        f"  RAM       : {ram}\n"
        f"  OS        : {info['os']}\n"
        f"  Python    : {info['python']}   cryptography {info['cryptography']}   {info['openssl']}"
    )
