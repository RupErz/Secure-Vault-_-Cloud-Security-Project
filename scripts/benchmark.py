#!/usr/bin/env python3
"""End-to-end benchmark of the deployed app (upload / download through Nginx + Gunicorn),
plus chart generation for the technical report.

  # 1) measure the app on the VM, run from your Mac (uses only the standard library)
  BENCH_PASSWORD='...' python3 scripts/benchmark.py run --base-url https://192.168.64.2 \
        --username benchuser --label vm

  # 2) after also running `manage.py bench_crypto` on the VM and on the Mac (see README):
  python3 scripts/benchmark.py plot --network bench_out/network_summary.csv \
        --crypto bench_out/crypto_vm.csv bench_out/crypto_physical.csv        # needs matplotlib

What `run` does, per size (10 MB, 100 MB, 500 MB, 1 GB = 1,000,000,000 bytes, all .txt so they
pass the type whitelist): generate the file once, then RUNS times:
    upload  (raw request body + X-CSRFToken + X-File-Name: exactly what upload.js does)
    download (SHA-256 of the received bytes must equal the original, else the run aborts)
    delete   (through the app, so no test data is left behind)
Timings are wall-clock from the first request byte to the last response byte. Local disk reads
(upload) and SHA-256 hashing (download) are measured and EXCLUDED, so the numbers are
network + Nginx + Django + crypto + server disk. TLS connect is done before the timer starts.

TLS verification is DISABLED in this script only (the VM uses a self-signed certificate).
Do not reuse this client for anything that handles real data.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import http.client
import json
import os
import re
import shutil
import ssl
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app"))
from vault.benchutil import (DEFAULT_SIZES, format_system_info, make_row, parse_sizes,  # noqa: E402
                             system_info, write_csv)

pc = time.perf_counter
BLOCK = 1024 * 1024
UA = "securevault-benchmark/1.0"


class BenchError(Exception):
    pass


# =============================================================================== HTTP client
class Client:
    """Minimal Django-aware HTTPS client: cookie jar + CSRF, no third-party packages."""

    def __init__(self, base_url: str, timeout: float = 3600):
        u = urllib.parse.urlparse(base_url)
        if u.scheme != "https":
            raise BenchError("base URL must be https://...")
        self.host, self.port = u.hostname, u.port or 443
        self.origin = f"{u.scheme}://{u.netloc}"
        self.timeout = timeout
        # Verification disabled ON PURPOSE for the self-signed VM certificate (this script only).
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self.cookies: dict[str, str] = {}
        self.csrf_token = ""
        self.tls_info = ""

    def _conn(self) -> http.client.HTTPSConnection:
        c = http.client.HTTPSConnection(self.host, self.port, context=self.ctx, timeout=self.timeout)
        c.connect()                                   # handshake happens BEFORE any timer starts
        self.tls_info = f"{c.sock.version()} {c.sock.cipher()[0]}"
        return c

    def _headers(self, extra: dict | None = None) -> dict:
        h = {"User-Agent": UA, "Origin": self.origin, "Referer": self.origin + "/"}
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        h.update(extra or {})
        return h

    def _absorb(self, resp: http.client.HTTPResponse) -> None:
        for sc in resp.msg.get_all("Set-Cookie") or []:
            m = re.match(r"([^=;\s]+)=([^;]*)", sc)
            if not m:
                continue
            if m.group(2) == "" or re.search(r"max-age=0", sc, re.I):
                self.cookies.pop(m.group(1), None)
            else:
                self.cookies[m.group(1)] = m.group(2)

    def request(self, method: str, path: str, body: bytes | None = None, headers: dict | None = None):
        c = self._conn()
        try:
            c.request(method, path, body=body, headers=self._headers(headers))
            r = c.getresponse()
            data = r.read()
            self._absorb(r)
            return r.status, r, data
        finally:
            c.close()

    # ------------------------------------------------------------------ session
    def login(self, username: str, password: str, register: bool = False) -> None:
        if register:
            status, _, page = self.request("GET", "/accounts/register/")
            tok = self._form_token(page)
            body = urllib.parse.urlencode({
                "csrfmiddlewaretoken": tok, "username": username, "password1": password, "password2": password})
            status, r, data = self.request("POST", "/accounts/register/", body.encode(),
                                           {"Content-Type": "application/x-www-form-urlencoded"})
            if status == 302:
                print(f"registered '{username}' and logged in")
                self._load_upload_token()
                return
            print("registration did not succeed (account may already exist); trying to log in")
        status, _, page = self.request("GET", "/accounts/login/")
        if status != 200:
            raise BenchError(f"GET /accounts/login/ -> {status}")
        body = urllib.parse.urlencode({
            "csrfmiddlewaretoken": self._form_token(page), "username": username, "password": password, "next": "/files/"})
        status, r, data = self.request("POST", "/accounts/login/", body.encode(),
                                       {"Content-Type": "application/x-www-form-urlencoded"})
        if status == 429:
            raise BenchError("login blocked by the rate limit (5 failures / 15 min per IP). Wait, then retry.")
        if status != 302:
            raise BenchError(f"login failed (HTTP {status}): wrong username/password? Use --register for a new user.")
        self._load_upload_token()

    @staticmethod
    def _form_token(html: bytes) -> str:
        m = re.search(rb'name="csrfmiddlewaretoken" value="([^"]+)"', html)
        if not m:
            raise BenchError("CSRF token not found in the page")
        return m.group(1).decode()

    def _load_upload_token(self) -> None:
        """Same token source as upload.js: data-csrf on the dropzone of /files/."""
        status, _, page = self.request("GET", "/files/")
        m = re.search(rb'data-csrf="([^"]+)"', page)
        if status != 200 or not m:
            raise BenchError(f"could not open /files/ after login (HTTP {status})")
        self.csrf_token = m.group(1).decode()

    # ------------------------------------------------------------------ operations
    def upload(self, path: str, name: str, size: int) -> tuple[float, str]:
        c = self._conn()
        try:
            c.putrequest("POST", "/files/upload/", skip_accept_encoding=True)
            for k, v in self._headers({
                "X-CSRFToken": self.csrf_token, "X-File-Name": urllib.parse.quote(name),
                "Content-Type": "application/octet-stream", "Content-Length": str(size)}).items():
                c.putheader(k, v)
            c.endheaders()
            read_t = 0.0
            t0 = pc()
            try:
                with open(path, "rb") as fh:
                    while True:
                        r0 = pc()
                        block = fh.read(BLOCK)
                        read_t += pc() - r0
                        if not block:
                            break
                        c.send(block)
            except (BrokenPipeError, ConnectionResetError):
                pass                                  # server answered early (error); read its reply below
            resp = c.getresponse()
            data = resp.read()
            elapsed = (pc() - t0) - read_t
            if resp.status != 201:
                raise BenchError(f"upload failed: HTTP {resp.status} {data[:200]!r}")
            return elapsed, json.loads(data)["id"]
        finally:
            c.close()

    def download(self, file_id: str, size: int, expected_sha: str) -> float:
        c = self._conn()
        try:
            t0 = pc()
            c.request("GET", f"/files/{file_id}/download/", headers=self._headers())
            resp = c.getresponse()                    # headers arrive after the server's integrity pass
            if resp.status != 200:
                raise BenchError(f"download failed: HTTP {resp.status}")
            sha, hash_t, got = hashlib.sha256(), 0.0, 0
            while True:
                b = resp.read(BLOCK)
                if not b:
                    break
                h0 = pc()
                sha.update(b)
                hash_t += pc() - h0
                got += len(b)
            elapsed = (pc() - t0) - hash_t
            if got != size or sha.hexdigest() != expected_sha:
                raise BenchError(f"DOWNLOAD MISMATCH: got {got} bytes (expected {size}); "
                                 f"sha256 {'ok' if sha.hexdigest() == expected_sha else 'DIFFERENT'}")
            return elapsed
        finally:
            c.close()

    def delete(self, file_id: str) -> None:
        body = urllib.parse.urlencode({"csrfmiddlewaretoken": self.csrf_token}).encode()
        status, _, _ = self.request("POST", f"/files/{file_id}/delete/", body,
                                    {"Content-Type": "application/x-www-form-urlencoded"})
        if status != 302:
            raise BenchError(f"delete failed: HTTP {status} (file {file_id} may remain on the server!)")


# =============================================================================== test data
def make_text_file(path: str, size: int) -> str:
    """ASCII text (passes the .txt whitelist: valid UTF-8, no NUL). Returns its SHA-256."""
    sha, written = hashlib.sha256(), 0
    with open(path, "wb") as fh:
        while written < size:
            n = min(BLOCK, size - written)
            chunk = base64.b64encode(os.urandom(n * 3 // 4 + 3))[:n]
            fh.write(chunk)
            sha.update(chunk)
            written += n
    return sha.hexdigest()


# =============================================================================== `run`
def cmd_run(a) -> int:
    sizes = parse_sizes(a.sizes)
    password = os.environ.get(a.password_env) or getpass.getpass(f"Password for {a.username}: ")
    info = system_info()
    print("Client machine (where this script runs):")
    print(format_system_info(info))
    print(f"Target: {a.base_url}   label={a.label}   runs={a.runs}   sizes={a.sizes}")
    print("WARNING: TLS certificate verification is disabled in this script (self-signed VM cert).\n")

    try:
        client = Client(a.base_url)
        client.login(a.username, password, register=a.register)
    except (BenchError, OSError) as exc:             # OSError: VM unreachable, TLS failure, timeout
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"logged in as {a.username}  ({client.tls_info})\n")

    tmp = tempfile.mkdtemp(prefix="sv-bench-")
    rows: list[dict] = []
    out_csv = os.path.join(a.out_dir, "network_summary.csv")
    try:
        need = max(s for _, s in sizes) + 100 * 2**20
        if shutil.disk_usage(tmp).free < need:
            raise BenchError(f"not enough free disk space in {tmp} (need ~{need // 2**20} MiB)")

        if not a.no_warmup:                           # 1 MB cycle: warms TLS, caches, Python paths
            wp = os.path.join(tmp, "warmup.txt")
            sha = make_text_file(wp, 1_000_000)
            _, fid = client.upload(wp, "benchmark-warmup.txt", 1_000_000)
            try:
                client.download(fid, 1_000_000, sha)
            finally:
                client.delete(fid)
            os.remove(wp)

        for label, size in sizes:
            path = os.path.join(tmp, f"benchmark-{label}.txt")
            print(f"[{label}] generating {size:,} bytes of text ...", flush=True)
            sha = make_text_file(path, size)
            ups, downs = [], []
            try:
                for i in range(1, a.runs + 1):
                    fid = None
                    try:
                        up, fid = client.upload(path, f"benchmark-{label}.txt", size)
                        down = client.download(fid, size, sha)
                    finally:
                        if fid:
                            client.delete(fid)        # always clean up on the server
                    ups.append(up)
                    downs.append(down)
                    print(f"[{label}] run {i}/{a.runs}: upload {up:8.3f}s ({size / 1e6 / up:6.1f} MB/s)   "
                          f"download {down:8.3f}s ({size / 1e6 / down:6.1f} MB/s)  sha256 OK, deleted", flush=True)
            finally:
                os.remove(path)                       # local test file removed after each size
            rows.append(make_row(info, a.label, a.base_url, label, size, "upload", ups))
            rows.append(make_row(info, a.label, a.base_url, label, size, "download", downs))
            write_csv(out_csv, rows)                  # partial results survive an interruption
    except KeyboardInterrupt:
        print("\ninterrupted; any file uploaded in the current run was deleted if possible.")
        return 130
    except BenchError as exc:
        print(f"\nERROR: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)        # all local test files deleted

    print("\nsummary (mean ± sample stdev):")
    for r in rows:
        print(f"{r['size_label']:>6} {r['operation']:<9} {r['mean_s']:9.3f} ± {r['stdev_s']:.3f} s   "
              f"{r['mean_MBps']:7.1f} ± {r['stdev_MBps']:.1f} MB/s")
    print(f"\nCSV written to {out_csv}")
    return 0


# =============================================================================== `plot`
def _read(paths):
    import csv
    rows = []
    for p in paths:
        with open(p, newline="") as fh:
            for r in csv.DictReader(fh):
                for k in ("size_bytes", "runs"):
                    r[k] = int(r[k])
                for k in ("mean_s", "stdev_s", "mean_MBps", "stdev_MBps"):
                    r[k] = float(r[k])
                rows.append(r)
    return rows


COLORS = ["#0072B2", "#E69F00", "#009E73", "#D55E00", "#CC79A7"]     # Okabe-Ito, colour-blind safe


def _grouped(ax, rows, series, key, value, err, ylabel, log=True):
    """series: list of (legend label, predicate). One bar group per file size."""
    import numpy as np
    sizes = sorted({(r["size_bytes"], r["size_label"]) for r in rows})
    x = np.arange(len(sizes))
    w = 0.8 / max(1, len(series))
    for i, (name, pred) in enumerate(series):
        means, errs = [], []
        for sb, _ in sizes:
            hit = [r for r in rows if r["size_bytes"] == sb and pred(r)]
            means.append(hit[0][value] if hit else float("nan"))
            errs.append(hit[0][err] if hit else 0)
        pos = x + (i - (len(series) - 1) / 2) * w
        ax.bar(pos, means, w * 0.92, yerr=errs, capsize=3, label=name, color=COLORS[i % len(COLORS)],
               error_kw={"elinewidth": 1, "ecolor": "#222"})
        for px, m, e in zip(pos, means, errs):
            if m == m:
                ax.text(px, m + e, (f"{m:.0f}" if m >= 100 else f"{m:.3g}"), ha="center", va="bottom", fontsize=7)
    ax.set_xticks(x, [s[1] for s in sizes])
    ax.set_xlabel("File size (decimal; 1 GB = 1,000,000,000 bytes)")
    ax.set_ylabel(ylabel)
    if log:
        ax.set_yscale("log")
    ax.grid(axis="y", alpha=0.3, which="both", linewidth=0.5)
    ax.set_axisbelow(True)
    ax.legend(frameon=False)


def cmd_plot(a) -> int:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    os.makedirs(a.out_dir, exist_ok=True)
    made = []

    def finish(fig, name):
        path = os.path.join(a.out_dir, name)
        fig.tight_layout()
        fig.savefig(path, dpi=200)
        plt.close(fig)
        made.append(path)

    if a.network:
        rows = _read([a.network])
        runs = rows[0]["runs"]
        who = f"client: {rows[0]['cpu_model']}, target: {rows[0]['target']}"
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8))
        ser = [("upload", lambda r: r["operation"] == "upload"), ("download", lambda r: r["operation"] == "download")]
        _grouped(ax1, rows, ser, None, "mean_s", "stdev_s", "Time (s, log scale)")
        _grouped(ax2, rows, ser, None, "mean_MBps", "stdev_MBps", "Throughput (MB/s)", log=False)
        ax1.set_title("Upload / download time")
        ax2.set_title("Upload / download throughput")
        fig.suptitle(f"End-to-end over HTTPS (mean ± std dev, n={runs})\n{who}", fontsize=10)
        finish(fig, "network_upload_download.png")

    if a.crypto:
        rows = _read(a.crypto)
        envs = sorted({r["environment"] for r in rows}, key=lambda e: (e != "vm", e))
        runs = rows[0]["runs"]
        fig, axes = plt.subplots(1, len(envs), figsize=(6.2 * len(envs), 4.8), squeeze=False, sharey=True)
        for ax, env in zip(axes[0], envs):
            sub = [r for r in rows if r["environment"] == env]
            _grouped(ax, sub, [("encrypt", lambda r: r["operation"] == "encrypt"),
                               ("decrypt", lambda r: r["operation"] == "decrypt")],
                     None, "mean_s", "stdev_s", "Time (s, log scale)")
            ax.set_title(f"{env}: {sub[0]['cpu_model']}\n{sub[0]['logical_cores']} cores, {sub[0]['ram_gib']} GiB RAM", fontsize=9)
        fig.suptitle(f"Encryption vs decryption only, AES-256-GCM, 1 MiB chunks (mean ± std dev, n={runs})", fontsize=10)
        finish(fig, "crypto_encrypt_decrypt.png")

        if len(envs) >= 2:
            fig, axes = plt.subplots(1, 2, figsize=(12, 4.8))
            for ax, op in zip(axes, ("encrypt", "decrypt")):
                _grouped(ax, rows, [(e, (lambda r, e=e: r["environment"] == e and r["operation"] == op)) for e in envs],
                         None, "mean_s", "stdev_s", "Time (s, log scale)")
                ax.set_title(op)
            fig.suptitle(f"Crypto only: {' vs '.join(envs)} (mean ± std dev, n={runs})", fontsize=10)
            finish(fig, "crypto_vm_vs_physical.png")
        else:
            print("only one environment in the crypto CSVs: skipping the VM vs physical chart")

    if not made:
        print("nothing to plot: give --network and/or --crypto", file=sys.stderr)
        return 1
    print("charts written:\n  " + "\n  ".join(made))
    return 0


# =============================================================================== CLI
def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="benchmark upload/download against the deployed app")
    r.add_argument("--base-url", default="https://192.168.64.2")
    r.add_argument("--username", default="benchuser")
    r.add_argument("--password-env", default="BENCH_PASSWORD",
                   help="env var holding the password (default BENCH_PASSWORD); prompts if unset")
    r.add_argument("--register", action="store_true", help="create the test account first if it doesn't exist")
    r.add_argument("--sizes", default=DEFAULT_SIZES)
    r.add_argument("--runs", type=int, default=5)
    r.add_argument("--label", default="vm", help="environment name stored in the CSV (default: vm)")
    r.add_argument("--out-dir", default="bench_out")
    r.add_argument("--no-warmup", action="store_true")
    r.set_defaults(fn=cmd_run)

    g = sub.add_parser("plot", help="make bar charts (matplotlib) from the CSVs")
    g.add_argument("--network", help="bench_out/network_summary.csv")
    g.add_argument("--crypto", nargs="+", help="one or more bench_crypto CSVs (e.g. vm and physical)")
    g.add_argument("--out-dir", default="bench_out/charts")
    g.set_defaults(fn=cmd_plot)

    a = p.parse_args()
    if getattr(a, "runs", 1) < 1:
        p.error("--runs must be >= 1")
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
