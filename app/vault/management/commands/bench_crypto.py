"""Benchmark ONLY the cryptography (no network, no database), using the app's real functions
`vault.crypto.encrypt_chunks` / `decrypt_chunks` (chunked AES-256-GCM, 1 MiB chunks).

    python manage.py bench_crypto --label physical --csv ../bench_out/crypto_physical.csv
    docker compose exec -T django-web python manage.py bench_crypto --label vm \
        --tmpdir /data/files --csv - > bench_out/crypto_vm.csv

What is timed, and what is not
  encrypt : time spent inside encrypt_chunks() producing every ciphertext chunk.
  decrypt : time spent inside decrypt_chunks() (includes GCM tag verification), MINUS the time
            its read() callback spends reading the ciphertext back from disk.
  NOT timed: writing the ciphertext to --tmpdir, reading it back, generating/ comparing plaintext.
The plaintext is one random 1 MiB block reused for every chunk (AES-GCM speed does not depend
on the data); every decrypted chunk is compared to it, so a run that decrypts wrongly fails.
Each run uses a fresh random data key and base nonce, like the app does per file.

Progress goes to stderr; with --csv - only the CSV goes to stdout.
"""
import os
import shutil
import sys
import tempfile
import time
import uuid

from django.core.management.base import BaseCommand, CommandError

from vault import crypto
from vault.benchutil import (DEFAULT_SIZES, format_system_info, make_row, parse_sizes,
                             system_info, write_csv)

pc = time.perf_counter


def log(msg=""):
    print(msg, file=sys.stderr, flush=True)


class Command(BaseCommand):
    help = "Time encryption and decryption only (real crypto.py code, no network) - for the technical report."
    requires_system_checks = []          # no DB / settings checks needed

    def add_arguments(self, parser):
        parser.add_argument("--sizes", default=DEFAULT_SIZES,
                            help=f"comma list, decimal units (default {DEFAULT_SIZES}; 1GB = 1,000,000,000 bytes)")
        parser.add_argument("--runs", type=int, default=5, help="runs per size and operation (default 5)")
        parser.add_argument("--label", default="local",
                            help="environment name stored in the CSV, e.g. 'vm' or 'physical'")
        parser.add_argument("--csv", default=None,
                            help="output CSV path, or '-' for stdout (default bench_out/crypto_<label>.csv)")
        parser.add_argument("--tmpdir", default=None,
                            help="where the temporary ciphertext file lives (default: system temp dir). "
                                 "In the container use /data/files (the real-disk volume; /tmp is RAM).")

    # ------------------------------------------------------------------ one timed encrypt+decrypt
    def one_run(self, size, ref, path):
        chunk = crypto.CHUNK_SIZE
        key, base_nonce = crypto.generate_file_secrets()
        fid = uuid.uuid4()

        def plain():
            full, rest = divmod(size, chunk)
            for _ in range(full):
                yield ref
            if rest:
                yield ref[:rest]

        # ---- encrypt
        enc = 0.0
        it = crypto.encrypt_chunks(plain(), key, base_nonce, fid)
        with open(path, "wb") as out:
            while True:
                t = pc()
                try:
                    ct = next(it)
                except StopIteration:
                    enc += pc() - t
                    break
                enc += pc() - t
                out.write(ct)                                    # untimed
        expected_ct = crypto.ciphertext_size(size, chunk)
        if os.path.getsize(path) != expected_ct:
            raise CommandError(f"unexpected ciphertext size {os.path.getsize(path)} != {expected_ct}")

        # ---- decrypt
        read_time = 0.0
        total = 0.0
        got = 0
        with open(path, "rb") as fh:
            def timed_read(n):
                nonlocal read_time
                t0 = pc()
                b = fh.read(n)
                read_time += pc() - t0
                return b

            it = crypto.decrypt_chunks(timed_read, key, base_nonce, fid, chunk)
            while True:
                t = pc()
                try:
                    p = next(it)
                except StopIteration:
                    total += pc() - t
                    break
                total += pc() - t
                if p != (ref if len(p) == chunk else ref[:len(p)]):   # untimed correctness check
                    raise CommandError("decrypted data does not match the plaintext!")
                got += len(p)
        if got != size:
            raise CommandError(f"decrypted {got} bytes, expected {size}")
        return enc, total - read_time

    # ------------------------------------------------------------------ main
    def handle(self, *args, **opts):
        try:
            sizes = parse_sizes(opts["sizes"])
        except ValueError as exc:
            raise CommandError(str(exc))
        runs, label = opts["runs"], opts["label"]
        if runs < 1:
            raise CommandError("--runs must be >= 1")
        tmpdir = opts["tmpdir"] or None
        if tmpdir and not os.path.isdir(tmpdir):
            raise CommandError(f"--tmpdir {tmpdir} is not a directory")
        csv_dest = opts["csv"] or os.path.join("bench_out", f"crypto_{label}.csv")

        info = system_info()
        log("bench_crypto: chunked AES-256-GCM (vault.crypto), no network")
        log(format_system_info(info))
        log(f"  label={label}  chunk={crypto.CHUNK_SIZE // 1024} KiB  runs={runs}  sizes={opts['sizes']}")
        log(f"  ciphertext temp dir: {tmpdir or 'system default'}\n")

        # fail early if the output can't be written (e.g. read-only container FS)
        if csv_dest != "-":
            try:
                os.makedirs(os.path.dirname(os.path.abspath(csv_dest)), exist_ok=True)
                open(csv_dest, "a").close()
            except OSError as exc:
                raise CommandError(f"Cannot write {csv_dest}: {exc}. In the container use --csv - and redirect on the host.")

        ref = os.urandom(crypto.CHUNK_SIZE)
        base = tmpdir or tempfile.gettempdir()
        rows = []
        for size_label, size in sizes:
            free = shutil.disk_usage(base).free
            need = crypto.ciphertext_size(size) + 50 * 2**20
            if free < need:
                raise CommandError(f"{size_label}: need ~{need // 2**20} MiB free in {base}, have {free // 2**20} MiB")
            enc_t, dec_t = [], []
            for i in range(1, runs + 1):
                path = os.path.join(base, f"bench-{uuid.uuid4().hex}.tmp")
                try:
                    e, d = self.one_run(size, ref, path)
                finally:
                    try:
                        os.remove(path)
                    except FileNotFoundError:
                        pass
                enc_t.append(e)
                dec_t.append(d)
                log(f"{size_label:>6} run {i}/{runs}: encrypt {e:8.3f}s ({size / 1e6 / e:7.1f} MB/s)   "
                    f"decrypt {d:8.3f}s ({size / 1e6 / d:7.1f} MB/s)")
            rows.append(make_row(info, label, "local crypto.py", size_label, size, "encrypt", enc_t))
            rows.append(make_row(info, label, "local crypto.py", size_label, size, "decrypt", dec_t))

        log("\nsummary (mean ± sample stdev):")
        for r in rows:
            log(f"{r['size_label']:>6} {r['operation']:<8} {r['mean_s']:8.3f} ± {r['stdev_s']:.3f} s   "
                f"{r['mean_MBps']:8.1f} ± {r['stdev_MBps']:.1f} MB/s")
        write_csv(csv_dest, rows)
        log(f"\nCSV written to {'stdout' if csv_dest == '-' else csv_dest}")
