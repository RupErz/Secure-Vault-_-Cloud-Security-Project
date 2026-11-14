# Benchmarks

Two complementary measurements, with 5 runs each for 10 MB, 100 MB, 500 MB and 1 GB. Sizes are decimal
(1 GB = 1,000,000,000 bytes, which is under the application's 1 GiB limit). Results are the mean and the
sample standard deviation (n-1), written to CSV together with the CPU model, core count and RAM of the machine.

| Tool | Measures | Runs on |
|---|---|---|
| `scripts/benchmark.py run` | Upload and download through the whole stack (TLS, Nginx, Gunicorn, Django, AES-GCM, disk). Download verifies SHA-256, and every test file is deleted through the application afterwards. | The VM, against `https://localhost` |
| `manage.py bench_crypto` | Encryption and decryption only, using the real `vault/crypto.py` functions, with no network and no database. | Inside `django-web` on the VM, and directly on the host machine |

The end-to-end benchmark was run on the VM against `https://localhost`. Client and server therefore share the
VM's CPU and the traffic never crosses a physical network, so the results exclude network latency and bandwidth limits.

## Setup

The end-to-end benchmark needs only Python 3 (standard library) and is run from a checkout of the project on the
VM. Generating charts and running `bench_crypto` on a physical host need a virtual environment with matplotlib,
Django and `cryptography`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r app/requirements.txt -r scripts/requirements-bench.txt
```

## Procedure

1. End to end, on the VM. Use a dedicated test account; `--register` creates it on first use. The password is read
   from `BENCH_PASSWORD` (or prompted for) so that it never appears on the command line. About 1 GB of local disk
   is needed, since one test file exists at a time.
   ```bash
   BENCH_PASSWORD='choose-a-test-password' python3 scripts/benchmark.py run \
       --base-url https://localhost --username benchuser --register --label vm
   ```
   Output: `bench_out/network_summary.csv`. For a quick trial, add `--sizes 10MB,100MB --runs 2`.
2. Crypto only, on the VM, inside the container. The CSV goes to stdout and progress to stderr:
   ```bash
   mkdir -p bench_out
   docker compose exec -T django-web python manage.py bench_crypto --label vm \
       --tmpdir /data/files --csv - > bench_out/crypto_vm.csv
   ```
   `--tmpdir /data/files` places the temporary ciphertext on the persistent disk volume, because the container's
   `/tmp` is RAM-backed. The temporary file is removed after every run and needs about 1 GB free on that volume.
3. Crypto only, on the physical host:
   ```bash
   cd app && DJANGO_SECRET_KEY=x USE_SQLITE=1 python manage.py bench_crypto --label physical \
       --csv ../bench_out/crypto_physical.csv && cd ..
   ```
4. Charts (PNG, 200 dpi; bars show the mean, error bars the standard deviation; logarithmic time axis). Copy the
   two VM CSVs (`network_summary.csv`, `crypto_vm.csv`) into the `bench_out/` directory of the machine that draws
   the charts, for example with `scp`, then run:
   ```bash
   python3 scripts/benchmark.py plot --network bench_out/network_summary.csv \
       --crypto bench_out/crypto_vm.csv bench_out/crypto_physical.csv
   ```
   This produces `bench_out/charts/network_upload_download.png` (time and throughput),
   `crypto_encrypt_decrypt.png` (one panel per machine) and `crypto_vm_vs_physical.png`.

Each tool prints the CPU model, core count and RAM of the machine it runs on, and every CSV row repeats them.
If a Linux/ARM VM reports only a hardware identifier instead of a CPU name, set the name explicitly with
`BENCH_CPU_MODEL="Apple M4 (UTM, 2 vCPU)"`. Inside the container, use
`docker compose exec -T -e BENCH_CPU_MODEL="..." django-web python manage.py bench_crypto ...`.

## Measurement notes

- Upload time runs from the first request byte to the last response byte. It includes the TLS and HTTP transfer,
  Nginx, server-side encryption and the disk write. Download time runs from the request to the last byte and
  includes the server's up-front integrity pass (the application decrypts twice: once to verify, once to stream).
  Local file reads (upload) and SHA-256 hashing (download) are measured separately and excluded. The TLS handshake
  completes before the timer starts. `bench_crypto` excludes disk reads and writes and the plaintext comparison.
- Each run uses a fresh random key and nonce, as the application does for every file. One untimed 1 MB warm-up
  cycle runs first; `--no-warmup` skips it.
- For comparable results, run on mains power with no heavy background load, and keep the VM otherwise idle.
- The script disables TLS verification because the VM certificate is self-signed. The setting is confined to
  `benchmark.py`.
- Crypto-only throughput (GB/s with AES hardware instructions) is expected to be far above end-to-end throughput,
  because the latter also includes TLS, HTTP handling, Python and disk I/O.
