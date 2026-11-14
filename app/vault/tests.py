import base64
import io
import os
import shutil
import tempfile
import uuid

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.test import Client, SimpleTestCase, TestCase, override_settings

from . import crypto
from .models import AuditLog, EncryptedFile
from .validators import UploadRejected, check_extension, check_magic, clean_filename

TEST_KEY = base64.b64encode(os.urandom(32)).decode()
SMALL = 1024  # tiny chunk size so multi-chunk paths are cheap to test


def roundtrip_parts(data: bytes, chunk=SMALL):
    fid = uuid.uuid4()
    key, nonce = crypto.generate_file_secrets()
    ct = b"".join(crypto.encrypt_chunks(crypto.iter_plain_chunks(io.BytesIO(data).read, chunk), key, nonce, fid))
    return fid, key, nonce, ct


def decrypt(ct, key, nonce, fid, chunk=SMALL):
    return b"".join(crypto.decrypt_chunks(io.BytesIO(ct).read, key, nonce, fid, chunk))


class CryptoTests(SimpleTestCase):
    def test_roundtrip_sizes(self):
        for n in (1, 5, SMALL - 1, SMALL, SMALL + 1, 5 * SMALL, 5 * SMALL + 17):
            data = os.urandom(n)
            fid, key, nonce, ct = roundtrip_parts(data)
            self.assertEqual(len(ct), crypto.ciphertext_size(n, SMALL))
            self.assertEqual(decrypt(ct, key, nonce, fid), data)

    def test_empty_file(self):
        fid, key, nonce, ct = roundtrip_parts(b"")
        self.assertEqual(len(ct), crypto.TAG_SIZE)
        self.assertEqual(decrypt(ct, key, nonce, fid), b"")

    def test_ciphertext_differs_from_plaintext(self):
        data = b"A" * (3 * SMALL)
        _, _, _, ct = roundtrip_parts(data)
        self.assertNotIn(b"AAAAAAAA", ct)

    def test_bitflip_detected_in_every_chunk(self):
        fid, key, nonce, ct = roundtrip_parts(os.urandom(4 * SMALL + 5))
        for pos in (0, SMALL + 16 + 3, 4 * (SMALL + 16) + 1, len(ct) - 1):
            bad = bytearray(ct)
            bad[pos] ^= 1
            with self.assertRaises(crypto.IntegrityError):
                decrypt(bytes(bad), key, nonce, fid)

    def test_truncation_detected(self):
        fid, key, nonce, ct = roundtrip_parts(os.urandom(4 * SMALL))
        # drop the whole last chunk: remaining chunks were sealed as "not final"
        with self.assertRaises(crypto.IntegrityError):
            decrypt(ct[: -(SMALL + 16)], key, nonce, fid)
        with self.assertRaises(crypto.IntegrityError):
            decrypt(ct[:-1], key, nonce, fid)
        with self.assertRaises(crypto.IntegrityError):
            decrypt(b"", key, nonce, fid)

    def test_appended_data_detected(self):
        fid, key, nonce, ct = roundtrip_parts(os.urandom(2 * SMALL))
        with self.assertRaises(crypto.IntegrityError):
            decrypt(ct + os.urandom(40), key, nonce, fid)

    def test_reordering_detected(self):
        fid, key, nonce, ct = roundtrip_parts(os.urandom(4 * SMALL))
        size = SMALL + 16
        chunks = [ct[i:i + size] for i in range(0, len(ct), size)]
        chunks[0], chunks[1] = chunks[1], chunks[0]
        with self.assertRaises(crypto.IntegrityError):
            decrypt(b"".join(chunks), key, nonce, fid)

    def test_chunk_transplant_between_files_detected(self):
        fid1, key, nonce, ct1 = roundtrip_parts(os.urandom(2 * SMALL))
        with self.assertRaises(crypto.IntegrityError):
            decrypt(ct1, key, nonce, uuid.uuid4())      # wrong file id in AAD

    def test_wrong_key(self):
        fid, key, nonce, ct = roundtrip_parts(os.urandom(100))
        with self.assertRaises(crypto.IntegrityError):
            decrypt(ct, os.urandom(32), nonce, fid)

    def test_nonces_unique_per_chunk(self):
        n = os.urandom(8)
        self.assertEqual(len({crypto._nonce(n, i) for i in range(10000)}), 10000)

    def test_key_wrap(self):
        mk, fid = os.urandom(32), uuid.uuid4()
        dk, _ = crypto.generate_file_secrets()
        wrapped, wn = crypto.wrap_key(dk, fid, mk)
        self.assertEqual(len(wrapped), 48)
        self.assertEqual(crypto.unwrap_key(wrapped, wn, fid, mk), dk)
        with self.assertRaises(crypto.IntegrityError):
            crypto.unwrap_key(wrapped, wn, uuid.uuid4(), mk)      # bound to the file id
        with self.assertRaises(crypto.IntegrityError):
            crypto.unwrap_key(wrapped, wn, fid, os.urandom(32))   # wrong master key


class ValidatorTests(SimpleTestCase):
    def test_extension_whitelist(self):
        self.assertEqual(check_extension("a.PDF"), "pdf")
        for bad in ("evil.exe", "noext", "x.php", "x.pdf.sh"):
            with self.assertRaises(UploadRejected):
                check_extension(bad)

    def test_magic(self):
        check_magic("pdf", b"%PDF-1.7 ...")
        check_magic("png", b"\x89PNG\r\n\x1a\nrest")
        check_magic("mp4", b"\x00\x00\x00\x18ftypisom")
        check_magic("txt", "héllo".encode())
        for ext, head in (("pdf", b"MZ\x90\x00"), ("png", b"%PDF-"), ("zip", b"<html>"),
                          ("txt", b"abc\x00def"), ("txt", b"\xff\xfe\xfa")):
            with self.assertRaises(UploadRejected):
                check_magic(ext, head)

    def test_filename_cleaning(self):
        self.assertEqual(clean_filename("../../etc/passwd"), "passwd")
        self.assertEqual(clean_filename("C:\\x\\y.pdf"), "y.pdf")
        self.assertEqual(clean_filename("a\x00b\n.pdf"), "ab.pdf")


class BenchTests(SimpleTestCase):
    def test_parse_sizes_decimal(self):
        from .benchutil import parse_sizes
        self.assertEqual(parse_sizes("10MB, 100mb,500MB,1GB"),
                         [("10MB", 10_000_000), ("100MB", 100_000_000), ("500MB", 500_000_000), ("1GB", 1_000_000_000)])
        self.assertLess(1_000_000_000, 1024 ** 3)          # 1 GB test file is under the app's 1 GiB limit
        for bad in ("", "10", "1TB", "x MB", "1.5GB"):
            with self.assertRaises(ValueError):
                parse_sizes(bad)

    def test_summarize_uses_sample_stdev(self):
        from .benchutil import summarize
        s = summarize([1.0, 2.0, 3.0], 10_000_000)
        self.assertAlmostEqual(s["mean_s"], 2.0)
        self.assertAlmostEqual(s["stdev_s"], 1.0)                      # n-1 denominator
        self.assertAlmostEqual(s["mean_MBps"], (10 + 5 + 10 / 3) / 3)  # mean of per-run speeds
        self.assertEqual(summarize([2.0], 1_000_000)["stdev_s"], 0.0)  # single run: no crash

    def test_system_info(self):
        from .benchutil import format_system_info, system_info
        info = system_info()
        for k in ("cpu_model", "logical_cores", "ram_gib", "os", "python"):
            self.assertIn(k, info)
        self.assertGreaterEqual(info["logical_cores"], 1)
        self.assertIn("CPU model", format_system_info(info))
        from unittest import mock
        with mock.patch.dict(os.environ, {"BENCH_CPU_MODEL": "Test CPU 9000"}):
            self.assertEqual(system_info()["cpu_model"], "Test CPU 9000")

    def test_bench_crypto_command_writes_csv(self):
        import contextlib
        import csv as csvmod
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(io.StringIO()):
            out = os.path.join(d, "c.csv")
            call_command("bench_crypto", sizes="1MB,2MB", runs=2, label="test", tmpdir=d, csv=out)
            rows = list(csvmod.DictReader(open(out)))
            self.assertEqual([(r["size_label"], r["operation"]) for r in rows],
                             [("1MB", "encrypt"), ("1MB", "decrypt"), ("2MB", "encrypt"), ("2MB", "decrypt")])
            self.assertTrue(all(r["environment"] == "test" and r["runs"] == "2" and float(r["mean_s"]) > 0 for r in rows))
            self.assertEqual([f for f in os.listdir(d) if f.endswith(".tmp")], [])   # temp ciphertext removed


class ClientIpTests(SimpleTestCase):
    def req(self, peer, real_ip=None):
        from django.test import RequestFactory
        extra = {"REMOTE_ADDR": peer}
        if real_ip is not None:
            extra["HTTP_X_REAL_IP"] = real_ip
        return RequestFactory().get("/", **extra)

    @override_settings(TRUSTED_PROXY_CIDRS=["172.20.0.0/16"], TRUSTED_PROXY_HOSTS=[])
    def test_header_honoured_only_from_trusted_proxy(self):
        from .audit import client_ip
        self.assertEqual(client_ip(self.req("172.20.0.5", "203.0.113.9")), "203.0.113.9")
        # a direct client (or any other container) can't forge it
        self.assertEqual(client_ip(self.req("198.51.100.7", "203.0.113.9")), "198.51.100.7")
        self.assertEqual(client_ip(self.req("172.21.0.5", "203.0.113.9")), "172.21.0.5")

    @override_settings(TRUSTED_PROXY_CIDRS=["172.20.0.0/16"], TRUSTED_PROXY_HOSTS=[])
    def test_garbage_or_missing_header_falls_back_to_peer(self):
        from .audit import client_ip
        for bad in (None, "", "not-an-ip", "1.2.3.4, 5.6.7.8", "1.2.3.4\r\nX: y"):
            self.assertEqual(client_ip(self.req("172.20.0.5", bad)), "172.20.0.5")

    @override_settings(TRUSTED_PROXY_CIDRS=[], TRUSTED_PROXY_HOSTS=[])
    def test_nobody_trusted_by_default_config(self):
        from .audit import client_ip
        self.assertEqual(client_ip(self.req("10.0.0.2", "203.0.113.9")), "10.0.0.2")

    @override_settings(TRUSTED_PROXY_CIDRS=[], TRUSTED_PROXY_HOSTS=["mynginx"])
    def test_service_name_resolution(self):
        from unittest import mock
        from . import audit
        audit._resolved.clear()
        with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("172.30.0.3", 0))]):
            self.assertEqual(audit.client_ip(self.req("172.30.0.3", "203.0.113.9")), "203.0.113.9")
            self.assertEqual(audit.client_ip(self.req("172.30.0.4", "203.0.113.9")), "172.30.0.4")
        audit._resolved.clear()
        with mock.patch("socket.getaddrinfo", side_effect=OSError):      # DNS down -> fail closed
            self.assertEqual(audit.client_ip(self.req("172.30.0.3", "203.0.113.9")), "172.30.0.3")
        audit._resolved.clear()


@override_settings(MAX_UPLOAD_BYTES=50_000)
class ViewTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tmp = tempfile.mkdtemp()
        os.environ["MASTER_KEY"] = TEST_KEY
        os.environ.pop("MASTER_KEY_FILE", None)
        crypto.get_master_key.cache_clear()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self._ov = override_settings(FILE_STORAGE_DIR=self.tmp)
        self._ov.enable()
        U = get_user_model()
        self.alice = U.objects.create_user("alice", password="correct-horse-1")
        self.bob = U.objects.create_user("bob", password="correct-horse-2")
        self.ca, self.cb = Client(enforce_csrf_checks=True), Client(enforce_csrf_checks=True)
        for c, name, pw in ((self.ca, "alice", "correct-horse-1"), (self.cb, "bob", "correct-horse-2")):
            c.get("/accounts/login/")
            tok = c.cookies["__Host-csrftoken"].value
            r = c.post("/accounts/login/", {"username": name, "password": pw, "csrfmiddlewaretoken": tok})
            self.assertEqual(r.status_code, 302)

    def tearDown(self):
        self._ov.disable()
        for f in os.listdir(self.tmp):
            os.remove(os.path.join(self.tmp, f))

    def token(self, c):
        c.get("/files/")
        return c.cookies["__Host-csrftoken"].value

    def upload(self, c, name, data, token=None):
        return c.generic("POST", "/files/upload/", data, content_type="application/octet-stream",
                         HTTP_X_FILE_NAME=name, HTTP_X_CSRFTOKEN=token or self.token(c))

    def make(self, c=None, name="note.txt", data=b"top secret text " * 100):
        r = self.upload(c or self.ca, name, data)
        self.assertEqual(r.status_code, 201, r.content)
        return r.json()["id"]

    def test_upload_encrypts_and_download_roundtrips(self):
        data = b"hello vault " * 3000
        fid = self.make(name="a.txt", data=data)
        f = EncryptedFile.objects.get(id=fid)
        raw = open(os.path.join(self.tmp, f"{fid}.enc"), "rb").read()
        self.assertNotIn(b"hello vault", raw)
        self.assertEqual(len(raw), f.encrypted_size)
        self.assertEqual(bytes(f.wrapped_key).__len__(), 48)
        r = self.ca.get(f"/files/{fid}/download/")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(b"".join(r.streaming_content), data)
        self.assertEqual(r["Content-Length"], str(len(data)))
        self.assertIn("attachment", r["Content-Disposition"])
        self.assertTrue(AuditLog.objects.filter(action="UPLOAD", user=self.alice).exists())
        self.assertTrue(AuditLog.objects.filter(action="DOWNLOAD", user=self.alice).exists())
        self.assertEqual(self.ca.get(f"/files/{fid}/").status_code, 200)  # details page renders

    def test_ownership_returns_404_and_is_audited(self):
        fid = self.make()
        for method, url in (("get", f"/files/{fid}/"), ("get", f"/files/{fid}/download/"),
                            ("post", f"/files/{fid}/delete/")):
            args = ({"csrfmiddlewaretoken": self.token(self.cb)},) if method == "post" else ()
            self.assertEqual(getattr(self.cb, method)(url, *args).status_code, 404, url)
        self.assertEqual(AuditLog.objects.filter(action="ACCESS_DENIED", user=self.bob).count(), 3)
        self.assertTrue(EncryptedFile.objects.filter(id=fid).exists())
        self.assertNotContains(self.cb.get("/files/"), "note.txt")

    def test_anonymous_cannot_access(self):
        fid = self.make()
        anon = Client()
        self.assertEqual(anon.get(f"/files/{fid}/download/").status_code, 302)
        r = anon.post("/files/upload/", b"x", content_type="application/octet-stream")
        self.assertIn(r.status_code, (401, 403))

    def test_csrf_enforced_on_upload(self):
        self.token(self.ca)
        r = self.ca.generic("POST", "/files/upload/", b"hello", content_type="application/octet-stream",
                            HTTP_X_FILE_NAME="a.txt")
        self.assertEqual(r.status_code, 403)

    def test_tampered_download_rejected_without_partial_data(self):
        data = os.urandom(0) + b"X" * 40_000
        fid = self.make(name="big.txt", data=data)
        call_command("tamper_file", fid, offset=10, count=4, stdout=io.StringIO())
        r = self.ca.get(f"/files/{fid}/download/")
        self.assertEqual(r.status_code, 500)
        self.assertFalse(r.streaming)
        self.assertNotIn(b"XXXX", r.content)
        self.assertTrue(AuditLog.objects.filter(action="DOWNLOAD_FAILED").exists())
        call_command("tamper_file", fid, offset=10, count=4, stdout=io.StringIO())   # undo
        self.assertEqual(self.ca.get(f"/files/{fid}/download/").status_code, 200)

    def test_truncated_file_rejected(self):
        fid = self.make(data=b"Y" * 3000)
        call_command("tamper_file", fid, truncate=20, stdout=io.StringIO())
        self.assertEqual(self.ca.get(f"/files/{fid}/download/").status_code, 500)

    def test_extension_and_magic_rejected(self):
        self.assertEqual(self.upload(self.ca, "evil.exe", b"MZ....").status_code, 415)
        self.assertEqual(self.upload(self.ca, "fake.pdf", b"MZ\x90\x00 not a pdf").status_code, 415)
        self.assertEqual(self.upload(self.ca, "fake.png", b"%PDF-1.4").status_code, 415)
        self.assertEqual(os.listdir(self.tmp), [])                 # nothing left behind, not even .part
        self.assertEqual(EncryptedFile.objects.count(), 0)
        self.assertEqual(AuditLog.objects.filter(action="UPLOAD_REJECTED").count(), 3)
        self.assertEqual(self.upload(self.ca, "ok.pdf", b"%PDF-1.4 hi").status_code, 201)

    def test_size_limit(self):
        r = self.upload(self.ca, "big.txt", b"a" * 50_001)
        self.assertEqual(r.status_code, 413)
        self.assertEqual(os.listdir(self.tmp), [])
        self.assertIn(self.upload(self.ca, "empty.txt", b"").status_code, (400, 411))

    def test_delete_removes_row_and_blob(self):
        fid = self.make()
        r = self.ca.post(f"/files/{fid}/delete/", {"csrfmiddlewaretoken": self.token(self.ca)})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(EncryptedFile.objects.filter(id=fid).exists())
        self.assertFalse(os.path.exists(os.path.join(self.tmp, f"{fid}.enc")))
        self.assertTrue(AuditLog.objects.filter(action="DELETE", file_id=fid).exists())
        self.assertEqual(self.ca.get(f"/files/{fid}/").status_code, 404)

    @override_settings(LOGIN_MAX_FAILURES=3, TRUSTED_PROXY_CIDRS=["127.0.0.1/32"], TRUSTED_PROXY_HOSTS=[])
    def test_lockout_is_per_real_client_ip_behind_proxy(self):
        """All requests arrive from the proxy (127.0.0.1); lockout must key on X-Real-IP."""
        c = Client()
        c.get("/accounts/login/")
        tok = c.cookies["__Host-csrftoken"].value

        def attempt(ip, password="bad"):
            return c.post("/accounts/login/", {"username": "alice", "password": password,
                                               "csrfmiddlewaretoken": tok}, HTTP_X_REAL_IP=ip)
        for _ in range(3):
            self.assertEqual(attempt("203.0.113.1").status_code, 200)
        self.assertEqual(attempt("203.0.113.1", "correct-horse-1").status_code, 429)    # attacker blocked
        self.assertEqual(attempt("203.0.113.2", "correct-horse-1").status_code, 302)    # other user unaffected
        self.assertTrue(AuditLog.objects.filter(action="LOGIN_FAILED", ip_address="203.0.113.1").count() == 3)

    @override_settings(LOGIN_MAX_FAILURES=3, TRUSTED_PROXY_CIDRS=[], TRUSTED_PROXY_HOSTS=[])
    def test_forged_x_real_ip_cannot_evade_lockout(self):
        c = Client()
        c.get("/accounts/login/")
        tok = c.cookies["__Host-csrftoken"].value
        for i in range(3):   # attacker rotates a forged header; peer is untrusted so it's ignored
            c.post("/accounts/login/", {"username": "alice", "password": "bad", "csrfmiddlewaretoken": tok},
                   HTTP_X_REAL_IP=f"198.51.100.{i}")
        r = c.post("/accounts/login/", {"username": "alice", "password": "x", "csrfmiddlewaretoken": tok},
                   HTTP_X_REAL_IP="198.51.100.99")
        self.assertEqual(r.status_code, 429)

    @override_settings(LOGIN_MAX_FAILURES=3)
    def test_login_rate_limit(self):
        c = Client()
        c.get("/accounts/login/")
        tok = c.cookies["__Host-csrftoken"].value
        for _ in range(3):
            r = c.post("/accounts/login/", {"username": "alice", "password": "bad", "csrfmiddlewaretoken": tok})
            self.assertEqual(r.status_code, 200)
        r = c.post("/accounts/login/", {"username": "alice", "password": "correct-horse-1", "csrfmiddlewaretoken": tok})
        self.assertEqual(r.status_code, 429)                     # even the right password is refused
        self.assertTrue(AuditLog.objects.filter(action="LOGIN_BLOCKED").exists())
