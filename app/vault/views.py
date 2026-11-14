import logging
import math
import os
import uuid
from urllib.parse import unquote

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.views import LoginView
from django.db import transaction
from django.db.models import Sum
from django.http import Http404, HttpResponse, JsonResponse, StreamingHttpResponse
from django.shortcuts import redirect, render
from django.utils.http import content_disposition_header
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_GET, require_POST

from . import crypto
from .audit import audit, is_login_locked
from .models import AuditLog, EncryptedFile
from .validators import ALLOWED, UploadRejected, check_extension, check_magic, clean_filename

log = logging.getLogger(__name__)
A = AuditLog.Action


# --------------------------------------------------------------------------- storage
def storage_path(name: str) -> str:
    return os.path.join(settings.FILE_STORAGE_DIR, name)


def blob_path(file_id) -> str:
    return storage_path(f"{file_id}.enc")


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError:
        log.exception("Could not remove %s", path)


# --------------------------------------------------------------------------- ownership
def get_owned_file(request, pk) -> EncryptedFile:
    """THE ownership check. Used by detail/download/delete.

    Filtering on owner in the query means a foreign file is indistinguishable from a
    non-existent one: both give 404 (no information leak about which IDs exist).
    The attempt is recorded in the audit log.
    """
    f = EncryptedFile.objects.filter(pk=pk, owner=request.user).first()
    if f is None:
        audit(request, A.ACCESS_DENIED, file_id=pk, detail=f"{request.method} {request.path}: not found or not owner")
        raise Http404("File not found.")
    return f


# --------------------------------------------------------------------------- auth views
@require_GET
def healthz(request):
    return HttpResponse("ok", content_type="text/plain")


class RateLimitedLoginView(LoginView):
    template_name = "registration/login.html"
    redirect_authenticated_user = True

    def post(self, request, *args, **kwargs):
        if is_login_locked(request):
            audit(request, A.LOGIN_BLOCKED, username=str(request.POST.get("username", ""))[:150],
                  detail="too many failed attempts from this IP")
            form = self.get_form_class()(request)  # unbound: don't even check the password
            return self.render_to_response(
                self.get_context_data(form=form, locked=True, lockout_minutes=max(1, settings.LOGIN_LOCKOUT_SECONDS // 60)),
                status=429)
        return super().post(request, *args, **kwargs)


def register(request):
    if request.user.is_authenticated:
        return redirect("file_list")
    form = UserCreationForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        user = form.save()
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        audit(request, A.REGISTER)
        return redirect("file_list")
    return render(request, "registration/register.html", {"form": form})


# --------------------------------------------------------------------------- file views
@login_required
def file_list(request):
    files = EncryptedFile.objects.filter(owner=request.user)
    return render(request, "vault/file_list.html", {
        "files": files,
        "total_size": files.aggregate(s=Sum("plaintext_size"))["s"] or 0,
        "max_bytes": settings.MAX_UPLOAD_BYTES,
        "allowed": sorted(ALLOWED),
    })


@login_required
def file_detail(request, pk):
    f = get_owned_file(request, pk)
    try:
        with open(blob_path(f.id), "rb") as fh:
            preview = fh.read(64)
    except OSError:
        preview = b""
    base_nonce = bytes(f.base_nonce)
    return render(request, "vault/file_detail.html", {
        "f": f,
        "base_nonce_hex": base_nonce.hex(),
        "example_nonce_hex": (base_nonce + (0).to_bytes(4, "big")).hex(),
        "wrap_nonce_hex": bytes(f.wrap_nonce).hex(),
        "wrapped_key_hex": bytes(f.wrapped_key).hex(),
        "overhead": f.encrypted_size - f.plaintext_size,
        "preview_rows": _hexdump(preview),
        "storage_name": f"{f.id}.enc",
    })


def _hexdump(data: bytes):
    rows = []
    for off in range(0, len(data), 16):
        part = data[off:off + 16]
        rows.append({
            "offset": f"{off:08x}",
            "hex": " ".join(f"{b:02x}" for b in part),
            "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in part),
        })
    return rows


@login_required
def activity(request):
    events = AuditLog.objects.filter(user=request.user)[:200]
    return render(request, "vault/activity.html", {"events": events})


# --------------------------------------------------------------------------- upload
def _drain(request) -> None:
    """Discard the unread request body so the keep-alive connection stays in sync and
    the browser receives our JSON error instead of a connection reset."""
    try:
        while request.read(1024 * 1024):
            pass
    except OSError:
        pass


def _encrypt_upload(request, name: str, ext: str, declared_length: int) -> EncryptedFile:
    """Stream request body -> validate first chunk -> encrypt chunk by chunk -> disk.
    Plaintext is never written to disk and at most ~2 MiB of it is in memory."""
    file_id = uuid.uuid4()
    data_key, base_nonce = crypto.generate_file_secrets()
    wrapped_key, wrap_nonce = crypto.wrap_key(data_key, file_id)
    os.makedirs(settings.FILE_STORAGE_DIR, exist_ok=True)
    tmp, final = storage_path(f"{file_id}.part"), blob_path(file_id)
    plain_total = 0

    def validated_chunks():
        nonlocal plain_total
        for index, chunk in enumerate(crypto.iter_plain_chunks(request.read)):
            if index == 0:
                check_magic(ext, chunk)                       # magic bytes, on the first 1 MiB
            plain_total += len(chunk)
            if plain_total > settings.MAX_UPLOAD_BYTES:       # Django-side 1 GB limit (defence in depth)
                raise UploadRejected("File exceeds the 1 GB limit.", 413)
            yield chunk

    try:
        enc_total = 0
        with open(tmp, "xb") as out:
            for ct in crypto.encrypt_chunks(validated_chunks(), data_key, base_nonce, file_id):
                out.write(ct)
                enc_total += len(ct)
            out.flush()
            os.fsync(out.fileno())
        if plain_total == 0:
            raise UploadRejected("Empty files are not accepted.")
        if plain_total != declared_length:
            raise UploadRejected("Upload was incomplete.")
        os.replace(tmp, final)                                # atomic: no half-written .enc ever exists
        try:
            return EncryptedFile.objects.create(
                id=file_id, owner=request.user, original_name=name,
                plaintext_size=plain_total, encrypted_size=enc_total,
                chunk_size=crypto.CHUNK_SIZE, chunk_count=math.ceil(plain_total / crypto.CHUNK_SIZE),
                algorithm=crypto.ALGORITHM, base_nonce=base_nonce,
                wrapped_key=wrapped_key, wrap_nonce=wrap_nonce,
                master_key_version=settings.MASTER_KEY_VERSION,
            )
        except Exception:
            _remove_quietly(final)
            raise
    except BaseException:
        _remove_quietly(tmp)
        raise


@require_POST
def upload(request):
    """Raw-body upload (not multipart): the browser PUTs the File bytes directly, so
    Django never spools plaintext to a temp file and we can encrypt on the fly.
    CSRF is still enforced (X-CSRFToken header, checked by the middleware)."""
    if not request.user.is_authenticated:
        return JsonResponse({"error": "Authentication required."}, status=401)

    name = clean_filename(unquote(request.headers.get("X-File-Name", "")))
    try:
        ext = check_extension(name)
        try:
            length = int(request.META.get("CONTENT_LENGTH", ""))
        except ValueError:
            raise UploadRejected("Content-Length header is required.", 411)
        if length > settings.MAX_UPLOAD_BYTES:
            raise UploadRejected("File exceeds the 1 GB limit.", 413)
        try:
            record = _encrypt_upload(request, name, ext, length)
        except UploadRejected:
            _drain(request)
            raise
    except UploadRejected as exc:
        audit(request, A.UPLOAD_REJECTED, file_name=name, detail=str(exc))
        return JsonResponse({"error": str(exc)}, status=exc.status)
    except OSError as exc:  # client aborted mid-upload, or disk problem
        log.warning("Upload failed: %s", exc)
        audit(request, A.UPLOAD_REJECTED, file_name=name, detail=f"upload interrupted: {type(exc).__name__}")
        return JsonResponse({"error": "Upload interrupted."}, status=400)

    audit(request, A.UPLOAD, file=record, detail=f"{record.plaintext_size} bytes -> {record.encrypted_size} bytes encrypted")
    return JsonResponse({"id": str(record.id), "name": record.original_name}, status=201)


# --------------------------------------------------------------------------- download
@login_required
@never_cache
def download(request, pk):
    f = get_owned_file(request, pk)
    path = blob_path(f.id)

    # PASS 1 - authenticate the WHOLE file before sending a single byte.
    # Streaming decrypt-as-you-go would hand the client the first N good chunks and then
    # fail, i.e. return partial data. Verifying first costs one extra sequential read
    # (still O(1 chunk) memory) and guarantees all-or-nothing.
    try:
        data_key = crypto.unwrap_key(f.wrapped_key, f.wrap_nonce, f.id)
        with open(path, "rb") as fh:
            crypto.verify_stream(fh, data_key, bytes(f.base_nonce), f.id, f.plaintext_size, f.chunk_size)
    except crypto.IntegrityError as exc:
        audit(request, A.DOWNLOAD_FAILED, file=f, detail=str(exc))
        return render(request, "vault/error.html", {
            "title": "Download rejected",
            "message": "SecureVault could not verify this file, so it was not sent. It was changed or damaged on disk after you uploaded it.",
            "reason": str(exc),
        }, status=500)
    except (OSError, crypto.MasterKeyError) as exc:
        log.error("Download error for %s: %s", f.id, exc)
        audit(request, A.DOWNLOAD_FAILED, file=f, detail=f"{type(exc).__name__}")
        return render(request, "vault/error.html", {
            "title": "Download unavailable", "message": "The stored file could not be read.", "reason": "",
        }, status=500)

    audit(request, A.DOWNLOAD, file=f, detail="integrity verified, streaming")

    # PASS 2 - stream-decrypt. Every chunk is authenticated again (the file could have
    # changed between the passes). If that ever happens we abort the connection; because
    # Content-Length is exact, the client sees an incomplete download, not a "valid" short file.
    def stream():
        try:
            with open(path, "rb") as fh:
                yield from crypto.decrypt_chunks(fh.read, data_key, bytes(f.base_nonce), f.id, f.chunk_size)
        except crypto.IntegrityError as exc:
            audit(request, A.DOWNLOAD_FAILED, file=f, detail=f"changed during download: {exc}")
            raise

    response = StreamingHttpResponse(stream(), content_type="application/octet-stream")
    response["Content-Length"] = str(f.plaintext_size)
    response["Content-Disposition"] = content_disposition_header(True, f.original_name)
    response["X-Content-Type-Options"] = "nosniff"
    return response


# --------------------------------------------------------------------------- delete
@login_required
@require_POST
def delete(request, pk):
    f = get_owned_file(request, pk)
    name, fid = f.original_name, f.id
    # Delete the DB row first: that destroys the wrapped data key, which alone makes the
    # ciphertext permanently undecryptable ("crypto-shredding"), even if the file
    # removal below were to fail or the blocks linger on disk.
    with transaction.atomic():
        audit(request, A.DELETE, file=f)
        f.delete()
    _remove_quietly(blob_path(fid))
    messages.success(request, f"Deleted “{name}”.")
    return redirect("file_list")
