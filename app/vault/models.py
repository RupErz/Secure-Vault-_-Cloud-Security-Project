import uuid

from django.conf import settings
from django.db import models


class EncryptedFile(models.Model):
    """Metadata + crypto parameters for one encrypted file.

    The ciphertext lives on the private volume as  <FILE_STORAGE_DIR>/<id>.enc
    (random UUID name, no relation to the original name). Nothing here is secret
    on its own: the nonce is public by design, and the data key is stored only
    in WRAPPED (encrypted) form.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="files")
    original_name = models.CharField(max_length=255)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    plaintext_size = models.BigIntegerField()
    encrypted_size = models.BigIntegerField()
    chunk_size = models.PositiveIntegerField()
    chunk_count = models.PositiveIntegerField()

    algorithm = models.CharField(max_length=64)
    base_nonce = models.BinaryField(max_length=8)      # 8 random bytes; 4-byte counter appended per chunk
    wrapped_key = models.BinaryField(max_length=48)    # data key encrypted with the master key
    wrap_nonce = models.BinaryField(max_length=12)
    master_key_version = models.PositiveSmallIntegerField(default=1)

    class Meta:
        ordering = ["-uploaded_at"]
        indexes = [models.Index(fields=["owner", "-uploaded_at"])]

    def __str__(self):
        return f"{self.original_name} ({self.id})"


class AuditLog(models.Model):
    class Action(models.TextChoices):
        UPLOAD = "UPLOAD", "Upload"
        UPLOAD_REJECTED = "UPLOAD_REJECTED", "Upload rejected"
        DOWNLOAD = "DOWNLOAD", "Download"
        DOWNLOAD_FAILED = "DOWNLOAD_FAILED", "Download failed (integrity)"
        DELETE = "DELETE", "Delete"
        ACCESS_DENIED = "ACCESS_DENIED", "Failed access"
        LOGIN = "LOGIN", "Login"
        LOGIN_FAILED = "LOGIN_FAILED", "Login failed"
        LOGIN_BLOCKED = "LOGIN_BLOCKED", "Login blocked (rate limit)"
        LOGOUT = "LOGOUT", "Logout"
        REGISTER = "REGISTER", "Register"

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    action = models.CharField(max_length=20, choices=Action.choices, db_index=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL)
    username = models.CharField(max_length=150, blank=True)      # snapshot: survives user deletion
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    # Plain UUID, not a FK: the record must outlive the file it describes.
    file_id = models.UUIDField(null=True, blank=True)
    file_name = models.CharField(max_length=255, blank=True)
    detail = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self):
        return f"{self.created_at:%Y-%m-%d %H:%M:%S} {self.action} {self.username}"
