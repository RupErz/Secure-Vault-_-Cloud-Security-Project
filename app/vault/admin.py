from django.contrib import admin

from .models import AuditLog, EncryptedFile


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ("created_at", "action", "username", "ip_address", "file_name", "detail")
    list_filter = ("action",)
    search_fields = ("username", "file_name", "detail", "ip_address")
    # The audit trail must be tamper-evident: read-only even for superusers.
    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False
    def has_delete_permission(self, request, obj=None): return False


@admin.register(EncryptedFile)
class EncryptedFileAdmin(admin.ModelAdmin):
    list_display = ("original_name", "owner", "plaintext_size", "uploaded_at")
    exclude = ("wrapped_key", "wrap_nonce", "base_nonce")
    readonly_fields = ("owner", "original_name", "plaintext_size", "encrypted_size", "chunk_size",
                       "chunk_count", "algorithm", "master_key_version")

    def has_add_permission(self, request): return False
