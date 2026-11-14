from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from .audit import audit
from .models import AuditLog


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs):
    audit(request, AuditLog.Action.LOGIN, username=user.get_username())


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs):
    if user is not None:
        audit(request, AuditLog.Action.LOGOUT, username=user.get_username())


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs):
    if request is not None:
        audit(request, AuditLog.Action.LOGIN_FAILED, username=str(credentials.get("username", ""))[:150])
