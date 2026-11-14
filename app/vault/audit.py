import ipaddress
import socket
import time
from datetime import timedelta

from django.conf import settings
from django.utils import timezone

from .models import AuditLog


_resolved: dict[str, tuple[float, set[str]]] = {}
_RESOLVE_TTL = 30.0


def _host_ips(host: str) -> set[str]:
    """IPs of a Compose service name (e.g. 'mynginx'), cached briefly because a container's
    IP can change when it restarts. On lookup failure the old answer (or empty) is used,
    which fails closed: nobody is trusted."""
    now = time.monotonic()
    cached = _resolved.get(host)
    if cached and now - cached[0] < _RESOLVE_TTL:
        return cached[1]
    try:
        ips = {ai[4][0] for ai in socket.getaddrinfo(host, None)}
    except OSError:
        ips = cached[1] if cached else set()
    _resolved[host] = (now, ips)
    return ips


def is_trusted_proxy(addr: str | None) -> bool:
    """Is the TCP peer (REMOTE_ADDR) our Nginx container?"""
    try:
        ip = ipaddress.ip_address(addr or "")
    except ValueError:
        return False
    if any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in settings.TRUSTED_PROXY_CIDRS):
        return True
    for host in settings.TRUSTED_PROXY_HOSTS:
        if str(ip) in _host_ips(host):
            return True
    return False


def client_ip(request) -> str | None:
    """The real client address.

    The TCP peer Gunicorn sees is always the Nginx container, so REMOTE_ADDR alone would
    put every user behind one IP (one failed login would lock out everyone). Nginx sets
    X-Real-IP to the real $remote_addr, overwriting whatever the client sent. We honour that
    header ONLY if the TCP peer really is the trusted proxy; from anyone else it is ignored,
    so it can't be forged to dodge the lockout or poison the audit log.
    """
    peer = request.META.get("REMOTE_ADDR") or None
    if is_trusted_proxy(peer):
        forwarded = (request.META.get("HTTP_X_REAL_IP") or "").strip()
        try:
            return str(ipaddress.ip_address(forwarded))      # must be a single valid IP
        except ValueError:
            pass
    return peer


def audit(request, action, *, file=None, file_id=None, file_name="", detail="", username=None):
    user = getattr(request, "user", None)
    authed = bool(user and user.is_authenticated)
    return AuditLog.objects.create(
        action=action,
        user=user if authed else None,
        username=username if username is not None else (user.get_username() if authed else ""),
        ip_address=client_ip(request),
        file_id=file.id if file is not None else file_id,
        file_name=(file.original_name if file is not None else file_name)[:255],
        detail=detail[:500],
    )


def is_login_locked(request) -> bool:
    """True if this IP has too many recent failed logins. Uses the audit table as the
    counter so it works across all Gunicorn workers without extra infrastructure."""
    since = timezone.now() - timedelta(seconds=settings.LOGIN_LOCKOUT_SECONDS)
    failures = AuditLog.objects.filter(
        action=AuditLog.Action.LOGIN_FAILED, ip_address=client_ip(request), created_at__gte=since
    ).count()
    return failures >= settings.LOGIN_MAX_FAILURES
