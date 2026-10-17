"""Rate limiting: ixtiyoriy tashqi limiter yoki Django cache'dagi default limiter."""
import hashlib
import logging
from functools import wraps

from django.core.cache import cache
from django.shortcuts import render

from .config.settings import get_callable, get_rate_limit

logger = logging.getLogger("accounts")


def client_ip(request):
    getter = get_callable("CLIENT_IP_GETTER")
    if getter is not None:
        return str(getter(request))
    return request.META.get("REMOTE_ADDR", "") or "unknown"


def _hit(key, limit, window):
    """Atomik hisoblagich: ``cache.add`` + ``cache.incr``. ``True`` = ruxsat."""
    if cache.add(key, 1, timeout=window):
        count = 1
    else:
        try:
            count = cache.incr(key)
        except ValueError:  # kalit shu orada muddati tugab o'chdi
            cache.add(key, 1, timeout=window)
            count = 1
    return count <= limit


def _default_allow(request, scope, identifier=None):
    limit, window = get_rate_limit(scope)
    ip = client_ip(request)
    allowed = _hit(f"accounts:rl:{scope}:ip:{ip}", limit, window)
    if identifier:
        digest = hashlib.sha256(identifier.strip().lower().encode()).hexdigest()[:16]
        # identifikator IP bilan birga: faqat identifikator bo'yicha kalit yo'q (qurbonni bloklash DoS'i)
        allowed = _hit(f"accounts:rl:{scope}:id:{ip}:{digest}", limit, window) and allowed
    return allowed


def allow(request, scope, identifier=None):
    """``True`` = so'rovga ruxsat. Xatoda fail-open (autentifikatsiya to'xtab qolmasin)."""
    try:
        limiter = get_callable("RATE_LIMITER")
        if limiter is not None:
            return bool(limiter(request, scope))
        return _default_allow(request, scope, identifier)
    except Exception:
        logger.error("rate limiter xatosi (fail-open), scope=%s", scope, exc_info=True)
        return True


class RateLimitMixin:
    """CBV uchun: ``rate_scope`` bo'yicha POST so'rovlarini cheklaydi (429)."""

    rate_scope = None

    def get_rate_identifier(self, request):
        return None

    def dispatch(self, request, *args, **kwargs):
        if self.rate_scope and request.method == "POST":
            if not allow(request, self.rate_scope, self.get_rate_identifier(request)):
                return render(request, "accounts/rate_limited.html", status=429)
        return super().dispatch(request, *args, **kwargs)


def rate_limit(scope, identifier=None):
    """Funksiya-view (yoki ``method_decorator``) uchun: POST so'rovlarni ``scope`` bo'yicha cheklaydi (429).

    ``identifier`` — ixtiyoriy ``f(request) -> str`` (masalan, loginda ``request.POST.get("username")``).
    Mixin bilan bir xil limiter: tashqi limiter sozlangan bo'lsa shu ustun, aks holda cache limiter.
    """

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if request.method == "POST":
                ident = identifier(request) if identifier else None
                if not allow(request, scope, ident):
                    return render(request, "accounts/rate_limited.html", status=429)
            return view(request, *args, **kwargs)

        return wrapper

    return decorator
