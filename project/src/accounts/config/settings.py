"""accounts konfiguratsiyasi: yagona manba.

Bu modul toza Python: modellar, ``apps`` va ``accounts.services`` ni import
qilmaydi. Standart qiymatlar faqat shu yerda turadi. Qiymatlar chaqiruv
vaqtida ``django.conf.settings`` dan o'qiladi (``override_settings`` ishlaydi).
"""
import re
import warnings
from email.utils import parseaddr

from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.validators import validate_email
from django.utils.module_loading import import_string

PREFIX = "ACCOUNTS_"

RATE_SCOPES = (
    "login",
    "signup",
    "password_reset",
    "verify_email",
    "resend_verification",
    "email_change",
    "reactivate",
)

DEFAULT_RATE_LIMITS = {
    "login": "10/5m",
    "signup": "10/h",
    "password_reset": "5/h",
    "verify_email": "20/h",
    "resend_verification": "5/h",
    "email_change": "5/h",
    "reactivate": "10/h",
}

ACCOUNTS_DEFAULTS = {
    "ACCOUNTS_REQUIRE_EMAIL_VERIFICATION": False,
    "ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT": 86400,
    "ACCOUNTS_EMAIL_VERIFICATION_RESEND_COOLDOWN": 60,
    "ACCOUNTS_DELETION_GRACE_PERIOD": 0,
    "ACCOUNTS_SITE_URL": "",
    "ACCOUNTS_FROM_EMAIL": None,
    "ACCOUNTS_RATE_LIMITER": None,
    "ACCOUNTS_RATE_LIMITS": dict(DEFAULT_RATE_LIMITS),
    "ACCOUNTS_CLIENT_IP_GETTER": None,
    "ACCOUNTS_IS_BLOCKED_CALLBACK": None,
    "ACCOUNTS_AVATAR_MAX_BYTES": 2 * 1024 * 1024,
    "ACCOUNTS_AVATAR_MAX_SIDE": 6000,
    "ACCOUNTS_AVATAR_MAX_PIXELS": 24_000_000,
    "ACCOUNTS_AVATAR_OUTPUT_SIZE": 512,
}

# eski nom -> kanonik nom (deprecated alias)
LEGACY_ALIASES = {
    "REQUIRE_EMAIL_VERIFICATION": "ACCOUNTS_REQUIRE_EMAIL_VERIFICATION",
    "EMAIL_VERIFICATION_TIMEOUT": "ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT",
    "EMAIL_VERIFICATION_RESEND_COOLDOWN": "ACCOUNTS_EMAIL_VERIFICATION_RESEND_COOLDOWN",
    "ACCOUNT_DELETION_GRACE_PERIOD": "ACCOUNTS_DELETION_GRACE_PERIOD",
}

SECRET_KEYS = {"EMAIL_HOST_PASSWORD"}


def _canonical(name):
    key = name if name.startswith(PREFIX) else PREFIX + name
    if key not in ACCOUNTS_DEFAULTS:
        raise KeyError(name)
    return key


def read(settings_obj, name):
    """``settings_obj`` dan kanonik nom bo'yicha qiymatni o'qiydi."""
    key = _canonical(name)
    for legacy, canon in LEGACY_ALIASES.items():
        if canon == key and hasattr(settings_obj, legacy):
            warnings.warn(
                f"{legacy} eskirgan; {key} dan foydalaning.",
                DeprecationWarning,
                stacklevel=3,
            )
            if not hasattr(settings_obj, key):
                return getattr(settings_obj, legacy)
    if hasattr(settings_obj, key):
        return getattr(settings_obj, key)
    return ACCOUNTS_DEFAULTS[key]


def get(name):
    from django.conf import settings

    return read(settings, name)


class _AccountsSettings:
    """``accounts_settings.REQUIRE_EMAIL_VERIFICATION`` uslubidagi o'qish."""

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return get(name)
        except KeyError:
            raise AttributeError(name) from None

    def __dir__(self):
        return [k[len(PREFIX):] for k in ACCOUNTS_DEFAULTS]

    def __repr__(self):
        return "<accounts_settings>"


accounts_settings = _AccountsSettings()


def redact(mapping):
    """Maxfiy kalitlar niqoblangan nusxa (log/repr uchun)."""
    return {k: ("***" if k in SECRET_KEYS else v) for k, v in dict(mapping).items()}


# --------------------------------------------------------------- yordamchilar
_RATE_RE = re.compile(r"^(\d+)/(\d*)([smh])$")
_UNITS = {"s": 1, "m": 60, "h": 3600}


def parse_rate(spec):
    """``"10/5m"`` -> ``(10, 300)``. Yaroqsiz bo'lsa ``ValueError``."""
    match = _RATE_RE.match(spec) if isinstance(spec, str) else None
    if not match:
        raise ValueError(spec)
    count, mult, unit = match.groups()
    count, seconds = int(count), int(mult or 1) * _UNITS[unit]
    if count < 1 or seconds < 1:
        raise ValueError(spec)
    return count, seconds


def get_rate_limit(scope):
    limits = dict(DEFAULT_RATE_LIMITS)
    limits.update(get("RATE_LIMITS") or {})
    return parse_rate(limits[scope])


def get_callable(name):
    """``None`` yoki chaqiriladigan obyekt (dotted path import qilinadi)."""
    return resolve_callable(get(name), PREFIX + name)


def resolve_callable(value, name="callable"):
    if value is None:
        return None
    if isinstance(value, str):
        try:
            value = import_string(value)
        except ImportError as exc:
            raise ImproperlyConfigured(f"{name}: import bo'lmadi ({exc.__class__.__name__}).") from None
    if not callable(value):
        raise ImproperlyConfigured(f"{name}: callable yoki dotted path bo'lishi kerak.")
    return value


_BOOL_TRUE = {"1", "true", "yes", "on"}
_BOOL_FALSE = {"0", "false", "no", "off"}

_ENV_SPECS = {
    "ACCOUNTS_REQUIRE_EMAIL_VERIFICATION": bool,
    "ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT": int,
    "ACCOUNTS_EMAIL_VERIFICATION_RESEND_COOLDOWN": int,
    "ACCOUNTS_DELETION_GRACE_PERIOD": int,
    "ACCOUNTS_SITE_URL": str,
    "ACCOUNTS_FROM_EMAIL": str,
    "ACCOUNTS_RATE_LIMITER": str,
    "ACCOUNTS_CLIENT_IP_GETTER": str,
    "ACCOUNTS_IS_BLOCKED_CALLBACK": str,
    "ACCOUNTS_AVATAR_MAX_BYTES": int,
    "ACCOUNTS_AVATAR_MAX_SIDE": int,
    "ACCOUNTS_AVATAR_MAX_PIXELS": int,
    "ACCOUNTS_AVATAR_OUTPUT_SIZE": int,
    "EMAIL_BACKEND": str,
    "EMAIL_HOST": str,
    "EMAIL_PORT": int,
    "EMAIL_HOST_USER": str,
    "EMAIL_HOST_PASSWORD": str,
    "EMAIL_USE_TLS": bool,
    "EMAIL_USE_SSL": bool,
    "DEFAULT_FROM_EMAIL": str,
    "SERVER_EMAIL": str,
}


def from_env(environ=None):
    """Muhit o'zgaruvchilaridan tiplangan qiymatlar (faqat berilganlari)."""
    if environ is None:
        import os

        environ = os.environ
    result = {}
    for name, typ in _ENV_SPECS.items():
        raw = environ.get(name)
        if raw is None or raw == "":
            continue
        try:
            if typ is bool:
                low = raw.strip().lower()
                if low in _BOOL_TRUE:
                    result[name] = True
                elif low in _BOOL_FALSE:
                    result[name] = False
                else:
                    raise ValueError
            elif typ is int:
                result[name] = int(raw.strip())
            else:
                result[name] = raw
        except ValueError:
            # qiymat xabarga qo'shilmaydi (maxfiy bo'lishi mumkin)
            raise ImproperlyConfigured(
                f"{name} muhit o'zgaruvchisi yaroqsiz (kutilgan tur: {typ.__name__})."
            ) from None
    return result


# ------------------------------------------------------------------ validate
def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_from_email(value):
    name, addr = parseaddr(value)
    try:
        validate_email(addr)
    except ValidationError:
        return False
    return True


def validate(settings_obj):
    """``(level, id, message)`` ro'yxati; level: ``"E"`` yoki ``"W"``."""
    out = []

    def r(name):
        return read(settings_obj, name)

    def err(code, msg):
        out.append(("E", f"accounts.E{code:03d}", msg))

    def warn(code, msg):
        out.append(("W", f"accounts.W{code:03d}", msg))

    if not isinstance(r("REQUIRE_EMAIL_VERIFICATION"), bool):
        err(1, "ACCOUNTS_REQUIRE_EMAIL_VERIFICATION bool bo'lishi kerak.")
    v = r("EMAIL_VERIFICATION_TIMEOUT")
    if not _is_int(v) or v <= 0:
        err(2, "ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT 0 dan katta butun son bo'lishi kerak.")
    v = r("EMAIL_VERIFICATION_RESEND_COOLDOWN")
    if not _is_int(v) or v < 0:
        err(3, "ACCOUNTS_EMAIL_VERIFICATION_RESEND_COOLDOWN manfiy bo'lmagan butun son bo'lishi kerak.")
    v = r("DELETION_GRACE_PERIOD")
    if not _is_int(v) or v < 0:
        err(4, "ACCOUNTS_DELETION_GRACE_PERIOD manfiy bo'lmagan butun son bo'lishi kerak.")

    debug = bool(getattr(settings_obj, "DEBUG", False))
    site_url = r("SITE_URL")
    if site_url not in ("", None):
        if not isinstance(site_url, str) or not re.match(r"^https?://[^/\s?#]+$", site_url):
            err(5, "ACCOUNTS_SITE_URL 'http(s)://host[:port]' ko'rinishida (yo'lsiz) bo'lishi kerak.")
        elif not debug and site_url.startswith("http://"):
            warn(1, "ACCOUNTS_SITE_URL production'da https:// bo'lishi kerak.")
    from_email = r("FROM_EMAIL")
    if from_email is not None and (not isinstance(from_email, str) or not _valid_from_email(from_email)):
        err(6, "ACCOUNTS_FROM_EMAIL email yoki 'Ism <e@x>' bo'lishi kerak.")

    for code, name in ((7, "RATE_LIMITER"), (9, "CLIENT_IP_GETTER"), (10, "IS_BLOCKED_CALLBACK")):
        try:
            resolve_callable(r(name), PREFIX + name)
        except ImproperlyConfigured as exc:
            err(code, str(exc))

    limits = r("RATE_LIMITS")
    if not isinstance(limits, dict):
        err(8, "ACCOUNTS_RATE_LIMITS dict bo'lishi kerak.")
    else:
        for scope, spec in limits.items():
            if scope not in RATE_SCOPES:
                err(8, f"ACCOUNTS_RATE_LIMITS: noma'lum scope '{scope}'.")
                continue
            try:
                parse_rate(spec)
            except ValueError:
                err(8, f"ACCOUNTS_RATE_LIMITS['{scope}'] 'N/<s|m|h>' ko'rinishida bo'lishi kerak.")

    for name in ("AVATAR_MAX_BYTES", "AVATAR_MAX_SIDE", "AVATAR_MAX_PIXELS", "AVATAR_OUTPUT_SIZE"):
        v = r(name)
        if not _is_int(v) or v <= 0:
            err(11, f"ACCOUNTS_{name} 0 dan katta butun son bo'lishi kerak.")

    if getattr(settings_obj, "EMAIL_USE_TLS", False) and getattr(settings_obj, "EMAIL_USE_SSL", False):
        err(12, "EMAIL_USE_TLS va EMAIL_USE_SSL birga True bo'lishi mumkin emas.")
    if getattr(settings_obj, "AUTH_USER_MODEL", "auth.User") != "accounts.User":
        err(13, "AUTH_USER_MODEL = 'accounts.User' bo'lishi kerak.")

    if not debug:
        backend = str(getattr(settings_obj, "EMAIL_BACKEND", ""))
        if any(x in backend for x in ("console", "locmem", "dummy")):
            warn(3, "EMAIL_BACKEND production uchun mos emas (console/locmem/dummy).")
        if getattr(settings_obj, "DEFAULT_FROM_EMAIL", "webmaster@localhost") == "webmaster@localhost":
            warn(4, "DEFAULT_FROM_EMAIL standart qiymatda (webmaster@localhost).")
        hosts = getattr(settings_obj, "ALLOWED_HOSTS", [])
        if not site_url or "*" in hosts:
            warn(2, "Havola hosti xavfsiz emas: ACCOUNTS_SITE_URL bering va ALLOWED_HOSTS da '*' ishlatmang.")
        caches = getattr(settings_obj, "CACHES", {})
        if "locmem" in str(caches.get("default", {}).get("BACKEND", "")).lower():
            warn(5, "LocMemCache jarayonlar orasida ulashilmaydi: rate limit uchun shared cache ishlating.")
        if "accounts.backends.AccountsBackend" not in getattr(settings_obj, "AUTHENTICATION_BACKENDS", []):
            warn(6, "AUTHENTICATION_BACKENDS da accounts.backends.AccountsBackend yo'q.")
    return out
