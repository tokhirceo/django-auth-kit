from functools import wraps

from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect

from .config.settings import accounts_settings
from .ratelimit import rate_limit  # noqa: F401  (ochiq API: accounts.decorators.rate_limit)


def role_required(*roles):
    """Anonim -> login; noto'g'ri rol -> 403."""

    def decorator(view):
        @wraps(view)
        def wrapper(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect_to_login(request.get_full_path())
            if request.user.role not in roles:
                raise PermissionDenied
            return view(request, *args, **kwargs)

        return wrapper

    return decorator


def teacher_required(view):
    return role_required("teacher", "superuser")(view)


class RoleRequiredMixin:
    allowed_roles = ()

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path())
        if request.user.role not in self.allowed_roles:
            raise PermissionDenied
        return super().dispatch(request, *args, **kwargs)


def email_verified_required(view):
    """Verification yoqilgan bo'lsa, tasdiqlanmagan foydalanuvchini to'xtatadi."""

    @wraps(view)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path())
        if accounts_settings.REQUIRE_EMAIL_VERIFICATION and not request.user.is_email_verified:
            return redirect("accounts:verification_required")
        return view(request, *args, **kwargs)

    return wrapper


class EmailVerifiedRequiredMixin:
    """CBV uchun ``email_verified_required`` ning ekvivalenti."""

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect_to_login(request.get_full_path())
        if accounts_settings.REQUIRE_EMAIL_VERIFICATION and not request.user.is_email_verified:
            return redirect("accounts:verification_required")
        return super().dispatch(request, *args, **kwargs)
