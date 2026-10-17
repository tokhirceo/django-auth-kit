"""Biznes mantiq. View va form'lar yupqa; barcha qoidalar shu yerda."""
import logging
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.core.mail import send_mail
from django.db import IntegrityError, transaction
from django.db.models import F
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils import timezone

from . import signals
from .config.settings import accounts_settings, get_callable
from .models import DeletedAccount, EmailVerificationToken, PrivacySettings, User, Visibility

logger = logging.getLogger("accounts")

PENDING_KEY = "accounts_pending_user_id"

SENT = "sent"
COOLDOWN = "cooldown"
FAILED = "failed"
NOOP = "noop"

VERIFIED = "verified"
EMAIL_CHANGED = "email_changed"
INVALID = "invalid"
TAKEN = "taken"


class AccountsError(Exception):
    pass


class IdentifierTakenError(AccountsError):
    pass


class LastSuperuserError(AccountsError):
    pass


class LifecycleError(AccountsError):
    pass


def _now():
    return timezone.now()


# ------------------------------------------------------------------ havolalar
def build_absolute_url(path, request=None):
    site_url = accounts_settings.SITE_URL
    if site_url:
        return site_url.rstrip("/") + path
    if request is not None:
        return request.build_absolute_uri(path)  # ALLOWED_HOSTS tekshiradi
    if settings.DEBUG:
        return "http://localhost:8000" + path
    raise ImproperlyConfigured("So'rovsiz kontekstda (command/task) site URL sozlamasi berilishi shart.")


def from_email():
    return accounts_settings.FROM_EMAIL or None


# ------------------------------------------------------- privilegiya yaxlitligi
def _lock_active_superuser_ids():
    qs = (
        User.objects.select_for_update()
        .filter(is_superuser=True, is_active=True, deletion_requested_at__isnull=True)
        .order_by("pk")
    )
    return set(qs.values_list("pk", flat=True))


def guard_privilege_change(user_pk, *, new_is_superuser=None, new_is_active=None, removing=False):
    """Oxirgi faol superuser qoidasi (yagona joy).

    Barcha faol superuser qatorlari ``select_for_update`` bilan qulflanadi
    (PostgreSQL'da; SQLite'da no-op). ``LastSuperuserError`` ko'taradi.
    """
    with transaction.atomic():
        active_ids = _lock_active_superuser_ids()
        if user_pk not in active_ids:
            return
        loses = removing or new_is_superuser is False or new_is_active is False
        if loses and not (active_ids - {user_pk}):
            raise LastSuperuserError("Oxirgi faol superuser'ni o'zgartirib yoki o'chirib bo'lmaydi.")


def would_remove_last_superuser(user, *, new_is_superuser, new_is_active):
    """Admin formasi uchun tezkor (qulfsiz) tekshiruv."""
    if not (user.pk and user.is_superuser and user.is_active and not user.deletion_requested_at):
        return False
    if new_is_superuser and new_is_active:
        return False
    others = (
        User.objects.filter(is_superuser=True, is_active=True, deletion_requested_at__isnull=True)
        .exclude(pk=user.pk)
        .exists()
    )
    return not others


def _lock_user(user):
    """Foydalanuvchi qatorini qulflaydi (PostgreSQL: ``SELECT ... FOR UPDATE``; SQLite'da no-op) va
    ob'ektni DB holatiga yangilaydi. Faqat ``transaction.atomic()`` ichida chaqiriladi.
    ``User.DoesNotExist`` ko'taradi (qator allaqachon o'chgan bo'lsa)."""
    if not User.objects.select_for_update().filter(pk=user.pk).exists():
        raise User.DoesNotExist
    user.refresh_from_db()
    return user


def invalidate_user_sessions(user):
    """session_epoch'ni oshiradi: eski sessiyalar va reset tokenlari bekor bo'ladi."""
    User.objects.filter(pk=user.pk).update(session_epoch=F("session_epoch") + 1)
    user.refresh_from_db(fields=["session_epoch"])
    EmailVerificationToken.objects.filter(user=user, used_at__isnull=True).delete()


@transaction.atomic
def update_privileges(user, *, role=None, is_superuser=None, is_staff=None, is_active=None):
    """Rol/privilegiyani o'zgartirishning yagona yo'li (set_role, admin)."""
    _lock_user(user)
    new_super = user.is_superuser if is_superuser is None else is_superuser
    new_staff = user.is_staff if is_staff is None else is_staff
    new_active = user.is_active if is_active is None else is_active
    new_role = user.role
    if role is not None:
        if role not in User.Role.values:
            raise ValueError("Noma'lum rol.")
        new_role = role
        new_super = role == User.Role.SUPERUSER
        if new_super:
            new_staff = True
    if new_active and user.deletion_requested_at:
        raise LifecycleError("O'chirish kutilayotgan hisobni qayta yoqib bo'lmaydi.")
    guard_privilege_change(user.pk, new_is_superuser=new_super, new_is_active=new_active)
    was_active = user.is_active
    user.role, user.is_superuser, user.is_staff, user.is_active = new_role, new_super, new_staff, new_active
    if not was_active and new_active:
        user.deactivated_at = None
    user.save()
    if was_active and not new_active:
        invalidate_user_sessions(user)
        signals.audit("account_blocked", user.pk)
    signals.audit("privileges_updated", user.pk)
    return user


def set_role(user, role):
    return update_privileges(user, role=role)


# ---------------------------------------------------------------- email xizmati
def _hours(seconds):
    return max(1, round(seconds / 3600))


def _render_subject(template, ctx):
    return "".join(render_to_string(template, ctx).splitlines()).strip()


def send_verification_email(user, request=None, *, email=None, respect_cooldown=True):
    """``SENT`` / ``COOLDOWN`` / ``FAILED`` qaytaradi (xatoni yutmaydi, log'laydi)."""
    target = email or user.email
    cooldown = accounts_settings.EMAIL_VERIFICATION_RESEND_COOLDOWN
    if respect_cooldown and cooldown:
        latest = EmailVerificationToken.objects.filter(user=user).order_by("-created_at").first()
        if latest and latest.created_at > _now() - timedelta(seconds=cooldown):
            return COOLDOWN
    raw = EmailVerificationToken.issue(user, target)
    url = build_absolute_url(reverse("accounts:verify_email", args=[raw]), request)
    ctx = {
        "user": user,
        "verify_url": url,
        "is_change": target.lower() != user.email.lower(),
        "timeout_hours": _hours(accounts_settings.EMAIL_VERIFICATION_TIMEOUT),
    }
    try:
        subject = _render_subject("accounts/email/verify_email_subject.txt", ctx)
        body = render_to_string("accounts/email/verify_email.txt", ctx)
        html = render_to_string("accounts/email/verify_email.html", ctx)
        send_mail(subject, body, from_email(), [target], fail_silently=False, html_message=html)
    except Exception:
        logger.exception("verification xati yuborilmadi user_id=%s", user.pk)
        EmailVerificationToken.objects.filter(token_hash=EmailVerificationToken.hash_token(raw)).delete()
        return FAILED
    signals.audit("verification_email_sent", user.pk)
    return SENT


def send_password_reset_email(*, user, to_email, reset_url):
    """Reset xati: istisno yutiladi va log'lanadi (foydalanuvchiga baribir bir xil javob)."""
    ctx = {"user": user, "reset_url": reset_url}
    try:
        subject = _render_subject("accounts/email/password_reset_subject.txt", ctx)
        body = render_to_string("accounts/email/password_reset_email.txt", ctx)
        html = render_to_string("accounts/email/password_reset_email.html", ctx)
        send_mail(subject, body, from_email(), [to_email], fail_silently=False, html_message=html)
    except Exception:
        logger.exception("parol tiklash xati yuborilmadi user_id=%s", user.pk)
        return False
    return True


def get_pending_user(request):
    """Verification kutayotgan (hali kirmagan) foydalanuvchi; faqat rejim yoqilganda."""
    if not accounts_settings.REQUIRE_EMAIL_VERIFICATION:
        request.session.pop(PENDING_KEY, None)
        return None
    pk = request.session.get(PENDING_KEY)
    if pk is None:
        return None
    user = User.objects.live().filter(pk=pk, is_active=True, is_email_verified=False).first()
    if user is None:
        request.session.pop(PENDING_KEY, None)
    return user


def resend_verification(user, request=None):
    if user.pending_email:
        return send_verification_email(user, request, email=user.pending_email)
    if not user.is_email_verified:
        return send_verification_email(user, request)
    return NOOP


@transaction.atomic
def confirm_email_token(raw):
    """Tokenni sarflaydi (faqat POST'dan chaqiriladi). ``(status, user)``."""
    token = EmailVerificationToken.find_valid(raw, lock=True)
    if token is None:
        return INVALID, None
    user = User.objects.select_for_update().get(pk=token.user_id)
    if user.deletion_requested_at:
        return INVALID, None
    token.used_at = _now()
    token.save(update_fields=["used_at"])
    email = token.email.lower()
    if email == user.email.lower():
        user.is_email_verified = True
        user.save(update_fields=["is_email_verified"])
        status = VERIFIED
    elif user.pending_email and email == user.pending_email.lower():
        if User.objects.identifier_taken(email=user.pending_email, exclude_pk=user.pk):
            user.pending_email = ""
            user.save(update_fields=["pending_email"])
            return TAKEN, user
        new_email = user.pending_email
        try:
            with transaction.atomic():  # savepoint: DB constraint poygadan oxirgi himoya
                user.email = new_email
                user.pending_email = ""
                user.is_email_verified = True
                user.save(update_fields=["email", "pending_email", "is_email_verified"])
        except IntegrityError:
            user.refresh_from_db()
            user.pending_email = ""
            user.save(update_fields=["pending_email"])
            return TAKEN, user
        status = EMAIL_CHANGED
    else:
        return INVALID, user
    signals.audit("email_verified", user.pk)
    transaction.on_commit(lambda: signals.emit(signals.email_verified, user=user))
    return status, user


def request_email_change(user, new_email, request=None):
    """Yangi manzil tasdiqlanmaguncha eski email amal qiladi (``pending_email``).

    Band manzil uchun ham tashqi javob bir xil (``NOOP``): enumeration yo'q.
    """
    new_email = User.objects.normalize_email((new_email or "").strip())
    with transaction.atomic():
        _lock_user(user)
        if new_email.lower() == user.email.lower():
            return NOOP
        if User.objects.identifier_taken(email=new_email, exclude_pk=user.pk):
            return NOOP
        user.pending_email = new_email
        user.save(update_fields=["pending_email"])
    signals.audit("email_change_requested", user.pk)
    return send_verification_email(user, request, email=new_email, respect_cooldown=False)


# ------------------------------------------------------------------ ro'yxatdan o'tish
def register_user(*, username, email, password, request=None):
    try:
        with transaction.atomic():
            user = User.objects.create_user(username=username, email=email, password=password)
    except IntegrityError:
        raise IdentifierTakenError from None
    signals.audit("user_signed_up", user.pk)
    transaction.on_commit(lambda: signals.emit(signals.user_signed_up, user=user))
    result = None
    if accounts_settings.REQUIRE_EMAIL_VERIFICATION:
        result = send_verification_email(user, request)
    return user, result


# ------------------------------------------------------------------------ lifecycle
@transaction.atomic
def deactivate_account(user):
    _lock_user(user)
    if not user.is_active or user.deletion_requested_at:
        return False
    guard_privilege_change(user.pk, new_is_active=False)
    user.is_active = False
    user.deactivated_at = _now()
    user.save(update_fields=["is_active", "deactivated_at"])
    invalidate_user_sessions(user)
    signals.audit("account_deactivated", user.pk)
    transaction.on_commit(lambda: signals.emit(signals.account_deactivated, user=user))
    return True


def reactivate_account(identifier, password):
    """O'zi faolsizlantirgan hisobni parol bilan qayta yoqadi. Aks holda ``None``."""
    user = User.objects.find_by_identifier(identifier)
    if user is None:
        User().set_password(password)
        return None
    if not user.check_password(password):
        return None
    with transaction.atomic():
        try:
            _lock_user(user)  # parol tekshiruvi va holat o'zgarishi orasida holat o'zgargan bo'lishi mumkin
        except User.DoesNotExist:
            return None
        if user.is_active or user.deactivated_at is None or user.deletion_requested_at:
            return None  # ACTIVE, BLOCKED (admin) yoki DELETION_PENDING
        user.is_active = True
        user.deactivated_at = None
        user.save(update_fields=["is_active", "deactivated_at"])
    signals.audit("account_reactivated", user.pk)
    transaction.on_commit(lambda: signals.emit(signals.account_reactivated, user=user))
    return user


def delete_file_on_commit(storage, name):
    if not name:
        return

    def _delete():
        try:
            storage.delete(name)
        except Exception:
            logger.exception("fayl o'chirilmadi")

    transaction.on_commit(_delete)


@transaction.atomic
def hard_delete_user(user, *, guard=True):
    if guard:
        guard_privilege_change(user.pk, removing=True)
    user_id = user.pk
    avatar_name = user.avatar.name if user.avatar else ""
    storage = user.avatar.storage
    DeletedAccount.objects.create(user_id=user_id)
    user.delete()
    delete_file_on_commit(storage, avatar_name)
    signals.audit("account_deleted", user_id)
    transaction.on_commit(lambda: signals.emit(signals.account_deleted, user_id=user_id))


@transaction.atomic
def delete_user_account(user):
    """grace=0 -> ``"deleted"`` (darhol); grace>0 -> ``"pending"``; takror -> ``False``."""
    try:
        _lock_user(user)
    except User.DoesNotExist:
        return False
    if user.deletion_requested_at:
        return False
    if accounts_settings.DELETION_GRACE_PERIOD == 0:
        hard_delete_user(user)
        return "deleted"
    guard_privilege_change(user.pk, removing=True)
    user.is_active = False
    user.deletion_requested_at = _now()
    user.save(update_fields=["is_active", "deletion_requested_at"])
    invalidate_user_sessions(user)
    signals.audit("account_deletion_requested", user.pk)
    transaction.on_commit(lambda: signals.emit(signals.account_deletion_requested, user=user))
    return "pending"


def purge_deleted_accounts(now=None):
    now = now or _now()
    cutoff = now - timedelta(seconds=accounts_settings.DELETION_GRACE_PERIOD)
    count = 0
    for user in User.objects.filter(deletion_requested_at__isnull=False, deletion_requested_at__lte=cutoff):
        hard_delete_user(user, guard=False)  # kutilayotgan superuser allaqachon "faol" emas
        count += 1
    return count


# ------------------------------------------------------------------ ommaviy profil
def get_privacy(user):
    """GET'da yozmaydi: yozuv yo'q bo'lsa saqlanmagan default qaytaradi."""
    try:
        return user.privacy
    except PrivacySettings.DoesNotExist:
        return PrivacySettings(user=user)


def _can_see(level, viewer, target):
    if viewer.is_authenticated and viewer.pk == target.pk:
        return True
    if level == Visibility.PUBLIC:
        return True
    if level == Visibility.MEMBERS:
        return bool(viewer.is_authenticated)
    return False


def get_public_profile(viewer, target):
    """Maxfiylik sozlamalariga ko'ra ko'rinadigan maydonlar (``dict``) yoki ``None``."""
    if not target.is_active or target.deletion_requested_at:
        return None
    is_self = viewer.is_authenticated and viewer.pk == target.pk
    if viewer.is_authenticated and not is_self:
        callback = get_callable("IS_BLOCKED_CALLBACK")
        if callback is not None and callback(viewer, target):
            return None
    privacy = get_privacy(target)
    data = {"id": target.pk, "username": target.username, "is_self": bool(is_self)}
    data["full_name"] = target.get_full_name() if _can_see(privacy.name_visibility, viewer, target) else ""
    data["display_name"] = data["full_name"] or target.username
    data["email"] = target.email if _can_see(privacy.email_visibility, viewer, target) else ""
    data["phone"] = target.phone if _can_see(privacy.phone_visibility, viewer, target) else ""
    data["bio"] = target.bio if _can_see(privacy.bio_visibility, viewer, target) else ""
    data["avatar_url"] = (
        target.avatar.url if target.avatar and _can_see(privacy.avatar_visibility, viewer, target) else ""
    )
    return data
