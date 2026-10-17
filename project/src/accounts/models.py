import hashlib
import os
import secrets
import uuid
from datetime import timedelta

from django.contrib.auth.models import AbstractUser
from django.core.validators import MinLengthValidator
from django.db import models
from django.db.models import Q
from django.db.models.functions import Lower
from django.utils import timezone
from django.utils.crypto import salted_hmac

from .config.settings import accounts_settings
from .managers import UserManager
from .validators import UnicodeUsernameValidator, phone_validator, validate_no_at_sign


def avatar_upload_path(instance, filename):
    """Yo'l foydalanuvchi bergan fayl nomiga bog'liq emas."""
    ext = os.path.splitext(filename or "")[1].lower().lstrip(".")
    if ext not in {"jpg", "png", "webp"}:
        ext = "jpg"
    return f"avatars/{instance.pk or 'new'}/{uuid.uuid4().hex}.{ext}"


class User(AbstractUser):
    class Role(models.TextChoices):
        USER = "user", "Foydalanuvchi"
        TEACHER = "teacher", "O'qituvchi"
        SUPERUSER = "superuser", "Superuser"

    # Unikallik DB'da shartli, case-insensitive constraint orqali (pastda).
    username = models.CharField(
        "foydalanuvchi nomi",
        max_length=150,
        validators=[UnicodeUsernameValidator(), validate_no_at_sign, MinLengthValidator(3)],
        help_text="3–150 belgi: harf, raqam va . + - _ belgilari.",
    )
    email = models.EmailField("email", max_length=254)
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.USER, db_index=True)
    avatar = models.ImageField(upload_to=avatar_upload_path, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    phone = models.CharField(max_length=20, blank=True, validators=[phone_validator])
    is_email_verified = models.BooleanField(default=False)
    pending_email = models.EmailField(max_length=254, blank=True)
    deactivated_at = models.DateTimeField(null=True, blank=True)
    deletion_requested_at = models.DateTimeField(null=True, blank=True)
    session_epoch = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    objects = UserManager()

    REQUIRED_FIELDS = ["email"]

    class Meta:
        constraints = [
            models.UniqueConstraint(
                Lower("username"),
                condition=Q(deletion_requested_at__isnull=True),
                name="accounts_user_username_ci_uniq",
            ),
            models.UniqueConstraint(
                Lower("email"),
                condition=Q(deletion_requested_at__isnull=True) & ~Q(email=""),
                name="accounts_user_email_ci_uniq",
            ),
        ]

    def save(self, *args, **kwargs):
        self.email = self.__class__.objects.normalize_email((self.email or "").strip())
        if self.is_superuser:
            self.role = self.Role.SUPERUSER
            self.is_staff = True
        elif self.role == self.Role.SUPERUSER:
            self.role = self.Role.USER
        update_fields = kwargs.get("update_fields")
        if update_fields is not None:
            kwargs["update_fields"] = set(update_fields) | {"email", "role", "is_staff", "updated_at"}
        super().save(*args, **kwargs)

    # --- sessiyani bekor qilish (session_epoch, 0 bo'lsa hash o'zgarmaydi)
    def _get_session_auth_hash(self, secret=None):
        base = super()._get_session_auth_hash(secret=secret)
        if self.session_epoch > 0:
            return salted_hmac(
                "accounts.User.session_epoch",
                f"{base}:{self.session_epoch}",
                secret=secret,
                algorithm="sha256",
            ).hexdigest()
        return base

    @property
    def is_deletion_pending(self):
        return self.deletion_requested_at is not None

    @property
    def full_name(self):
        return self.get_full_name()

    def __str__(self):
        return self.get_username()


class Visibility(models.TextChoices):
    PUBLIC = "public", "Hamma"
    MEMBERS = "members", "Faqat kirgan foydalanuvchilar"
    PRIVATE = "private", "Faqat men"


class PrivacySettings(models.Model):
    user = models.OneToOneField("accounts.User", on_delete=models.CASCADE, related_name="privacy")
    name_visibility = models.CharField(max_length=10, choices=Visibility.choices, default=Visibility.PUBLIC)
    email_visibility = models.CharField(max_length=10, choices=Visibility.choices, default=Visibility.PRIVATE)
    phone_visibility = models.CharField(max_length=10, choices=Visibility.choices, default=Visibility.PRIVATE)
    bio_visibility = models.CharField(max_length=10, choices=Visibility.choices, default=Visibility.PUBLIC)
    avatar_visibility = models.CharField(max_length=10, choices=Visibility.choices, default=Visibility.PUBLIC)

    class Meta:
        verbose_name = "maxfiylik sozlamasi"
        verbose_name_plural = "maxfiylik sozlamalari"

    def __str__(self):
        return f"PrivacySettings(user_id={self.user_id})"


class EmailVerificationToken(models.Model):
    user = models.ForeignKey("accounts.User", on_delete=models.CASCADE, related_name="verification_tokens")
    token_hash = models.CharField(max_length=64, unique=True)
    email = models.EmailField(max_length=254)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    @staticmethod
    def hash_token(raw):
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def issue(cls, user, email):
        """Yangi token yaratadi; foydalanuvchining eski ishlatilmaganlarini bekor qiladi."""
        cls.objects.filter(user=user, used_at__isnull=True).delete()
        raw = secrets.token_urlsafe(32)
        cls.objects.create(
            user=user,
            token_hash=cls.hash_token(raw),
            email=email,
            expires_at=timezone.now() + timedelta(seconds=accounts_settings.EMAIL_VERIFICATION_TIMEOUT),
        )
        return raw

    @classmethod
    def find_valid(cls, raw, *, lock=False):
        qs = cls.objects.select_related("user")
        if lock:
            qs = qs.select_for_update(of=("self",))
        token = qs.filter(token_hash=cls.hash_token(raw or "")).first()
        if token is None or token.used_at is not None or token.expires_at <= timezone.now():
            return None
        return token

    def __str__(self):
        return f"EmailVerificationToken(user_id={self.user_id})"


class DeletedAccount(models.Model):
    """PII'siz tombstone: faqat user_id va vaqt."""

    user_id = models.BigIntegerField(db_index=True)
    deleted_at = models.DateTimeField(default=timezone.now)

    class Meta:
        verbose_name = "o'chirilgan hisob"
        verbose_name_plural = "o'chirilgan hisoblar"

    def __str__(self):
        return f"DeletedAccount(user_id={self.user_id})"
