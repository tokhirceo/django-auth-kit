import os

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.contrib.auth.validators import UnicodeUsernameValidator

from .config.settings import accounts_settings

username_validator = UnicodeUsernameValidator()

phone_validator = RegexValidator(
    r"^\+?[0-9 ()\-]{7,20}$",
    "Telefon raqamini to'g'ri kiriting (masalan, +998 90 123 45 67).",
)

ALLOWED_AVATAR_FORMATS = {"JPEG": "jpg", "PNG": "png", "WEBP": "webp"}
ALLOWED_AVATAR_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}


def validate_no_at_sign(value):
    """Yangi username'da '@' taqiqlanadi (email bilan to'qnashmaslik uchun)."""
    if "@" in value:
        raise ValidationError("Foydalanuvchi nomida '@' belgisi bo'lishi mumkin emas.", code="at_sign")


def validate_avatar(upload):
    """Avatarni tekshiradi: hajm, kengaytma, haqiqiy format, o'lchamlar.

    Pillow faqat sarlavhani o'qiydi (``Image.open``), piksellar dekodlanmaydi,
    shuning uchun decompression bomb dekodlashdan oldin rad etiladi.
    """
    from PIL import Image, UnidentifiedImageError

    if upload.size > accounts_settings.AVATAR_MAX_BYTES:
        raise ValidationError("Rasm hajmi juda katta.", code="avatar_size")
    ext = os.path.splitext(getattr(upload, "name", "") or "")[1].lower()
    if ext not in ALLOWED_AVATAR_EXTENSIONS:
        raise ValidationError("Faqat JPG, PNG yoki WEBP rasm yuklash mumkin.", code="avatar_ext")
    try:
        upload.seek(0)
        with Image.open(upload) as img:
            fmt = img.format
            width, height = img.size
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        raise ValidationError("Fayl yaroqli rasm emas.", code="avatar_invalid") from None
    finally:
        upload.seek(0)
    if fmt not in ALLOWED_AVATAR_FORMATS:
        raise ValidationError("Faqat JPG, PNG yoki WEBP rasm yuklash mumkin.", code="avatar_format")
    if (
        width > accounts_settings.AVATAR_MAX_SIDE
        or height > accounts_settings.AVATAR_MAX_SIDE
        or width * height > accounts_settings.AVATAR_MAX_PIXELS
    ):
        raise ValidationError("Rasm o'lchamlari juda katta.", code="avatar_dimensions")
    return fmt
