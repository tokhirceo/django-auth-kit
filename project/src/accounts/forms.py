import io

from django import forms
from django.contrib.auth import forms as auth_forms
from django.contrib.auth import password_validation
from django.core.files.uploadedfile import SimpleUploadedFile, UploadedFile
from django.urls import reverse

from . import services
from .config.settings import accounts_settings
from .models import PrivacySettings, User
from .validators import (
    ALLOWED_AVATAR_FORMATS,
    UnicodeUsernameValidator,
    validate_avatar,
    validate_no_at_sign,
)

INPUT = (
    "block w-full rounded-lg border border-slate-300 bg-white px-3 py-2 text-slate-900 shadow-sm "
    "focus:border-indigo-600 focus:outline-none focus:ring-2 focus:ring-indigo-500 "
    "dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100"
)
CHECKBOX = (
    "mt-1 h-4 w-4 rounded border-slate-400 text-indigo-600 "
    "focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2"
)
FILE = (
    "block w-full text-sm text-slate-700 file:mr-3 file:rounded-lg file:border-0 file:bg-indigo-600 "
    "file:px-3 file:py-2 file:text-white hover:file:bg-indigo-700 dark:text-slate-300"
)

AUTOCOMPLETE = {
    "username": "username",
    "password": "current-password",
    "old_password": "current-password",
    "current_password": "current-password",
    "new_password1": "new-password",
    "new_password2": "new-password",
    "password1": "new-password",
    "password2": "new-password",
    "email": "email",
    "new_email": "email",
    "first_name": "given-name",
    "last_name": "family-name",
    "phone": "tel",
}


class TailwindFormMixin:
    """Tailwind sinflari, ``autocomplete`` va a11y atributlari (``aria-*``)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        auto_id = self.auto_id if isinstance(self.auto_id, str) and "%s" in self.auto_id else "id_%s"
        for name, field in self.fields.items():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                widget.attrs["class"] = CHECKBOX
            elif isinstance(widget, forms.FileInput):
                widget.attrs["class"] = FILE
            else:
                widget.attrs["class"] = INPUT
            if name in AUTOCOMPLETE:
                widget.attrs.setdefault("autocomplete", AUTOCOMPLETE[name])
            widget.attrs["aria-describedby"] = (auto_id % self.add_prefix(name)) + "_desc"

    def full_clean(self):
        super().full_clean()
        for name in self.errors:
            if name in self.fields:
                self.fields[name].widget.attrs["aria-invalid"] = "true"


# ------------------------------------------------------------------- signup/login
class SignupForm(TailwindFormMixin, forms.Form):
    username = forms.CharField(
        label="Foydalanuvchi nomi",
        max_length=150,
        min_length=3,
        validators=[UnicodeUsernameValidator(), validate_no_at_sign],
    )
    email = forms.EmailField(label="Email", max_length=254)
    password1 = forms.CharField(
        label="Parol", strip=False, widget=forms.PasswordInput, help_text=password_validation.password_validators_help_text_html()
    )
    password2 = forms.CharField(label="Parolni takrorlang", strip=False, widget=forms.PasswordInput)

    def clean_username(self):
        username = self.cleaned_data["username"]
        if User.objects.identifier_taken(username=username):
            raise forms.ValidationError("Bu foydalanuvchi nomi band.", code="username_taken")
        return username

    def clean_email(self):
        email = User.objects.normalize_email(self.cleaned_data["email"].strip())
        if User.objects.identifier_taken(email=email):
            raise forms.ValidationError("Bu email manzil band.", code="email_taken")
        return email

    def clean(self):
        cleaned = super().clean()
        p1, p2 = cleaned.get("password1"), cleaned.get("password2")
        if p1 and p2:
            if p1 != p2:
                self.add_error("password2", "Parollar mos kelmadi.")
            else:
                candidate = User(username=cleaned.get("username", ""), email=cleaned.get("email", ""))
                try:
                    password_validation.validate_password(p1, candidate)
                except forms.ValidationError as exc:
                    self.add_error("password1", exc)
        return cleaned


class LoginForm(TailwindFormMixin, auth_forms.AuthenticationForm):
    username = forms.CharField(label="Foydalanuvchi nomi yoki email", max_length=254)
    password = forms.CharField(label="Parol", strip=False, widget=forms.PasswordInput)
    error_messages = {
        "invalid_login": "Foydalanuvchi nomi/email yoki parol noto'g'ri.",
        "inactive": "Foydalanuvchi nomi/email yoki parol noto'g'ri.",
    }


class ReactivateForm(TailwindFormMixin, forms.Form):
    username = forms.CharField(label="Foydalanuvchi nomi yoki email", max_length=254)
    password = forms.CharField(label="Parol", strip=False, widget=forms.PasswordInput)


# ---------------------------------------------------------------- parol (Django built-in)
class PasswordChangeForm(TailwindFormMixin, auth_forms.PasswordChangeForm):
    pass


class SetPasswordForm(TailwindFormMixin, auth_forms.SetPasswordForm):
    pass


class PasswordResetForm(TailwindFormMixin, auth_forms.PasswordResetForm):
    """Havola sozlangan site URL (yoki tekshirilgan request hosti) bilan yasaladi."""

    request = None

    def send_mail(
        self,
        subject_template_name,
        email_template_name,
        context,
        from_email,
        to_email,
        html_email_template_name=None,
    ):
        path = reverse("accounts:password_reset_confirm", kwargs={"uidb64": context["uid"], "token": context["token"]})
        services.send_password_reset_email(
            user=context["user"],
            to_email=to_email,
            reset_url=services.build_absolute_url(path, self.request),
        )


# -------------------------------------------------------------------------- profil
class ProfileForm(TailwindFormMixin, forms.ModelForm):
    avatar = forms.ImageField(label="Avatar", required=False, widget=forms.FileInput)
    remove_avatar = forms.BooleanField(label="Avatarni olib tashlash", required=False)

    class Meta:
        model = User
        fields = ["first_name", "last_name", "phone", "bio", "avatar"]
        labels = {"first_name": "Ism", "last_name": "Familiya", "phone": "Telefon", "bio": "Bio"}
        widgets = {"bio": forms.Textarea(attrs={"rows": 4})}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._old_avatar = self.instance.avatar.name if self.instance.pk and self.instance.avatar else ""

    def clean_avatar(self):
        upload = self.cleaned_data.get("avatar")
        if not isinstance(upload, UploadedFile):  # yangi fayl yo'q (mavjud avatar qoladi)
            return upload
        from PIL import Image, ImageOps

        fmt = validate_avatar(upload)
        side = accounts_settings.AVATAR_OUTPUT_SIZE
        upload.seek(0)
        with Image.open(upload) as img:
            img = ImageOps.exif_transpose(img)  # yo'nalishni qo'llab, EXIF'ni tashlaydi
            img.thumbnail((side, side))
            if fmt == "JPEG" and img.mode not in ("RGB", "L"):
                img = img.convert("RGB")
            buffer = io.BytesIO()
            img.save(buffer, format=fmt)  # EXIF/metadata saqlanmaydi
        ext = ALLOWED_AVATAR_FORMATS[fmt]
        return SimpleUploadedFile(f"avatar.{ext}", buffer.getvalue(), content_type=f"image/{ext}")

    def save(self, commit=True):
        user = super().save(commit=False)
        if self.cleaned_data.get("remove_avatar") and not self.files.get(self.add_prefix("avatar")):
            user.avatar = ""
        if commit:
            user.save()
            if self._old_avatar and self._old_avatar != (user.avatar.name if user.avatar else ""):
                services.delete_file_on_commit(user.avatar.storage, self._old_avatar)
        return user


class PrivacyForm(TailwindFormMixin, forms.ModelForm):
    class Meta:
        model = PrivacySettings
        fields = [
            "name_visibility",
            "email_visibility",
            "phone_visibility",
            "bio_visibility",
            "avatar_visibility",
        ]
        labels = {
            "name_visibility": "Ism va familiya",
            "email_visibility": "Email",
            "phone_visibility": "Telefon",
            "bio_visibility": "Bio",
            "avatar_visibility": "Avatar",
        }


class PasswordConfirmForm(TailwindFormMixin, forms.Form):
    current_password = forms.CharField(label="Joriy parol", strip=False, widget=forms.PasswordInput)

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        password = self.cleaned_data["current_password"]
        if not self.user.check_password(password):
            raise forms.ValidationError("Parol noto'g'ri.", code="wrong_password")
        return password


class EmailChangeForm(PasswordConfirmForm):
    new_email = forms.EmailField(label="Yangi email", max_length=254)
    field_order = ["new_email", "current_password"]


class DangerForm(PasswordConfirmForm):
    confirm = forms.BooleanField(label="Oqibatlarini tushundim", required=True)
