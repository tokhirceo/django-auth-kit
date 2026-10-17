from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse_lazy
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.cache import never_cache
from django.views.generic import FormView, TemplateView, UpdateView

from . import forms, services
from .config.settings import accounts_settings
from .models import EmailVerificationToken, PrivacySettings, User
from .ratelimit import RateLimitMixin
from .tokens import accounts_token_generator

BACKEND = "accounts.backends.AccountsBackend"

MSG_GENERIC_RESEND = (
    "Agar tasdiqlash kerak bo'lsa, xat yuborildi. Xat kelmasa, bir ozdan keyin qayta urinib ko'ring."
)
MSG_SEND_FAILED = "Xat yuborib bo'lmadi. Keyinroq «Qayta yuborish» tugmasini bosing."


class AnonymousOnlyMixin:
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect(settings.LOGIN_REDIRECT_URL)
        return super().dispatch(request, *args, **kwargs)


# ---------------------------------------------------------------- kirish/chiqish
class SignupView(AnonymousOnlyMixin, RateLimitMixin, FormView):
    template_name = "accounts/signup.html"
    form_class = forms.SignupForm
    rate_scope = "signup"

    def form_valid(self, form):
        cd = form.cleaned_data
        try:
            user, result = services.register_user(
                username=cd["username"], email=cd["email"], password=cd["password1"], request=self.request
            )
        except services.IdentifierTakenError:
            form.add_error(None, "Bu foydalanuvchi nomi yoki email band.")
            return self.form_invalid(form)
        if accounts_settings.REQUIRE_EMAIL_VERIFICATION:
            self.request.session[services.PENDING_KEY] = user.pk
            if result == services.FAILED:
                messages.error(self.request, "Hisob yaratildi, lekin tasdiqlash xati yuborilmadi. " + MSG_SEND_FAILED)
            else:
                messages.success(self.request, "Hisob yaratildi. Emailingizga tasdiqlash xati yuborildi.")
            return redirect("accounts:verification_required")
        login(self.request, user, backend=BACKEND)
        messages.success(self.request, "Xush kelibsiz! Hisobingiz yaratildi.")
        return redirect(settings.LOGIN_REDIRECT_URL)


class LoginView(RateLimitMixin, auth_views.LoginView):
    template_name = "accounts/login.html"
    authentication_form = forms.LoginForm
    redirect_authenticated_user = True
    rate_scope = "login"

    def get_rate_identifier(self, request):
        return request.POST.get("username")

    def form_valid(self, form):
        user = form.get_user()
        if accounts_settings.REQUIRE_EMAIL_VERIFICATION and not user.is_email_verified:
            self.request.session[services.PENDING_KEY] = user.pk
            return redirect("accounts:verification_required")
        self.request.session.pop(services.PENDING_KEY, None)  # H17: parking kaliti tozalanadi
        return super().form_valid(form)


class LogoutView(View):
    http_method_names = ["post", "options"]

    def post(self, request):
        logout(request)
        return redirect(settings.LOGOUT_REDIRECT_URL)


# ------------------------------------------------------------ email tasdiqlash
class VerificationRequiredView(TemplateView):
    template_name = "accounts/verification_required.html"

    def dispatch(self, request, *args, **kwargs):
        if not accounts_settings.REQUIRE_EMAIL_VERIFICATION:
            return redirect(settings.LOGIN_REDIRECT_URL if request.user.is_authenticated else settings.LOGIN_URL)
        user = request.user if request.user.is_authenticated else services.get_pending_user(request)
        if user is None or user.is_email_verified:
            return redirect(settings.LOGIN_REDIRECT_URL if request.user.is_authenticated else settings.LOGIN_URL)
        self.target_user = user
        return super().dispatch(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["target_user"] = self.target_user
        return ctx


class ResendVerificationView(RateLimitMixin, View):
    http_method_names = ["post", "options"]
    rate_scope = "resend_verification"

    def post(self, request):
        user = request.user if request.user.is_authenticated else services.get_pending_user(request)
        if user is None:
            return redirect(settings.LOGIN_URL)
        result = services.resend_verification(user, request)
        if result == services.FAILED:
            messages.error(request, MSG_SEND_FAILED)
        else:
            messages.info(request, MSG_GENERIC_RESEND)
        if accounts_settings.REQUIRE_EMAIL_VERIFICATION and not user.is_email_verified:
            return redirect("accounts:verification_required")
        return redirect("accounts:profile")


@method_decorator(never_cache, name="dispatch")
class VerifyEmailView(RateLimitMixin, View):
    """GET tokenni sarflamaydi; sarflash faqat POST (CSRF) orqali."""

    rate_scope = "verify_email"

    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        response["Referrer-Policy"] = "no-referrer"
        return response

    def get(self, request, token):
        if EmailVerificationToken.find_valid(token) is None:
            return render(request, "accounts/verify_email_invalid.html", status=400)
        return render(request, "accounts/verify_email_confirm.html", {"token": token})

    def post(self, request, token):
        status, user = services.confirm_email_token(token)
        if status in (services.INVALID,):
            return render(request, "accounts/verify_email_invalid.html", status=400)
        if user is not None and request.session.get(services.PENDING_KEY) == user.pk:
            request.session.pop(services.PENDING_KEY, None)
        if status == services.VERIFIED:
            messages.success(request, "Email manzilingiz tasdiqlandi.")
        elif status == services.EMAIL_CHANGED:
            messages.success(request, "Yangi email manzilingiz tasdiqlandi va faollashtirildi.")
        else:
            messages.error(request, "Bu email manzil endi band; o'zgartirish bekor qilindi.")
        if request.user.is_authenticated:
            return redirect("accounts:profile")
        return redirect(settings.LOGIN_URL)


# ------------------------------------------------------------------------- parol
class PasswordChangeView(auth_views.PasswordChangeView):
    template_name = "accounts/password_change.html"
    form_class = forms.PasswordChangeForm
    success_url = reverse_lazy("accounts:password_change_done")


class PasswordChangeDoneView(auth_views.PasswordChangeDoneView):
    template_name = "accounts/password_change_done.html"


class PasswordResetView(RateLimitMixin, auth_views.PasswordResetView):
    template_name = "accounts/password_reset.html"
    form_class = forms.PasswordResetForm
    success_url = reverse_lazy("accounts:password_reset_done")
    token_generator = accounts_token_generator
    rate_scope = "password_reset"

    def form_valid(self, form):
        form.request = self.request
        return super().form_valid(form)


class PasswordResetDoneView(auth_views.PasswordResetDoneView):
    template_name = "accounts/password_reset_done.html"


class PasswordResetConfirmView(auth_views.PasswordResetConfirmView):
    template_name = "accounts/password_reset_confirm.html"
    form_class = forms.SetPasswordForm
    success_url = reverse_lazy("accounts:password_reset_complete")
    token_generator = accounts_token_generator


class PasswordResetCompleteView(auth_views.PasswordResetCompleteView):
    template_name = "accounts/password_reset_complete.html"


# ------------------------------------------------------------------------ profil
class ProfileView(LoginRequiredMixin, TemplateView):
    template_name = "accounts/profile.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["profile"] = services.get_public_profile(self.request.user, self.request.user)
        ctx["account"] = self.request.user
        ctx["is_self"] = True
        ctx["require_verification"] = accounts_settings.REQUIRE_EMAIL_VERIFICATION
        return ctx


class SettingsView(LoginRequiredMixin, TemplateView):
    """Sozlamalar markazi: profil, maxfiylik, parol, email, faolsizlantirish/o'chirish."""

    template_name = "accounts/settings.html"


class ProfileEditView(LoginRequiredMixin, UpdateView):
    template_name = "accounts/profile_edit.html"
    form_class = forms.ProfileForm
    success_url = reverse_lazy("accounts:profile")

    def get_object(self, queryset=None):
        return self.request.user  # IDOR yo'q: URL'da id/username yo'q

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Profil saqlandi.")
        return response


class PrivacySettingsView(LoginRequiredMixin, UpdateView):
    template_name = "accounts/privacy.html"
    form_class = forms.PrivacyForm
    success_url = reverse_lazy("accounts:privacy")

    def get_object(self, queryset=None):
        if self.request.method == "POST":
            obj, _ = PrivacySettings.objects.get_or_create(user=self.request.user)
            return obj
        return services.get_privacy(self.request.user)  # GET'da yozmaydi

    def form_valid(self, form):
        response = super().form_valid(form)
        messages.success(self.request, "Maxfiylik sozlamalari saqlandi.")
        return response


class PublicProfileView(TemplateView):
    template_name = "accounts/public_profile.html"

    def get_context_data(self, username, **kwargs):
        ctx = super().get_context_data(**kwargs)
        target = User.objects.live().select_related("privacy").filter(username__iexact=username).first()
        profile = services.get_public_profile(self.request.user, target) if target else None
        if profile is None:
            raise Http404
        ctx["profile"] = profile
        ctx["is_self"] = profile["is_self"]
        ctx["account"] = self.request.user if profile["is_self"] else None
        return ctx


class EmailChangeView(LoginRequiredMixin, RateLimitMixin, FormView):
    template_name = "accounts/email_change.html"
    form_class = forms.EmailChangeForm
    success_url = reverse_lazy("accounts:profile")
    rate_scope = "email_change"

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        result = services.request_email_change(self.request.user, form.cleaned_data["new_email"], self.request)
        if result == services.FAILED:
            messages.error(self.request, MSG_SEND_FAILED)
        else:
            messages.info(
                self.request,
                "Agar manzil bo'sh bo'lsa, tasdiqlash xati yuborildi. "
                "Tasdiqlanmaguncha joriy email amal qiladi.",
            )
        return super().form_valid(form)


class _DangerView(LoginRequiredMixin, FormView):
    form_class = forms.DangerForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs


class DeactivateView(_DangerView):
    template_name = "accounts/deactivate.html"

    def form_valid(self, form):
        try:
            services.deactivate_account(self.request.user)
        except services.LastSuperuserError:
            form.add_error(None, "Oxirgi faol superuser hisobini faolsizlantirib bo'lmaydi.")
            return self.form_invalid(form)
        logout(self.request)
        messages.success(self.request, "Hisobingiz faolsizlantirildi. Istalgan vaqt qayta yoqishingiz mumkin.")
        return redirect(settings.LOGIN_URL)


class DeleteAccountView(_DangerView):
    template_name = "accounts/delete.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["grace_days"] = accounts_settings.DELETION_GRACE_PERIOD // 86400
        return ctx

    def form_valid(self, form):
        try:
            services.delete_user_account(self.request.user)
        except services.LastSuperuserError:
            form.add_error(None, "Oxirgi faol superuser hisobini o'chirib bo'lmaydi.")
            return self.form_invalid(form)
        logout(self.request)
        return redirect("accounts:deleted")


class DeletedView(TemplateView):
    template_name = "accounts/deleted.html"


class ReactivateView(AnonymousOnlyMixin, RateLimitMixin, FormView):
    template_name = "accounts/reactivate.html"
    form_class = forms.ReactivateForm
    success_url = reverse_lazy("accounts:login")
    rate_scope = "reactivate"

    def get_rate_identifier(self, request):
        return request.POST.get("username")

    def form_valid(self, form):
        user = services.reactivate_account(form.cleaned_data["username"], form.cleaned_data["password"])
        if user is None:
            form.add_error(None, "Ma'lumotlar noto'g'ri yoki hisobni qayta yoqib bo'lmaydi.")
            return self.form_invalid(form)
        messages.success(self.request, "Hisobingiz qayta yoqildi. Endi kirishingiz mumkin.")
        return super().form_valid(form)
