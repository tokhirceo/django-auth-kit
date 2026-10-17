from django import forms
from django.contrib import admin, messages
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from django.core.exceptions import PermissionDenied
from django.db import transaction

from . import services
from .models import DeletedAccount, User

PRIVILEGE_FIELDS = ("is_active", "is_staff", "is_superuser", "role", "groups", "user_permissions")


class AdminUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ("username", "email")

    def clean_username(self):
        username = self.cleaned_data["username"]
        if User.objects.identifier_taken(username=username):
            raise forms.ValidationError("Bu foydalanuvchi nomi band.")
        return username

    def clean_email(self):
        email = self.cleaned_data["email"]
        if User.objects.identifier_taken(email=email):
            raise forms.ValidationError("Bu email manzil band.")
        return email


class AdminUserChangeForm(UserChangeForm):
    class Meta(UserChangeForm.Meta):
        model = User
        fields = "__all__"

    def clean(self):
        cleaned = super().clean()
        if not self.instance.pk:
            return cleaned
        if "role" in self.changed_data and "role" in cleaned:
            cleaned["is_superuser"] = cleaned["role"] == User.Role.SUPERUSER
            if cleaned["is_superuser"]:
                cleaned["is_staff"] = True
        new_super = cleaned.get("is_superuser", self.instance.is_superuser)
        new_active = cleaned.get("is_active", self.instance.is_active)
        if new_active and cleaned.get("deletion_requested_at", self.instance.deletion_requested_at):
            self.add_error("is_active", "O'chirish kutilayotgan hisobni qayta yoqib bo'lmaydi.")
        db_user = User.objects.get(pk=self.instance.pk)
        if services.would_remove_last_superuser(db_user, new_is_superuser=new_super, new_is_active=new_active):
            raise forms.ValidationError("Oxirgi faol superuser'ni o'zgartirib bo'lmaydi.")
        return cleaned


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
    form = AdminUserChangeForm
    add_form = AdminUserCreationForm
    list_display = ("username", "email", "role", "is_active", "is_email_verified", "is_staff", "created_at")
    list_filter = ("role", "is_active", "is_email_verified", "is_staff")
    search_fields = ("username", "email", "first_name", "last_name")
    ordering = ("-created_at",)
    readonly_fields = ("created_at", "updated_at", "last_login", "date_joined", "session_epoch")
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        ("Shaxsiy ma'lumot", {"fields": ("first_name", "last_name", "email", "pending_email", "phone", "bio", "avatar")}),
        ("Holat", {"fields": ("is_email_verified", "is_active", "deactivated_at", "deletion_requested_at", "session_epoch")}),
        ("Ruxsatlar", {"fields": ("role", "is_staff", "is_superuser", "groups", "user_permissions")}),
        ("Sanalar", {"fields": ("last_login", "date_joined", "created_at", "updated_at")}),
    )
    add_fieldsets = (
        (None, {"classes": ("wide",), "fields": ("username", "email", "password1", "password2")}),
    )

    def get_readonly_fields(self, request, obj=None):
        fields = list(super().get_readonly_fields(request, obj))
        if not request.user.is_superuser:
            fields += [f for f in PRIVILEGE_FIELDS if f not in fields]
        return fields

    def has_view_permission(self, request, obj=None):
        if obj is not None and obj.is_superuser and not request.user.is_superuser:
            return False
        return super().has_view_permission(request, obj)

    def has_change_permission(self, request, obj=None):
        if obj is not None and obj.is_superuser and not request.user.is_superuser:
            return False
        return super().has_change_permission(request, obj)

    def has_delete_permission(self, request, obj=None):
        if obj is not None:
            if obj.is_superuser and not request.user.is_superuser:
                return False
            if services.would_remove_last_superuser(obj, new_is_superuser=False, new_is_active=False):
                return False
        return super().has_delete_permission(request, obj)

    def save_model(self, request, obj, form, change):
        if not change:
            super().save_model(request, obj, form, change)
            return
        with transaction.atomic():
            try:
                services.guard_privilege_change(
                    obj.pk, new_is_superuser=obj.is_superuser, new_is_active=obj.is_active
                )
            except services.LastSuperuserError:
                raise PermissionDenied from None  # poyga (forma tekshiruvidan keyin)
            was_active = User.objects.filter(pk=obj.pk).values_list("is_active", flat=True).first()
            if obj.is_active and not was_active:
                obj.deactivated_at = None
            super().save_model(request, obj, form, change)
            if was_active and not obj.is_active:
                services.invalidate_user_sessions(obj)

    def delete_model(self, request, obj):
        try:
            services.hard_delete_user(obj)
        except services.LastSuperuserError:
            raise PermissionDenied from None

    def delete_queryset(self, request, queryset):
        for user in queryset:
            try:
                services.hard_delete_user(user)
            except services.LastSuperuserError:
                self.message_user(
                    request, "Oxirgi faol superuser o'chirilmadi.", level=messages.ERROR
                )


@admin.register(DeletedAccount)
class DeletedAccountAdmin(admin.ModelAdmin):
    list_display = ("user_id", "deleted_at")
    readonly_fields = ("user_id", "deleted_at")

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
