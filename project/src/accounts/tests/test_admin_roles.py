from django.core.exceptions import PermissionDenied
from django.http import HttpResponse
from django.test import Client, RequestFactory
from django.urls import reverse
from django.views import View

from accounts import services
from accounts.decorators import RoleRequiredMixin, role_required, teacher_required
from accounts.models import User

from .helpers import PASSWORD, AccountsTestCase, make_superuser, make_user


class RoleTests(AccountsTestCase):
    def call(self, view, user=None):
        request = RequestFactory().get("/x/")
        request.user = user or type("A", (), {"is_authenticated": False})()
        try:
            return view(request)
        except PermissionDenied:
            return HttpResponse(status=403)

    def test_S26_role_required_and_teacher_required(self):
        ok = lambda request: HttpResponse("ok")  # noqa: E731
        teacher_view, super_view = teacher_required(ok), role_required("superuser")(ok)
        user, teacher, root = make_user("u"), make_user("t", role="teacher"), make_superuser("r")
        self.assertEqual(self.call(teacher_view).status_code, 302)  # anonim -> login
        self.assertIn("/accounts/login/", self.call(teacher_view)["Location"])
        self.assertEqual(self.call(teacher_view, user).status_code, 403)
        self.assertEqual(self.call(teacher_view, teacher).status_code, 200)
        self.assertEqual(self.call(teacher_view, root).status_code, 200)
        self.assertEqual(self.call(super_view, teacher).status_code, 403)

    def test_S26_mixin(self):
        class V(RoleRequiredMixin, View):
            allowed_roles = ("teacher",)
            def get(self, request):
                return HttpResponse("ok")
        view = V.as_view()
        self.assertEqual(self.call(view).status_code, 302)
        self.assertEqual(self.call(view, make_user("u")).status_code, 403)
        self.assertEqual(self.call(view, make_user("t", role="teacher")).status_code, 200)


class AdminTests(AccountsTestCase):
    def change_url(self, user):
        return reverse("admin:accounts_user_change", args=[user.pk])

    def form_data(self, user, **over):
        data = {
            "username": user.username, "email": user.email, "first_name": "", "last_name": "", "phone": "", "bio": "",
            "pending_email": "", "role": user.role, "date_joined_0": "2026-01-01", "date_joined_1": "00:00:00",
            "is_active": "on" if user.is_active else "", "is_staff": "on" if user.is_staff else "",
            "is_superuser": "on" if user.is_superuser else "",
        }
        data = {k: v for k, v in data.items() if v != ""}
        data.update(over)
        return {k: v for k, v in data.items() if v is not None}

    def test_S10_admin_form_cannot_demote_or_deactivate_last_superuser(self):
        root = make_superuser("root")
        self.client.force_login(root)
        for over in ({"is_active": None}, {"role": "user", "is_superuser": None}):
            r = self.client.post(self.change_url(root), self.form_data(root, **over))
            self.assertEqual(r.status_code, 200, over)
            self.assertContains(r, "Oxirgi faol superuser")
        root.refresh_from_db()
        self.assertTrue(root.is_active and root.is_superuser)

    def test_S10_admin_delete_and_bulk_delete_protect_last_superuser(self):
        root = make_superuser("root")
        other = make_user("alice")
        self.client.force_login(root)
        r = self.client.post(reverse("admin:accounts_user_delete", args=[root.pk]), {"post": "yes"})
        self.assertIn(r.status_code, (403, 302))
        self.assertTrue(User.objects.filter(pk=root.pk).exists())
        bulk = lambda pks: self.client.post(reverse("admin:accounts_user_changelist"), {  # noqa: E731
            "action": "delete_selected", "_selected_action": pks, "post": "yes"})
        bulk([root.pk, other.pk])  # Django ruxsatsiz obyekt bor bo'lgani uchun butun amalni rad etadi
        self.assertTrue(User.objects.filter(pk=root.pk).exists())
        bulk([other.pk])
        self.assertTrue(User.objects.filter(pk=root.pk).exists())
        self.assertFalse(User.objects.filter(pk=other.pk).exists())
        # delete_queryset to'g'ridan-to'g'ri (ruxsat tekshiruvini chetlab): baribir himoyalangan
        from accounts.admin import UserAdmin
        from django.contrib.admin.sites import site
        request = RequestFactory().post("/")
        request.user = root
        request._messages = type("M", (), {"add": lambda *a, **k: None})()
        UserAdmin(User, site).delete_queryset(request, User.objects.filter(pk=root.pk))
        self.assertTrue(User.objects.filter(pk=root.pk).exists())

    def test_admin_blocking_user_kills_sessions(self):
        root = make_superuser("root")
        victim = make_user("alice")
        c = Client()
        c.login(username="alice", password=PASSWORD)
        self.assertEqual(c.get(reverse("accounts:profile")).status_code, 200)
        self.client.force_login(root)
        r = self.client.post(self.change_url(victim), self.form_data(victim, is_active=None))
        self.assertEqual(r.status_code, 302, getattr(r, "context", None) and r.context["adminform"].form.errors)
        victim.refresh_from_db()
        self.assertFalse(victim.is_active)
        self.assertIsNone(victim.deactivated_at)  # BLOCKED: o'zi qayta yoqa olmaydi
        self.assertEqual(c.get(reverse("accounts:profile")).status_code, 302)
        self.assertIsNone(services.reactivate_account("alice", PASSWORD))

    def test_admin_cannot_reactivate_deletion_pending(self):
        from django.utils import timezone
        root = make_superuser("root")
        pending = make_user("alice", is_active=False, deletion_requested_at=timezone.now())
        self.client.force_login(root)
        r = self.client.post(self.change_url(pending), self.form_data(
            pending, is_active="on", deletion_requested_at_0="2026-01-01", deletion_requested_at_1="00:00:00"))
        self.assertEqual(r.status_code, 200)
        pending.refresh_from_db()
        self.assertFalse(pending.is_active)

    def test_S15_staff_cannot_escalate_or_touch_superuser(self):
        make_superuser("root")
        staff = make_user("staff", is_staff=True, role="teacher")
        from django.contrib.auth.models import Permission
        staff.user_permissions.set(Permission.objects.filter(content_type__app_label="accounts", content_type__model="user"))
        self.client.force_login(staff)
        r = self.client.post(self.change_url(staff), self.form_data(staff, is_superuser="on", role="superuser"))
        staff.refresh_from_db()
        self.assertFalse(staff.is_superuser)
        self.assertEqual(staff.role, "teacher")
        root = User.objects.get(username="root")
        self.assertIn(self.client.get(self.change_url(root)).status_code, (302, 403))
        self.assertIn(self.client.post(self.change_url(root), self.form_data(root, first_name="X")).status_code, (302, 403))
        root.refresh_from_db()
        self.assertEqual(root.first_name, "")
        self.assertIn(self.client.post(reverse("admin:accounts_user_delete", args=[root.pk]), {"post": "yes"}).status_code, (302, 403))
        self.assertTrue(User.objects.filter(username="root").exists())

    def test_admin_add_user_rejects_taken_identifier(self):
        root = make_superuser("root")
        self.client.force_login(root)
        r = self.client.post(reverse("admin:accounts_user_add"), {
            "username": "ROOT", "email": "x@example.com", "password1": PASSWORD, "password2": PASSWORD})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(User.objects.filter(username__iexact="root").count(), 1)

    def test_createsuperuser_manager_marks_verified(self):
        self.assertTrue(make_superuser("root").is_email_verified)
