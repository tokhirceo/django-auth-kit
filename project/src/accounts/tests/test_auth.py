import re
from pathlib import Path

import accounts
from django.contrib.auth.hashers import identify_hasher
from django.core import mail
from django.test import Client, override_settings
from django.urls import reverse

from accounts import services
from accounts.models import PrivacySettings, User

from .helpers import PASSWORD, AccountsTestCase, last_mail_link, make_user

PKG = Path(accounts.__file__).resolve().parent


class SignupTests(AccountsTestCase):
    def signup(self, **extra):
        data = {
            "username": "newuser",
            "email": "new@example.com",
            "password1": PASSWORD,
            "password2": PASSWORD,
        }
        data.update(extra)
        return self.client.post(reverse("accounts:signup"), data)

    def test_signup_logs_in_and_sends_no_mail_when_verification_off(self):
        response = self.signup()
        self.assertRedirects(response, reverse("accounts:profile"), fetch_redirect_response=False)
        user = User.objects.get(username="newuser")
        self.assertEqual(user.email, "new@example.com")
        self.assertFalse(user.is_email_verified)
        self.assertEqual(self.client.session["_auth_user_id"], str(user.pk))
        self.assertEqual(mail.outbox, [])
        self.assertTrue(PrivacySettings.objects.filter(user=user).exists())

    def test_S1_cannot_set_role_or_staff_via_signup(self):
        self.signup(role="superuser", is_staff="on", is_superuser="on")
        user = User.objects.get(username="newuser")
        self.assertEqual(user.role, "user")
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_S1_cannot_set_role_or_staff_via_profile(self):
        user = make_user()
        self.client.force_login(user)
        self.client.post(
            reverse("accounts:profile_edit"),
            {"first_name": "A", "last_name": "B", "phone": "", "bio": "", "role": "superuser",
             "is_staff": "on", "is_superuser": "on", "email": "hacker@example.com"},
        )
        user.refresh_from_db()
        self.assertEqual((user.role, user.is_staff, user.is_superuser), ("user", False, False))
        self.assertEqual(user.email, "alice@example.com")
        self.assertEqual(user.first_name, "A")

    def test_S6_weak_password_rejected_and_hash_stored(self):
        response = self.signup(password1="12345678", password2="12345678")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(username="newuser").exists())
        self.signup()
        stored = User.objects.get(username="newuser").password
        self.assertNotEqual(stored, PASSWORD)
        self.assertNotIn(PASSWORD, stored)
        identify_hasher(stored)  # Django hasher formati

    def test_password_mismatch(self):
        response = self.signup(password2="Different-Pass-1!")
        self.assertContains(response, "Parollar mos kelmadi")
        self.assertFalse(User.objects.filter(username="newuser").exists())

    def test_S25_at_sign_in_username_rejected(self):
        response = self.signup(username="bob@x.com")
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "&#x27;@&#x27; belgisi")
        self.assertFalse(User.objects.filter(username="bob@x.com").exists())

    def test_H6_signup_reveals_taken_identifier_by_design(self):
        make_user("alice", "alice@example.com")
        r1 = self.signup(username="ALICE")
        self.assertContains(r1, "Bu foydalanuvchi nomi band")
        r2 = self.signup(email="Alice@Example.com")
        self.assertContains(r2, "Bu email manzil band")

    def test_unique_case_insensitive_at_db_level(self):
        from django.db import IntegrityError, transaction

        make_user("alice")
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.bulk_create([User(username="ALICE", email="other@example.com")])
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.bulk_create([User(username="other", email="ALICE@example.com")])


class LoginTests(AccountsTestCase):
    def setUp(self):
        super().setUp()
        self.user = make_user("alice", "alice@example.com")
        self.url = reverse("accounts:login")

    def test_login_with_username_and_email_case_insensitive(self):
        for ident in ("alice", "ALICE", "alice@example.com", "Alice@Example.com"):
            client = Client()
            response = client.post(self.url, {"username": ident, "password": PASSWORD})
            self.assertEqual(response.status_code, 302, ident)
            self.assertEqual(client.session["_auth_user_id"], str(self.user.pk), ident)

    def test_S7_login_errors_identical_for_missing_and_wrong_password(self):
        wrong = self.client.post(self.url, {"username": "alice", "password": "Wrong-pass-1!"})
        missing = Client().post(self.url, {"username": "nobody", "password": "Wrong-pass-1!"})
        self.assertEqual(wrong.status_code, missing.status_code)
        msg = "Foydalanuvchi nomi/email yoki parol noto&#x27;g&#x27;ri."
        self.assertContains(wrong, msg)
        self.assertContains(missing, msg)

    def test_S2_open_redirect_blocked(self):
        for target in ("https://evil.com/x", "//evil.com", "javascript:alert(1)"):
            response = Client().post(self.url, {"username": "alice", "password": PASSWORD, "next": target})
            self.assertRedirects(response, reverse("accounts:profile"), fetch_redirect_response=False)

    def test_internal_next_is_followed(self):
        response = Client().post(
            self.url, {"username": "alice", "password": PASSWORD, "next": reverse("accounts:privacy")}
        )
        self.assertRedirects(response, reverse("accounts:privacy"), fetch_redirect_response=False)

    def test_S3_logout_post_only(self):
        self.client.force_login(self.user)
        self.assertEqual(self.client.get(reverse("accounts:logout")).status_code, 405)
        self.assertIn("_auth_user_id", self.client.session)
        response = self.client.post(reverse("accounts:logout"))
        self.assertEqual(response.status_code, 302)
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_inactive_user_cannot_login(self):
        User.objects.filter(pk=self.user.pk).update(is_active=False)
        response = Client().post(self.url, {"username": "alice", "password": PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("_auth_user_id", self.client.session)


class CsrfTests(AccountsTestCase):
    def test_S4_state_changing_views_require_csrf(self):
        user = make_user()
        client = Client(enforce_csrf_checks=True)
        client.force_login(user)
        for name, kwargs in [
            ("accounts:logout", {}),
            ("accounts:deactivate", {}),
            ("accounts:delete", {}),
            ("accounts:email_change", {}),
            ("accounts:resend_verification", {}),
            ("accounts:verify_email", {"token": "abc"}),
            ("accounts:profile_edit", {}),
            ("accounts:privacy", {}),
        ]:
            response = client.post(reverse(name, kwargs=kwargs), {})
            self.assertEqual(response.status_code, 403, name)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.assertTrue(User.objects.filter(pk=user.pk).exists())


class IdorTests(AccountsTestCase):
    def test_S5_edit_views_only_touch_request_user(self):
        alice, bob = make_user("alice"), make_user("bob")
        self.client.force_login(alice)
        self.client.post(
            reverse("accounts:profile_edit"), {"first_name": "Changed", "last_name": "", "phone": "", "bio": ""}
        )
        alice.refresh_from_db()
        bob.refresh_from_db()
        self.assertEqual(alice.first_name, "Changed")
        self.assertEqual(bob.first_name, "")
        # URL orqali boshqa user tahrirlanmaydi: public_profile faqat GET
        response = self.client.post(reverse("accounts:public_profile", args=["bob"]), {"first_name": "X"})
        self.assertEqual(response.status_code, 405)
        bob.refresh_from_db()
        self.assertEqual(bob.first_name, "")
        self.client.post(reverse("accounts:privacy"), {k: "private" for k in (
            "name_visibility", "email_visibility", "phone_visibility", "bio_visibility", "avatar_visibility")})
        self.assertEqual(PrivacySettings.objects.get(user=bob).name_visibility, "public")


class XssTests(AccountsTestCase):
    PAYLOAD = "<script>alert(1)</script>"

    def test_S12_bio_and_username_fields_escaped(self):
        user = make_user("alice", first_name=self.PAYLOAD, bio=self.PAYLOAD)
        self.client.force_login(user)
        for url in (reverse("accounts:profile"), reverse("accounts:public_profile", args=["alice"])):
            body = self.client.get(url).content.decode()
            self.assertNotIn(self.PAYLOAD, body, url)
            self.assertIn("&lt;script&gt;", body, url)

    def test_S12_no_safe_filter_or_mark_safe_in_templates_and_code(self):
        offenders = []
        for path in PKG.rglob("*"):
            if path.suffix not in {".html", ".txt", ".py"} or "tests" in path.parts:
                continue
            text = path.read_text()
            if re.search(r"\|\s*safe\b|mark_safe|{%\s*autoescape\s+off", text) and path.suffix != ".txt":
                offenders.append(str(path.relative_to(PKG)))
        self.assertEqual(offenders, [])


class PrivacyTests(AccountsTestCase):
    FIELDS = {
        "name": ("first_name", "full_name", "Ali Valiyev"),
        "email": ("email", "email", "alice@example.com"),
        "phone": ("phone", "phone", "+998901234567"),
        "bio": ("bio", "bio", "Salom dunyo"),
        "avatar": (None, "avatar_url", None),
    }

    def test_S16_matrix(self):
        owner = make_user("alice", first_name="Ali", last_name="Valiyev", phone="+998901234567", bio="Salom dunyo")
        other = make_user("bob")
        anon = type("Anon", (), {"is_authenticated": False, "pk": None})()
        for name, (_model_field, key, value) in self.FIELDS.items():
            for level in ("public", "members", "private"):
                privacy = PrivacySettings.objects.get(user=owner)
                for f in self.FIELDS:
                    setattr(privacy, f"{f}_visibility", "private")
                setattr(privacy, f"{name}_visibility", level)
                privacy.save()
                fresh = User.objects.select_related("privacy").get(pk=owner.pk)
                expected = {"anon": level == "public", "other": level in ("public", "members"), "self": True}
                for who, viewer in (("anon", anon), ("other", other), ("self", owner)):
                    profile = services.get_public_profile(viewer, fresh)
                    if name == "avatar":
                        continue  # avatar fayli pastda alohida
                    shown = bool(profile[key])
                    self.assertEqual(shown, expected[who], (name, level, who))
                    if shown:
                        self.assertEqual(profile[key], value)

    def test_S16_avatar_visibility(self):
        from django.core.files.base import ContentFile

        owner = make_user("alice")
        owner.avatar.save("a.png", ContentFile(b"x"), save=True)
        other = make_user("bob")
        for level, expect_other in (("public", True), ("members", True), ("private", False)):
            PrivacySettings.objects.filter(user=owner).update(avatar_visibility=level)
            fresh = User.objects.select_related("privacy").get(pk=owner.pk)
            self.assertEqual(bool(services.get_public_profile(other, fresh)["avatar_url"]), expect_other, level)
            self.assertTrue(services.get_public_profile(owner, fresh)["avatar_url"])

    def test_inactive_and_missing_profiles_404_identically(self):
        user = make_user("alice")
        User.objects.filter(pk=user.pk).update(is_active=False)
        self.assertEqual(self.client.get(reverse("accounts:public_profile", args=["alice"])).status_code, 404)
        self.assertEqual(self.client.get(reverse("accounts:public_profile", args=["nobody"])).status_code, 404)

    def test_block_callback(self):
        make_user("alice")
        viewer = make_user("bob")
        self.client.force_login(viewer)
        url = reverse("accounts:public_profile", args=["alice"])
        self.assertEqual(self.client.get(url).status_code, 200)
        with override_settings(ACCOUNTS_IS_BLOCKED_CALLBACK=lambda v, t: True):
            self.assertEqual(self.client.get(url).status_code, 404)

    def test_H7_get_does_not_write_and_query_count(self):
        user = make_user("alice")
        PrivacySettings.objects.filter(user=user).delete()
        viewer = make_user("bob")
        self.client.force_login(viewer)
        with self.assertNumQueries(3):  # session, viewer, target(+privacy join)
            response = self.client.get(reverse("accounts:public_profile", args=["alice"]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(PrivacySettings.objects.filter(user=user).count(), 0)
        self.client.force_login(user)
        self.assertEqual(self.client.get(reverse("accounts:privacy")).status_code, 200)
        self.assertEqual(PrivacySettings.objects.filter(user=user).count(), 0)  # GET yozmadi
        self.client.post(reverse("accounts:privacy"), {k: "members" for k in (
            "name_visibility", "email_visibility", "phone_visibility", "bio_visibility", "avatar_visibility")})
        self.assertEqual(PrivacySettings.objects.get(user=user).email_visibility, "members")


class PasswordTests(AccountsTestCase):
    def test_password_change_keeps_current_and_kills_other_sessions(self):
        user = make_user()
        a, b = Client(), Client()
        a.login(username="alice", password=PASSWORD)
        b.login(username="alice", password=PASSWORD)
        new = "Brand-New-Pass-7#z"
        response = a.post(reverse("accounts:password_change"), {
            "old_password": PASSWORD, "new_password1": new, "new_password2": new})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(a.get(reverse("accounts:profile")).status_code, 200)
        self.assertEqual(b.get(reverse("accounts:profile")).status_code, 302)
        user.refresh_from_db()
        self.assertTrue(user.check_password(new))

    def test_reset_flow_and_S7_identical_responses(self):
        user = make_user()
        url = reverse("accounts:password_reset")
        known = self.client.post(url, {"email": "alice@example.com"})
        unknown = Client().post(url, {"email": "ghost@example.com"})
        self.assertEqual(known.status_code, unknown.status_code)
        self.assertEqual(known["Location"], unknown["Location"])
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["alice@example.com"])
        _url, path = last_mail_link()
        page = self.client.get(path, follow=True)
        self.assertEqual(page.status_code, 200)
        set_url = page.redirect_chain[-1][0]
        new = "Reset-Pass-123!x"
        done = self.client.post(set_url, {"new_password1": new, "new_password2": new})
        self.assertRedirects(done, reverse("accounts:password_reset_complete"), fetch_redirect_response=False)
        user.refresh_from_db()
        self.assertTrue(user.check_password(new))
        self.assertEqual(Client().post(reverse("accounts:login"), {"username": "alice", "password": new}).status_code, 302)

    def test_reset_not_sent_for_inactive(self):
        user = make_user()
        User.objects.filter(pk=user.pk).update(is_active=False)
        self.client.post(reverse("accounts:password_reset"), {"email": "alice@example.com"})
        self.assertEqual(mail.outbox, [])
