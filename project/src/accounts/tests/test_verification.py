from datetime import timedelta
from unittest import mock

from django.core import mail
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone

from accounts import services
from accounts.models import EmailVerificationToken, User

from .helpers import PASSWORD, AccountsTestCase, last_mail_link, make_user

ON = override_settings(ACCOUNTS_REQUIRE_EMAIL_VERIFICATION=True, ACCOUNTS_SITE_URL="https://site.example")
SIGNUP = {"username": "newuser", "email": "new@example.com", "password1": PASSWORD, "password2": PASSWORD}


@ON
class VerificationOnTests(AccountsTestCase):
    def test_S18_signup_verify_login_flow(self):
        r = self.client.post(reverse("accounts:signup"), SIGNUP)
        self.assertRedirects(r, reverse("accounts:verification_required"), fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(len(mail.outbox), 1)
        url, path = last_mail_link()
        self.assertTrue(url.startswith("https://site.example/accounts/verify/"))
        # GET sarflamaydi (H2)
        self.assertEqual(self.client.get(path).status_code, 200)
        self.assertEqual(EmailVerificationToken.objects.filter(used_at__isnull=True).count(), 1)
        # POST sarflaydi
        self.client.post(path)
        user = User.objects.get(username="newuser")
        self.assertTrue(user.is_email_verified)
        self.assertEqual(EmailVerificationToken.objects.filter(used_at__isnull=False).count(), 1)
        r = Client().post(reverse("accounts:login"), {"username": "newuser", "password": PASSWORD})
        self.assertRedirects(r, reverse("accounts:profile"), fetch_redirect_response=False)

    def test_unverified_login_is_parked_not_logged_in(self):
        make_user("bob")
        r = self.client.post(reverse("accounts:login"), {"username": "bob", "password": PASSWORD})
        self.assertRedirects(r, reverse("accounts:verification_required"), fetch_redirect_response=False)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertEqual(self.client.get(reverse("accounts:verification_required")).status_code, 200)

    def test_H17_parking_key_cleared_after_verified_login(self):
        user = make_user("bob")
        self.client.post(reverse("accounts:login"), {"username": "bob", "password": PASSWORD})
        self.assertIn(services.PENDING_KEY, self.client.session)
        User.objects.filter(pk=user.pk).update(is_email_verified=True)
        self.client.post(reverse("accounts:login"), {"username": "bob", "password": PASSWORD})
        self.assertNotIn(services.PENDING_KEY, self.client.session)

    def test_token_single_use_expiry_and_foreign_rejected(self):
        user = make_user("bob")
        raw = EmailVerificationToken.issue(user, user.email)
        path = reverse("accounts:verify_email", args=[raw])
        self.assertEqual(self.client.post(path).status_code, 302)
        self.assertEqual(self.client.post(path).status_code, 400)  # bir martalik
        self.assertEqual(self.client.get(reverse("accounts:verify_email", args=["x" * 43])).status_code, 400)
        raw2 = EmailVerificationToken.issue(user, user.email)
        EmailVerificationToken.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
        self.assertEqual(self.client.post(reverse("accounts:verify_email", args=[raw2])).status_code, 400)

    def test_S8_only_hash_stored_and_new_token_invalidates_old(self):
        user = make_user("bob")
        old = EmailVerificationToken.issue(user, user.email)
        new = EmailVerificationToken.issue(user, user.email)
        self.assertFalse(EmailVerificationToken.objects.filter(token_hash=old).exists())
        self.assertNotIn(new, list(EmailVerificationToken.objects.values_list("token_hash", flat=True)))
        self.assertIsNone(EmailVerificationToken.find_valid(old))
        self.assertIsNotNone(EmailVerificationToken.find_valid(new))

    def test_verify_page_headers(self):
        user = make_user("bob")
        raw = EmailVerificationToken.issue(user, user.email)
        r = self.client.get(reverse("accounts:verify_email", args=[raw]))
        self.assertEqual(r["Referrer-Policy"], "no-referrer")
        self.assertIn("no-store", r["Cache-Control"])

    def test_resend_cooldown_and_identical_response(self):
        self.client.post(reverse("accounts:signup"), SIGNUP)
        self.assertEqual(len(mail.outbox), 1)
        r1 = self.client.post(reverse("accounts:resend_verification"), follow=True)
        self.assertEqual(len(mail.outbox), 1)  # cooldown
        EmailVerificationToken.objects.update(created_at=timezone.now() - timedelta(seconds=120))
        r2 = self.client.post(reverse("accounts:resend_verification"), follow=True)
        self.assertEqual(len(mail.outbox), 2)
        self.assertEqual(r1.status_code, r2.status_code)
        last = lambda r: str(list(r.context["messages"])[-1])  # noqa: E731
        self.assertEqual(last(r1), last(r2))

    @override_settings(ACCOUNTS_FROM_EMAIL="Sayt <hello@site.example>")
    def test_from_email_and_subject_template(self):
        self.client.post(reverse("accounts:signup"), SIGNUP)
        self.assertEqual(mail.outbox[0].from_email, "Sayt <hello@site.example>")
        self.assertEqual(mail.outbox[0].subject, "Email manzilingizni tasdiqlang")

    def test_decorator_blocks_unverified(self):
        from django.http import HttpResponse
        from django.test import RequestFactory
        from accounts.decorators import email_verified_required

        view = email_verified_required(lambda request: HttpResponse("ok"))
        rf = RequestFactory().get("/")
        rf.user = make_user("bob")
        self.assertEqual(view(rf).status_code, 302)
        User.objects.filter(pk=rf.user.pk).update(is_email_verified=True)
        rf.user.refresh_from_db()
        self.assertEqual(view(rf).content, b"ok")

    def test_S20_email_change_requires_confirmation_and_keeps_verified(self):
        user = make_user("bob", is_email_verified=True)
        self.client.force_login(user)
        r = self.client.post(reverse("accounts:email_change"), {"new_email": "new@example.com", "current_password": PASSWORD})
        self.assertEqual(r.status_code, 302)
        user.refresh_from_db()
        self.assertEqual(user.email, "bob@example.com")  # eski amal qiladi
        self.assertEqual(user.pending_email, "new@example.com")
        self.assertTrue(user.is_email_verified)  # H11: qulflanmaydi
        self.assertEqual(mail.outbox[0].to, ["new@example.com"])
        self.client.post(last_mail_link()[1])
        user.refresh_from_db()
        self.assertEqual((user.email, user.pending_email, user.is_email_verified), ("new@example.com", "", True))
        # logout -> login: qulflanmagan
        c = Client()
        r = c.post(reverse("accounts:login"), {"username": "new@example.com", "password": PASSWORD})
        self.assertRedirects(r, reverse("accounts:profile"), fetch_redirect_response=False)

    def test_email_change_taken_is_silent_noop(self):
        make_user("carol", "taken@example.com")
        user = make_user("bob", is_email_verified=True)
        self.client.force_login(user)
        r = self.client.post(reverse("accounts:email_change"), {"new_email": "taken@example.com", "current_password": PASSWORD}, follow=True)
        self.assertEqual(mail.outbox, [])
        self.assertEqual(r.status_code, 200)
        user.refresh_from_db()
        self.assertEqual(user.pending_email, "")

    def test_email_change_wrong_password_rejected(self):
        user = make_user("bob")
        self.client.force_login(user)
        r = self.client.post(reverse("accounts:email_change"), {"new_email": "n@example.com", "current_password": "nope"})
        self.assertEqual(r.status_code, 200)
        user.refresh_from_db()
        self.assertEqual(user.pending_email, "")


class VerificationOffTests(AccountsTestCase):
    def test_S19_signup_sends_no_mail_and_logs_in(self):
        r = self.client.post(reverse("accounts:signup"), SIGNUP)
        self.assertRedirects(r, reverse("accounts:profile"), fetch_redirect_response=False)
        self.assertEqual(mail.outbox, [])
        self.assertIn("_auth_user_id", self.client.session)

    def test_S19_old_token_still_works_and_required_page_does_not_lock(self):
        user = make_user("bob")
        raw = EmailVerificationToken.issue(user, user.email)
        self.client.post(reverse("accounts:verify_email", args=[raw]))
        user.refresh_from_db()
        self.assertTrue(user.is_email_verified)
        r = self.client.get(reverse("accounts:verification_required"))
        self.assertEqual(r.status_code, 302)
        self.assertNotIn("verification_required", r["Location"])

    def test_unverified_user_logs_in_normally(self):
        make_user("bob")
        r = self.client.post(reverse("accounts:login"), {"username": "bob", "password": PASSWORD})
        self.assertRedirects(r, reverse("accounts:profile"), fetch_redirect_response=False)

    @override_settings(ACCOUNTS_SITE_URL="https://site.example")
    def test_S20_email_change_still_requires_confirmation_when_off(self):
        user = make_user("bob")
        self.client.force_login(user)
        self.client.post(reverse("accounts:email_change"), {"new_email": "new@example.com", "current_password": PASSWORD})
        user.refresh_from_db()
        self.assertEqual((user.email, user.pending_email), ("bob@example.com", "new@example.com"))
        self.assertEqual(len(mail.outbox), 1)

    def test_optional_verify_via_profile_resend(self):
        user = make_user("bob")
        self.client.force_login(user)
        self.client.post(reverse("accounts:resend_verification"))
        self.assertEqual(len(mail.outbox), 1)


class HostAndFailureTests(AccountsTestCase):
    @override_settings(ACCOUNTS_REQUIRE_EMAIL_VERIFICATION=True, ACCOUNTS_SITE_URL="https://site.example", ALLOWED_HOSTS=["*"])
    def test_S17_fake_host_never_in_links(self):
        h = {"HTTP_HOST": "evil.example"}
        self.client.post(reverse("accounts:signup"), SIGNUP, **h)
        user = make_user("bob", is_email_verified=True)
        self.client.force_login(user)
        self.client.post(reverse("accounts:email_change"), {"new_email": "n@example.com", "current_password": PASSWORD}, **h)
        Client().post(reverse("accounts:password_reset"), {"email": "bob@example.com"}, **h)
        self.assertEqual(len(mail.outbox), 3)
        for m in mail.outbox:
            self.assertNotIn("evil.example", m.body)
            self.assertIn("https://site.example/accounts/", m.body)

    @override_settings(ALLOWED_HOSTS=["testserver"], ACCOUNTS_SITE_URL="")
    def test_request_host_used_when_no_site_url(self):
        make_user("bob")
        self.client.post(reverse("accounts:password_reset"), {"email": "bob@example.com"})
        self.assertIn("http://testserver/accounts/password/reset/", mail.outbox[0].body)

    @override_settings(DEBUG=False, ACCOUNTS_SITE_URL="")
    def test_no_request_no_site_url_raises_in_production(self):
        from django.core.exceptions import ImproperlyConfigured
        with self.assertRaises(ImproperlyConfigured):
            services.build_absolute_url("/x/")

    @override_settings(ACCOUNTS_SITE_URL="", DEBUG=True)
    def test_no_request_debug_fallback(self):
        self.assertEqual(services.build_absolute_url("/x/"), "http://localhost:8000/x/")

    FAIL = {"EMAIL_BACKEND": "accounts.tests.helpers.FailingEmailBackend"}

    @override_settings(ACCOUNTS_REQUIRE_EMAIL_VERIFICATION=True, ACCOUNTS_SITE_URL="https://s.example", **FAIL)
    def test_S21_signup_send_failure_keeps_account_and_is_honest(self):
        with self.assertLogs("accounts", level="ERROR"):
            r = self.client.post(reverse("accounts:signup"), SIGNUP, follow=True)
        self.assertTrue(User.objects.filter(username="newuser").exists())
        text = " ".join(str(m) for m in r.context["messages"])
        self.assertIn("yuborilmadi", text)
        self.assertNotIn("ConnectionError", r.content.decode())
        self.assertNotIn("Traceback", r.content.decode())
        self.assertFalse(EmailVerificationToken.objects.exists())

    @override_settings(ACCOUNTS_SITE_URL="https://s.example", **FAIL)
    def test_S21_email_change_send_failure(self):
        user = make_user("bob")
        self.client.force_login(user)
        with self.assertLogs("accounts", level="ERROR"):
            r = self.client.post(reverse("accounts:email_change"), {"new_email": "n@example.com", "current_password": PASSWORD}, follow=True)
        user.refresh_from_db()
        self.assertEqual(user.pending_email, "n@example.com")  # holat saqlanadi
        self.assertIn("yuborib bo'lmadi", " ".join(str(m) for m in r.context["messages"]))

    @override_settings(**FAIL)
    def test_S21_reset_failure_gives_same_done_page(self):
        make_user("bob")
        with self.assertLogs("accounts", level="ERROR"):
            known = self.client.post(reverse("accounts:password_reset"), {"email": "bob@example.com"})
        unknown = Client().post(reverse("accounts:password_reset"), {"email": "ghost@example.com"})
        self.assertEqual((known.status_code, known["Location"]), (unknown.status_code, unknown["Location"]))
