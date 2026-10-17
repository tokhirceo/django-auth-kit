"""Birlashtirishda qo'shilgan imkoniyatlar: rate_limit dekoratori, EmailVerifiedRequiredMixin,
sozlamalar sahifasi, kabinet shabloni, HTML email, qulf/poyga himoyasi."""
from unittest import mock

from django.contrib.messages import get_messages
from django.core import mail
from django.db import IntegrityError, transaction
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.urls import reverse
from django.utils import timezone
from django.views import View

from accounts import services
from accounts.decorators import EmailVerifiedRequiredMixin, email_verified_required, rate_limit
from accounts.models import EmailVerificationToken, User

from .helpers import PASSWORD, AccountsTestCase, make_user

SITE = override_settings(ACCOUNTS_SITE_URL="https://site.example")


def _req(method="post", user=None, **data):
    rf = RequestFactory()
    request = getattr(rf, method)("/x/", data)
    request.user = user
    request.session = {}
    return request


# ------------------------------------------------------------------ rate_limit dekoratori
@override_settings(ACCOUNTS_RATE_LIMITS={"login": "2/5m"})
class RateLimitDecoratorTests(AccountsTestCase):
    def setUp(self):
        super().setUp()
        self.view = rate_limit("login")(lambda request: HttpResponse("ok"))

    def test_post_limited_after_threshold_get_never(self):
        statuses = [self.view(_req()).status_code for _ in range(4)]
        self.assertEqual(statuses, [200, 200, 429, 429])
        self.assertEqual(self.view(_req("get")).status_code, 200)

    def test_429_uses_rate_limited_template(self):
        for _ in range(2):
            self.view(_req())
        response = self.view(_req())
        self.assertEqual(response.status_code, 429)
        self.assertTrue(response.content)

    def test_identifier_separates_buckets_but_ip_bucket_still_applies(self):
        # identifikator IP bilan birga hisoblanadi; IP kaliti ham alohida ishlaydi
        view = rate_limit("login", identifier=lambda r: r.POST.get("username"))(lambda request: HttpResponse("ok"))
        self.assertEqual(view(_req(username="a")).status_code, 200)
        self.assertEqual(view(_req(username="b")).status_code, 200)
        self.assertEqual(view(_req(username="c")).status_code, 429)  # IP chegarasi (2) oshdi

    def test_custom_limiter_wins(self):
        with override_settings(ACCOUNTS_RATE_LIMITER=lambda request, scope: False):
            self.assertEqual(self.view(_req()).status_code, 429)
        with override_settings(ACCOUNTS_RATE_LIMITER=lambda request, scope: True):
            for _ in range(5):
                self.assertEqual(self.view(_req()).status_code, 200)

    def test_cache_failure_fails_open(self):
        with mock.patch("accounts.ratelimit.cache.add", side_effect=RuntimeError("cache down")):
            with self.assertLogs("accounts", level="ERROR"):
                self.assertEqual(self.view(_req()).status_code, 200)


# ------------------------------------------------------------ EmailVerifiedRequiredMixin
class _Page(EmailVerifiedRequiredMixin, View):
    def get(self, request):
        return HttpResponse("secret")


class EmailVerifiedMixinTests(AccountsTestCase):
    def call(self, user):
        request = _req("get", user=user)
        return _Page.as_view()(request)

    def test_anonymous_goes_to_login(self):
        from django.contrib.auth.models import AnonymousUser

        response = self.call(AnonymousUser())
        self.assertEqual(response.status_code, 302)
        self.assertIn(reverse("accounts:login"), response["Location"])

    @override_settings(ACCOUNTS_REQUIRE_EMAIL_VERIFICATION=True)
    def test_unverified_blocked_verified_allowed_when_required(self):
        unverified = make_user("u1")
        self.assertRedirects(
            self.call(unverified), reverse("accounts:verification_required"), fetch_redirect_response=False
        )
        verified = make_user("u2", is_email_verified=True)
        self.assertEqual(self.call(verified).status_code, 200)

    @override_settings(ACCOUNTS_REQUIRE_EMAIL_VERIFICATION=False)
    def test_not_enforced_when_verification_off(self):
        self.assertEqual(self.call(make_user("u3")).status_code, 200)

    @override_settings(ACCOUNTS_REQUIRE_EMAIL_VERIFICATION=True)
    def test_function_decorator_matches_mixin(self):
        view = email_verified_required(lambda request: HttpResponse("ok"))
        self.assertEqual(view(_req("get", user=make_user("u4"))).status_code, 302)
        self.assertEqual(view(_req("get", user=make_user("u5", is_email_verified=True))).status_code, 200)


# ------------------------------------------------------------------- sozlamalar + kabinet
class CabinetTests(AccountsTestCase):
    def setUp(self):
        super().setUp()
        self.user = make_user("alice")
        self.client.force_login(self.user)

    def test_settings_requires_login(self):
        self.client.logout()
        r = self.client.get(reverse("accounts:settings"))
        self.assertEqual(r.status_code, 302)
        self.assertIn(reverse("accounts:login"), r["Location"])

    def test_settings_page_links_and_status(self):
        r = self.client.get(reverse("accounts:settings"))
        self.assertEqual(r.status_code, 200)
        for name in ("profile_edit", "privacy", "password_change", "email_change", "deactivate", "delete"):
            self.assertContains(r, reverse(f"accounts:{name}"))

    def test_cabinet_pages_render_in_shell(self):
        for name in ("profile", "profile_edit", "privacy", "password_change", "email_change",
                     "deactivate", "delete", "settings"):
            r = self.client.get(reverse(f"accounts:{name}"))
            self.assertEqual(r.status_code, 200, name)
            self.assertTemplateUsed(r, "accounts/accounts_base.html")

    def test_flash_message_rendered_exactly_once(self):
        r = self.client.post(
            reverse("accounts:profile_edit"), {"first_name": "Ali", "last_name": "Valiyev", "phone": "", "bio": ""},
            follow=True,
        )
        self.assertContains(r, "Profil saqlandi.", count=1)

    def test_profile_shows_pending_email_and_resend_for_owner(self):
        self.user.pending_email = "new@example.com"
        self.user.is_email_verified = True
        self.user.save()
        r = self.client.get(reverse("accounts:profile"))
        self.assertContains(r, "new@example.com")
        self.assertContains(r, reverse("accounts:resend_verification"))

    def test_public_profile_anonymous_hides_private_data(self):
        self.client.logout()
        r = self.client.get(reverse("accounts:public_profile", args=["alice"]))
        self.assertEqual(r.status_code, 200)
        self.assertNotContains(r, "alice@example.com")  # email default: nobody
        self.assertNotContains(r, "Hisob ma‘lumotlari")  # faqat egasi uchun bo'lim
        self.assertNotContains(r, reverse("accounts:logout"))  # anonim uchun sidebar yo'q

    def test_public_profile_self_shows_account_section(self):
        r = self.client.get(reverse("accounts:public_profile", args=["alice"]))
        self.assertContains(r, "Hisob ma‘lumotlari")

    def test_public_profile_404_for_inactive(self):
        make_user("ghost", is_active=False)
        self.assertEqual(self.client.get(reverse("accounts:public_profile", args=["ghost"])).status_code, 404)

    @override_settings(ACCOUNTS_DELETION_GRACE_PERIOD=7 * 86400)
    def test_delete_page_mentions_grace_days(self):
        self.assertContains(self.client.get(reverse("accounts:delete")), "7 kunlik")

    def test_delete_page_without_grace_has_no_grace_text(self):
        self.assertNotContains(self.client.get(reverse("accounts:delete")), "kunlik kutish")

    def test_display_name_in_public_profile_data(self):
        data = services.get_public_profile(self.user, self.user)
        self.assertEqual(data["display_name"], "alice")
        self.user.first_name, self.user.last_name = "Ali", "Valiyev"
        self.user.save()
        self.assertEqual(services.get_public_profile(self.user, self.user)["display_name"], "Ali Valiyev")


# ------------------------------------------------------------------------- HTML email
@SITE
class HtmlEmailTests(AccountsTestCase):
    def _html(self, message):
        alts = [a for a in message.alternatives if a[1] == "text/html"]
        self.assertEqual(len(alts), 1)
        return alts[0][0]

    def test_verification_email_has_text_and_html(self):
        user = make_user("bob")
        self.assertEqual(services.send_verification_email(user), services.SENT)
        msg = mail.outbox[-1]
        url = [w for w in msg.body.split() if w.startswith("https://site.example")][0]
        self.assertIn(f'href="{url}"', self._html(msg))
        self.assertIn("24 soat", msg.body)
        self.assertIn("24 soat", self._html(msg))

    def test_html_escapes_username(self):
        user = make_user("carol")
        user.username = "<b>x</b>"  # saqlanmaydi; faqat shablon escaping'ini tekshiradi
        services.send_verification_email(user)
        html = self._html(mail.outbox[-1])
        self.assertNotIn("<b>x</b>", html)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)

    def test_password_reset_email_has_text_and_html(self):
        make_user("dave")
        self.client.post(reverse("accounts:password_reset"), {"email": "dave@example.com"})
        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertIn("/accounts/password/reset/", msg.body)
        self.assertIn("/accounts/password/reset/", self._html(msg))


# ------------------------------------------------------------------ qulf / poyga himoyasi
class LockAndRaceTests(AccountsTestCase):
    def test_lock_user_requires_atomic_and_refreshes(self):
        user = make_user("erin")
        User.objects.filter(pk=user.pk).update(bio="DB'da yangilandi")
        with transaction.atomic():
            services._lock_user(user)
        self.assertEqual(user.bio, "DB'da yangilandi")

    def test_lock_user_missing_row_raises(self):
        user = make_user("frank")
        pk = user.pk
        User.objects.filter(pk=pk).delete()
        with transaction.atomic():
            with self.assertRaises(User.DoesNotExist):
                services._lock_user(user)

    def test_delete_account_twice_is_idempotent(self):
        user = make_user("gina")
        stale = User.objects.get(pk=user.pk)
        self.assertEqual(services.delete_user_account(user), "deleted")
        self.assertFalse(services.delete_user_account(stale))

    def test_reactivate_vanished_user_returns_none(self):
        user = make_user("hank")
        services.deactivate_account(user)
        with mock.patch.object(services, "_lock_user", side_effect=User.DoesNotExist):
            self.assertIsNone(services.reactivate_account("hank", PASSWORD))

    def test_email_change_confirm_race_returns_taken_not_500(self):
        """identifier_taken tekshiruvidan keyin boshqa hisob shu emailni egallab olsa: DB constraint ushlaydi."""
        user = make_user("ivan", email="ivan@example.com", is_email_verified=True)
        user.pending_email = "race@example.com"
        user.save()
        raw = EmailVerificationToken.issue(user, "race@example.com")
        make_user("thief", email="race@example.com")  # poyga: email band bo'ldi
        with mock.patch.object(User.objects.__class__, "identifier_taken", return_value=False):
            status, returned = services.confirm_email_token(raw)
        self.assertEqual(status, services.TAKEN)
        user.refresh_from_db()
        self.assertEqual(user.email, "ivan@example.com")
        self.assertEqual(user.pending_email, "")

    def test_request_email_change_noop_when_same_or_taken(self):
        user = make_user("jane")
        make_user("kate", email="kate@example.com")
        self.assertEqual(services.request_email_change(user, "JANE@example.com"), services.NOOP)
        self.assertEqual(services.request_email_change(user, "kate@example.com"), services.NOOP)
        user.refresh_from_db()
        self.assertEqual(user.pending_email, "")

    @SITE
    def test_request_email_change_sets_pending_and_sends(self):
        user = make_user("lena")
        self.assertEqual(services.request_email_change(user, "lena2@example.com"), services.SENT)
        user.refresh_from_db()
        self.assertEqual(user.pending_email, "lena2@example.com")
        self.assertEqual(mail.outbox[-1].to, ["lena2@example.com"])
