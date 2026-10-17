from unittest import mock

from django.core.cache import cache
from django.test import Client, override_settings
from django.urls import reverse

from .helpers import PASSWORD, AccountsTestCase, make_user

LOGIN = "accounts:login"


def bad_login(client, ident="alice", **extra):
    return client.post(reverse(LOGIN), {"username": ident, "password": "Wrong-pass-1!"}, **extra)


@override_settings(ACCOUNTS_RATE_LIMITS={"login": "3/5m"})
class RateLimitTests(AccountsTestCase):
    def setUp(self):
        super().setUp()
        make_user("alice")

    def test_H1_S14a_n_plus_one_attempt_gets_429(self):
        for _ in range(3):
            self.assertEqual(bad_login(self.client).status_code, 200)
        r = bad_login(self.client)
        self.assertEqual(r.status_code, 429)
        self.assertContains(r, "Juda ko'p urinish", status_code=429)

    def test_S14b_window_expires(self):
        import time
        now = time.time()
        with mock.patch("time.time", return_value=now):
            for _ in range(4):
                bad_login(self.client)
        self.assertEqual(bad_login(self.client).status_code, 429)
        with mock.patch("time.time", return_value=now + 301):
            self.assertEqual(bad_login(self.client).status_code, 200)

    def test_S14c_other_ip_unaffected(self):
        for _ in range(4):
            bad_login(self.client)
        self.assertEqual(bad_login(self.client).status_code, 429)
        self.assertEqual(bad_login(Client(), REMOTE_ADDR="10.9.9.9").status_code, 200)

    def test_S14d_same_identifier_other_ip_does_not_block_victim(self):
        for i in range(6):
            bad_login(Client(), ident="alice", REMOTE_ADDR=f"10.0.0.{i}")
        r = Client().post(reverse(LOGIN), {"username": "alice", "password": PASSWORD}, REMOTE_ADDR="10.1.1.1")
        self.assertEqual(r.status_code, 302)  # qurbon kira oladi

    def test_identifier_plus_ip_key_limits_across_spoofed_identifier_case(self):
        for ident in ("alice", "ALICE", " alice "):
            bad_login(self.client, ident)
        self.assertEqual(bad_login(self.client, "alice").status_code, 429)

    def test_S14e_custom_limiter_takes_precedence(self):
        calls = []
        def limiter(request, scope):
            calls.append(scope)
            return False
        with override_settings(ACCOUNTS_RATE_LIMITER=limiter):
            self.assertEqual(bad_login(self.client).status_code, 429)
        self.assertEqual(calls, ["login"])
        with override_settings(ACCOUNTS_RATE_LIMITER=lambda r, s: True):
            for _ in range(6):
                self.assertEqual(bad_login(self.client).status_code, 200)

    def test_S14f_cache_failure_fails_open_and_logs(self):
        with mock.patch.object(cache, "add", side_effect=ConnectionError("cache down")):
            with self.assertLogs("accounts", level="ERROR") as logs:
                r = bad_login(self.client)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(any("fail-open" in line for line in logs.output))

    def test_client_ip_getter_hook(self):
        with override_settings(ACCOUNTS_CLIENT_IP_GETTER=lambda request: "1.2.3.4"):
            for _ in range(4):
                bad_login(self.client, REMOTE_ADDR="10.0.0.1")
            self.assertEqual(bad_login(Client(), REMOTE_ADDR="10.0.0.2").status_code, 429)  # getter bitta IP beradi

    @override_settings(ACCOUNTS_RATE_LIMITS={"signup": "2/h"})
    def test_signup_and_reset_scopes_limited(self):
        for i in range(3):
            self.client.post(reverse("accounts:signup"), {"username": f"u{i}", "email": f"u{i}@x.com", "password1": "x", "password2": "x"})
        self.assertEqual(self.client.post(reverse("accounts:signup"), {}).status_code, 429)

    @override_settings(ACCOUNTS_RATE_LIMITS={"password_reset": "1/h"})
    def test_reset_scope(self):
        self.client.post(reverse("accounts:password_reset"), {"email": "a@x.com"})
        self.assertEqual(self.client.post(reverse("accounts:password_reset"), {"email": "a@x.com"}).status_code, 429)

    def test_get_requests_are_not_limited(self):
        for _ in range(10):
            self.assertEqual(self.client.get(reverse(LOGIN)).status_code, 200)
