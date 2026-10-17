from io import StringIO
from unittest import mock

from django.core.management import CommandError, call_command
from django.test import Client, override_settings
from django.urls import reverse
from django.utils import timezone

from accounts import services, signals
from accounts.models import DeletedAccount, User
from accounts.tokens import accounts_token_generator

from .helpers import PASSWORD, AccountsTestCase, make_superuser, make_user

DANGER = {"current_password": PASSWORD, "confirm": "on"}


class SessionInvalidationTests(AccountsTestCase):
    def test_S9_deactivate_then_reactivate_old_cookie_dead(self):
        user = make_user("alice")
        old = Client()
        old.login(username="alice", password=PASSWORD)
        self.assertEqual(old.get(reverse("accounts:profile")).status_code, 200)
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(services.deactivate_account(user))
        self.assertEqual(old.get(reverse("accounts:profile")).status_code, 302)
        self.assertIsNotNone(services.reactivate_account("alice", PASSWORD))
        self.assertEqual(old.get(reverse("accounts:profile")).status_code, 302)  # tirilmaydi
        fresh = Client()
        fresh.login(username="alice", password=PASSWORD)
        self.assertEqual(fresh.get(reverse("accounts:profile")).status_code, 200)

    def test_S9_reset_token_dies_after_deactivate_and_delete_request(self):
        from django.contrib.auth.tokens import default_token_generator as _  # noqa: F401
        user = make_user("alice")
        token = accounts_token_generator.make_token(user)
        self.assertTrue(accounts_token_generator.check_token(user, token))
        services.deactivate_account(user)
        user.refresh_from_db()
        self.assertFalse(accounts_token_generator.check_token(user, token))

    @override_settings(ACCOUNTS_DELETION_GRACE_PERIOD=3600)
    def test_S9_delete_pending_kills_session(self):
        user = make_user("alice")
        c = Client()
        c.login(username="alice", password=PASSWORD)
        self.assertEqual(services.delete_user_account(user), "pending")
        self.assertEqual(c.get(reverse("accounts:profile")).status_code, 302)

    def test_epoch_zero_keeps_hash_unchanged_for_existing_users(self):
        from django.contrib.auth.base_user import AbstractBaseUser
        user = make_user("alice")
        base = AbstractBaseUser._get_session_auth_hash(user)  # epoch aralashmagan Django hash'i
        self.assertEqual(user.get_session_auth_hash(), base)
        user.session_epoch = 1
        self.assertNotEqual(user.get_session_auth_hash(), base)
        user.session_epoch = 2
        self.assertNotEqual(user.get_session_auth_hash(), AbstractBaseUser._get_session_auth_hash(user))


class StateMatrixTests(AccountsTestCase):
    def test_S23_active_deactivated_blocked_pending(self):
        now = timezone.now()
        states = {
            "active": dict(is_active=True),
            "deactivated": dict(is_active=False, deactivated_at=now),
            "blocked": dict(is_active=False),
            "pending": dict(is_active=False, deletion_requested_at=now),
        }
        for name, kw in states.items():
            make_user(name, **kw)
        login = lambda n: Client().post(reverse("accounts:login"), {"username": n, "password": PASSWORD})  # noqa: E731
        self.assertEqual(login("active").status_code, 302)
        for n in ("deactivated", "blocked", "pending"):
            self.assertEqual(login(n).status_code, 200, n)
        # reactivate: faqat o'zi faolsizlantirgan
        self.assertIsNone(services.reactivate_account("blocked", PASSWORD))
        self.assertIsNone(services.reactivate_account("pending", PASSWORD))
        self.assertIsNone(services.reactivate_account("active", PASSWORD))
        self.assertIsNone(services.reactivate_account("deactivated", "wrong"))
        user = services.reactivate_account("deactivated", PASSWORD)
        self.assertTrue(user.is_active)
        self.assertIsNone(user.deactivated_at)
        # pending: get_user None
        pending = User.objects.get(username="pending")
        from accounts.backends import AccountsBackend
        self.assertIsNone(AccountsBackend().get_user(pending.pk))

    def test_pending_does_not_hold_identifier(self):
        make_user("alice", "alice@example.com", is_active=False, deletion_requested_at=timezone.now())
        r = self.client.post(reverse("accounts:signup"), {
            "username": "alice", "email": "alice@example.com", "password1": PASSWORD, "password2": PASSWORD})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(User.objects.filter(username="alice").count(), 2)

    def test_idempotent(self):
        user = make_user("alice")
        self.assertTrue(services.deactivate_account(user))
        self.assertFalse(services.deactivate_account(user))
        user2 = make_user("bob")
        self.assertEqual(services.delete_user_account(user2), "deleted")
        self.assertFalse(services.delete_user_account(user2))

    def test_reactivate_view(self):
        user = make_user("alice")
        services.deactivate_account(user)
        r = self.client.post(reverse("accounts:reactivate"), {"username": "alice", "password": PASSWORD})
        self.assertRedirects(r, reverse("accounts:login"), fetch_redirect_response=False)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        bad = self.client.post(reverse("accounts:reactivate"), {"username": "alice", "password": "bad"})
        self.assertEqual(bad.status_code, 200)

    def test_deactivate_view_requires_password(self):
        user = make_user("alice")
        self.client.force_login(user)
        r = self.client.post(reverse("accounts:deactivate"), {"current_password": "bad", "confirm": "on"})
        self.assertEqual(r.status_code, 200)
        user.refresh_from_db()
        self.assertTrue(user.is_active)
        self.client.post(reverse("accounts:deactivate"), DANGER)
        user.refresh_from_db()
        self.assertFalse(user.is_active)
        self.assertIsNotNone(user.deactivated_at)


class DeletionTests(AccountsTestCase):
    def test_grace_zero_hard_delete_tombstone_and_signal(self):
        user = make_user("alice")
        uid = user.pk
        received = []
        receiver = lambda sender, user_id, **kw: received.append(user_id)  # noqa: E731
        signals.account_deleted.connect(receiver, weak=False)
        self.addCleanup(signals.account_deleted.disconnect, receiver)
        self.client.force_login(user)
        with self.captureOnCommitCallbacks(execute=True):
            self.client.post(reverse("accounts:delete"), DANGER)
        self.assertFalse(User.objects.filter(pk=uid).exists())
        self.assertEqual(received, [uid])
        tomb = DeletedAccount.objects.get(user_id=uid)
        self.assertEqual({f.name for f in tomb._meta.fields}, {"id", "user_id", "deleted_at"})  # PII yo'q
        make_user("alice", "alice@example.com")  # identifikator bo'shadi

    @override_settings(ACCOUNTS_DELETION_GRACE_PERIOD=3600)
    def test_grace_pending_then_purge(self):
        user = make_user("alice")
        self.assertEqual(services.delete_user_account(user), "pending")
        self.assertEqual(services.purge_deleted_accounts(), 0)
        self.assertTrue(User.objects.filter(pk=user.pk).exists())
        later = timezone.now() + timezone.timedelta(seconds=3601)
        out = StringIO()
        with mock.patch("accounts.services._now", return_value=later):
            pass
        self.assertEqual(services.purge_deleted_accounts(now=later), 1)
        self.assertFalse(User.objects.filter(pk=user.pk).exists())
        self.assertTrue(DeletedAccount.objects.filter(user_id=user.pk).exists())
        call_command("purge_deleted_accounts", stdout=out)
        self.assertIn("0", out.getvalue())

    def test_avatar_file_removed_on_delete(self):
        from django.core.files.base import ContentFile
        user = make_user("alice")
        user.avatar.save("a.png", ContentFile(b"x"), save=True)
        storage, name = user.avatar.storage, user.avatar.name
        self.assertTrue(storage.exists(name))
        with self.captureOnCommitCallbacks(execute=True):
            services.delete_user_account(user)
        self.assertFalse(storage.exists(name))


class SuperuserGuardTests(AccountsTestCase):
    def test_S10_service_paths(self):
        root = make_superuser("root")
        with self.assertRaises(services.LastSuperuserError):
            services.deactivate_account(root)
        with self.assertRaises(services.LastSuperuserError):
            services.delete_user_account(root)
        with self.assertRaises(services.LastSuperuserError):
            services.set_role(root, "user")
        with self.assertRaises(services.LastSuperuserError):
            services.update_privileges(root, is_active=False)
        root.refresh_from_db()
        self.assertTrue(root.is_active and root.is_superuser)

    def test_S10_set_role_command(self):
        make_superuser("root")
        with self.assertRaises(CommandError):
            call_command("set_role", "root", "user", stdout=StringIO())
        self.assertTrue(User.objects.get(username="root").is_superuser)

    def test_second_superuser_allows_demotion_of_one(self):
        a, b = make_superuser("a"), make_superuser("b")
        services.set_role(a, "user")
        a.refresh_from_db()
        self.assertEqual((a.role, a.is_superuser, a.is_staff), ("user", False, True))
        with self.assertRaises(services.LastSuperuserError):
            services.set_role(b, "teacher")

    def test_deactivate_view_shows_error_for_last_superuser(self):
        root = make_superuser("root")
        self.client.force_login(root)
        r = self.client.post(reverse("accounts:deactivate"), DANGER)
        self.assertEqual(r.status_code, 200)
        self.assertContains(r, "Oxirgi faol superuser")

    def test_role_sync_invariants(self):
        user = make_user("alice")
        user.is_superuser = True
        user.save()
        self.assertEqual((user.role, user.is_staff), ("superuser", True))
        user.save(update_fields=["bio"])
        user.refresh_from_db()
        self.assertEqual(user.role, "superuser")

    def test_set_role_promotes(self):
        user = make_user("alice")
        services.set_role(user, "teacher")
        user.refresh_from_db()
        self.assertEqual((user.role, user.is_superuser), ("teacher", False))
        services.set_role(user, "superuser")
        user.refresh_from_db()
        self.assertEqual((user.role, user.is_superuser, user.is_staff), ("superuser", True, True))


class SignalRobustnessTests(AccountsTestCase):
    def test_S22_receiver_exception_does_not_break_request(self):
        def boom(sender, **kw):
            raise RuntimeError("receiver xatosi")
        for sig in (signals.user_signed_up, signals.account_deleted):
            sig.connect(boom, weak=False)
            self.addCleanup(sig.disconnect, boom)
        with self.assertLogs("accounts", level="ERROR") as logs, self.captureOnCommitCallbacks(execute=True):
            r = self.client.post(reverse("accounts:signup"), {
                "username": "newuser", "email": "n@example.com", "password1": PASSWORD, "password2": PASSWORD})
        self.assertEqual(r.status_code, 302)
        self.assertTrue(any("RuntimeError" in line for line in logs.output))
        self.client.force_login(User.objects.get(username="newuser"))
        with self.assertLogs("accounts", level="ERROR"), self.captureOnCommitCallbacks(execute=True):
            r = self.client.post(reverse("accounts:delete"), DANGER)
        self.assertEqual(r.status_code, 302)
        self.assertFalse(User.objects.filter(username="newuser").exists())

    def test_S13_audit_log_has_no_pii(self):
        with self.assertLogs("accounts.audit", level="INFO") as logs, self.captureOnCommitCallbacks(execute=True):
            user = make_user("alice", "secret.mail@example.com")
            services.register_user(username="zed", email="zed.mail@example.com", password=PASSWORD)
            services.deactivate_account(user)
        text = "\n".join(logs.output)
        self.assertIn("account_deactivated user_id=", text)
        for forbidden in ("secret.mail", "zed.mail", PASSWORD, "alice", "zed"):
            self.assertNotIn(forbidden, text)

    def test_raw_fixture_load_does_not_create_privacy(self):
        from accounts.models import PrivacySettings
        user = make_user("alice")
        PrivacySettings.objects.all().delete()
        signals.create_privacy_settings(User, user, created=True, raw=True)
        self.assertEqual(PrivacySettings.objects.count(), 0)


class IdentifierTests(AccountsTestCase):
    def test_S25_find_by_identifier_deterministic_and_command(self):
        bob_email = make_user("bob", "bob@x.com")
        legacy = User.objects.create(username="bob@x.com", email="legacy@example.com")  # eski ma'lumot
        self.assertEqual(User.objects.find_by_identifier("bob@x.com"), bob_email)  # email avval
        self.assertEqual(User.objects.find_by_identifier("BOB"), bob_email)
        out = StringIO()
        call_command("check_identifier_collisions", stdout=out)
        self.assertIn(f"user_id={legacy.pk}", out.getvalue())
        self.assertEqual(User.objects.count(), 2)  # faqat o'qiydi
