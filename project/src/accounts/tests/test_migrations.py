from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase


class MigrationRoundTripTests(TransactionTestCase):
    """S24: faqat 0001 bor (additive 0002 yo'q), shuning uchun: constraint ishlashi va orqaga/oldinga yurish."""

    def migrate(self, target):
        executor = MigrationExecutor(connection)
        executor.migrate(target)
        if target[0][1] is None:
            return None
        executor.loader.build_graph()
        return executor.loader.project_state(target).apps

    def test_populated_db_roundtrip_and_constraints(self):
        from django.db import IntegrityError, transaction

        latest = [("accounts", "0001_initial")]
        apps = self.migrate(latest)
        User = apps.get_model("accounts", "User")
        user = User.objects.create(username="alice", email="a@example.com", password="x", role="teacher",
                                   pending_email="n@example.com")
        apps.get_model("accounts", "PrivacySettings").objects.create(user=user)
        apps.get_model("accounts", "EmailVerificationToken").objects.create(
            user=user, token_hash="h" * 64, email="a@example.com", expires_at="2030-01-01T00:00:00Z")
        apps.get_model("accounts", "DeletedAccount").objects.create(user_id=999)
        # constraint: Lower(username) shartli unikal
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.create(username="ALICE", email="z@example.com", password="x")
        # orqaga: accounts ni nolga qaytarish va yana oldinga (sxema butun)
        self.migrate([("accounts", None)])
        apps = self.migrate(latest)
        self.assertEqual(apps.get_model("accounts", "User").objects.count(), 0)  # jadval qayta yaratildi
