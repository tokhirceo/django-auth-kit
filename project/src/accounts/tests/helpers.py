import re
from urllib.parse import urlparse

from django.core import mail
from django.core.cache import cache
from django.core.mail.backends.base import BaseEmailBackend
from django.test import TestCase

from accounts.models import User

PASSWORD = "S3cure-Pass-9f!x"


class FailingEmailBackend(BaseEmailBackend):
    """Har doim xato beradi (SMTP ishdan chiqqan holatni modellashtiradi)."""

    def send_messages(self, email_messages):
        raise ConnectionError("SMTP ishlamayapti (test)")


class AccountsTestCase(TestCase):
    def setUp(self):
        super().setUp()
        cache.clear()  # rate limit hisoblagichlari testlar orasida aralashmasin


def make_user(username="alice", email=None, password=PASSWORD, **extra):
    return User.objects.create_user(username, email or f"{username}@example.com", password, **extra)


def make_superuser(username="root", **extra):
    return User.objects.create_superuser(username, f"{username}@example.com", PASSWORD, **extra)


def last_mail_link(index=-1):
    """Oxirgi xatdagi birinchi havola: (to'liq URL, path)."""
    body = mail.outbox[index].body
    url = re.search(r"https?://\S+", body).group(0)
    return url, urlparse(url).path
