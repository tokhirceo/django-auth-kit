import os
import re
import subprocess
import sys
import warnings
from pathlib import Path
from types import SimpleNamespace

from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from django.test import SimpleTestCase, override_settings

import accounts
from accounts.config import settings as cfg
from accounts.config.settings import ACCOUNTS_DEFAULTS, accounts_settings, from_env, validate

PKG = Path(accounts.__file__).resolve().parent
EXPECTED_DEFAULTS = {
    "REQUIRE_EMAIL_VERIFICATION": False,
    "EMAIL_VERIFICATION_TIMEOUT": 86400,
    "EMAIL_VERIFICATION_RESEND_COOLDOWN": 60,
    "DELETION_GRACE_PERIOD": 0,
    "SITE_URL": "",
    "FROM_EMAIL": None,
    "RATE_LIMITER": None,
    "CLIENT_IP_GETTER": None,
    "IS_BLOCKED_CALLBACK": None,
    "AVATAR_MAX_BYTES": 2 * 1024 * 1024,
    "AVATAR_MAX_SIDE": 6000,
    "AVATAR_MAX_PIXELS": 24_000_000,
    "AVATAR_OUTPUT_SIZE": 512,
}


def ids(settings_obj):
    return {check_id for _level, check_id, _msg in validate(settings_obj)}


def ns(**kw):
    base = dict(DEBUG=True, AUTH_USER_MODEL="accounts.User")
    base.update(kw)
    return SimpleNamespace(**base)


class C1DefaultsTests(SimpleTestCase):
    def test_defaults_match_table(self):
        # harness ACCOUNTS_DEFAULTS ni globals ga ulagan; kanonik qiymatlar jadvalga teng
        for name, expected in EXPECTED_DEFAULTS.items():
            self.assertEqual(ACCOUNTS_DEFAULTS["ACCOUNTS_" + name], expected, name)
            self.assertEqual(getattr(accounts_settings, name), expected, name)
        self.assertEqual(ACCOUNTS_DEFAULTS["ACCOUNTS_RATE_LIMITS"]["login"], "10/5m")
        self.assertEqual(set(ACCOUNTS_DEFAULTS), {"ACCOUNTS_" + n for n in EXPECTED_DEFAULTS} | {"ACCOUNTS_RATE_LIMITS"})

    def test_defaults_work_without_being_wired_into_settings(self):
        bare = SimpleNamespace()
        self.assertEqual(cfg.read(bare, "REQUIRE_EMAIL_VERIFICATION"), False)
        self.assertEqual(cfg.read(bare, "AVATAR_OUTPUT_SIZE"), 512)


class C2OverrideTests(SimpleTestCase):
    def test_override_settings_each_parameter(self):
        values = {
            "REQUIRE_EMAIL_VERIFICATION": True,
            "EMAIL_VERIFICATION_TIMEOUT": 10,
            "EMAIL_VERIFICATION_RESEND_COOLDOWN": 5,
            "DELETION_GRACE_PERIOD": 99,
            "SITE_URL": "https://example.org",
            "FROM_EMAIL": "Ism <a@example.org>",
            "RATE_LIMITER": "os.path.exists",
            "CLIENT_IP_GETTER": "os.path.exists",
            "IS_BLOCKED_CALLBACK": "os.path.exists",
            "AVATAR_MAX_BYTES": 1,
            "AVATAR_MAX_SIDE": 2,
            "AVATAR_MAX_PIXELS": 3,
            "AVATAR_OUTPUT_SIZE": 4,
        }
        for name, value in values.items():
            self.assertNotEqual(getattr(accounts_settings, name), value, name)
            with override_settings(**{"ACCOUNTS_" + name: value}):
                self.assertEqual(getattr(accounts_settings, name), value, name)  # chaqiruv vaqtida
            self.assertNotEqual(getattr(accounts_settings, name), value, name)

    def test_rate_limits_merge_over_defaults(self):
        with override_settings(ACCOUNTS_RATE_LIMITS={"login": "3/s"}):
            self.assertEqual(cfg.get_rate_limit("login"), (3, 1))
            self.assertEqual(cfg.get_rate_limit("signup"), (10, 3600))

    def test_unknown_attribute(self):
        with self.assertRaises(AttributeError):
            accounts_settings.NOPE


class C3LegacyAliasTests(SimpleTestCase):
    def test_legacy_name_works_and_warns(self):
        bare = SimpleNamespace(REQUIRE_EMAIL_VERIFICATION=True)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertIs(cfg.read(bare, "REQUIRE_EMAIL_VERIFICATION"), True)
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))

    def test_all_legacy_aliases_map(self):
        for legacy, canon in cfg.LEGACY_ALIASES.items():
            bare = SimpleNamespace(**{legacy: 7})
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                self.assertEqual(cfg.read(bare, canon), 7, legacy)

    def test_canonical_wins_when_both_given(self):
        both = SimpleNamespace(REQUIRE_EMAIL_VERIFICATION=False, ACCOUNTS_REQUIRE_EMAIL_VERIFICATION=True)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            self.assertIs(cfg.read(both, "REQUIRE_EMAIL_VERIFICATION"), True)
        self.assertTrue(any(issubclass(w.category, DeprecationWarning) for w in caught))

    def test_legacy_via_django_settings(self):
        with override_settings(EMAIL_VERIFICATION_TIMEOUT=123):
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                # harness kanonik defaultni ham ulagan: kanonik g'olib
                self.assertEqual(accounts_settings.EMAIL_VERIFICATION_TIMEOUT, 86400)


class C4ValidateTests(SimpleTestCase):
    def test_clean_config_has_no_errors(self):
        self.assertEqual([x for x in validate(ns()) if x[0] == "E"], [])

    def test_invalid_values_report_expected_ids(self):
        cases = {
            "accounts.E001": {"ACCOUNTS_REQUIRE_EMAIL_VERIFICATION": "yes"},
            "accounts.E002": {"ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT": 0},
            "accounts.E003": {"ACCOUNTS_EMAIL_VERIFICATION_RESEND_COOLDOWN": -1},
            "accounts.E004": {"ACCOUNTS_DELETION_GRACE_PERIOD": True},
            "accounts.E005": {"ACCOUNTS_SITE_URL": "example.org/path"},
            "accounts.E006": {"ACCOUNTS_FROM_EMAIL": "not-an-email"},
            "accounts.E007": {"ACCOUNTS_RATE_LIMITER": "no.such.module.func"},
            "accounts.E008": {"ACCOUNTS_RATE_LIMITS": {"login": "abc"}},
            "accounts.E009": {"ACCOUNTS_CLIENT_IP_GETTER": 5},
            "accounts.E010": {"ACCOUNTS_IS_BLOCKED_CALLBACK": "no.such.cb"},
            "accounts.E011": {"ACCOUNTS_AVATAR_MAX_BYTES": 0},
            "accounts.E012": {"EMAIL_USE_TLS": True, "EMAIL_USE_SSL": True},
            "accounts.E013": {"AUTH_USER_MODEL": "auth.User"},
        }
        for expected, kw in cases.items():
            self.assertIn(expected, ids(ns(**kw)), kw)

    def test_rate_limit_unknown_scope_is_error(self):
        self.assertIn("accounts.E008", ids(ns(ACCOUNTS_RATE_LIMITS={"nope": "1/s"})))

    def test_warnings_for_production(self):
        prod = ns(
            DEBUG=False,
            ACCOUNTS_SITE_URL="http://example.org",
            ALLOWED_HOSTS=["*"],
            EMAIL_BACKEND="django.core.mail.backends.console.EmailBackend",
            DEFAULT_FROM_EMAIL="webmaster@localhost",
            CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
        )
        found = ids(prod)
        for expected in ("accounts.W001", "accounts.W002", "accounts.W003", "accounts.W004", "accounts.W005", "accounts.W006"):
            self.assertIn(expected, found)

    def test_system_check_registered(self):
        with override_settings(ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT=0):
            errors = [m for m in checks.run_checks() if m.id == "accounts.E002"]
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], checks.Error)


class C5ImportCycleTests(SimpleTestCase):
    def test_config_importable_without_django_settings_module(self):
        root = str(PKG.parent)
        code = (
            "import sys; sys.path.insert(0, %r); "
            "import accounts.config.settings as s; "
            "assert 'accounts.models' not in sys.modules; "
            "assert 'accounts.services' not in sys.modules; "
            "assert 'accounts.apps' not in sys.modules; "
            "print('ok')" % root
        )
        env = {k: v for k, v in os.environ.items() if k not in ("DJANGO_SETTINGS_MODULE", "PYTHONPATH")}
        result = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ok", result.stdout)

    def test_package_init_is_empty(self):
        self.assertEqual((PKG / "__init__.py").read_text().strip(), "")


class C6FromEnvTests(SimpleTestCase):
    def test_types_and_only_given_keys(self):
        env = {
            "ACCOUNTS_REQUIRE_EMAIL_VERIFICATION": "true",
            "ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT": "120",
            "ACCOUNTS_SITE_URL": "https://example.org",
            "EMAIL_PORT": "587",
            "EMAIL_USE_TLS": "0",
            "EMAIL_HOST": "smtp.example.org",
            "UNRELATED": "x",
        }
        result = from_env(env)
        self.assertEqual(
            result,
            {
                "ACCOUNTS_REQUIRE_EMAIL_VERIFICATION": True,
                "ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT": 120,
                "ACCOUNTS_SITE_URL": "https://example.org",
                "EMAIL_PORT": 587,
                "EMAIL_USE_TLS": False,
                "EMAIL_HOST": "smtp.example.org",
            },
        )
        self.assertEqual(from_env({}), {})

    def test_invalid_value_raises_with_name_not_value(self):
        for env in ({"EMAIL_PORT": "abc-secret"}, {"ACCOUNTS_REQUIRE_EMAIL_VERIFICATION": "maybe-secret"}):
            with self.assertRaises(ImproperlyConfigured) as ctx:
                from_env(env)
            self.assertIn(next(iter(env)), str(ctx.exception))
            self.assertNotIn("secret", str(ctx.exception))


class C7SecretTests(SimpleTestCase):
    SECRET = "s3cr3t-smtp-password-XYZ"

    def test_secret_not_in_repr_errors_or_validation(self):
        env = {"EMAIL_HOST_PASSWORD": self.SECRET, "EMAIL_PORT": "x"}
        with self.assertRaises(ImproperlyConfigured) as ctx:
            from_env(env)
        self.assertNotIn(self.SECRET, str(ctx.exception))
        values = from_env({"EMAIL_HOST_PASSWORD": self.SECRET})
        self.assertEqual(values["EMAIL_HOST_PASSWORD"], self.SECRET)
        self.assertNotIn(self.SECRET, repr(cfg.redact(values)))
        self.assertNotIn(self.SECRET, repr(accounts_settings))
        messages = validate(ns(EMAIL_HOST_PASSWORD=self.SECRET, ACCOUNTS_SITE_URL="bad"))
        self.assertNotIn(self.SECRET, repr(messages))

    def test_secret_not_in_source_docs_or_env_example(self):
        for path in list(PKG.rglob("*")):
            if path.suffix in {".py", ".md", ".html", ".txt", ".example"} and "tests" not in path.parts:
                text = path.read_text(errors="ignore")
                self.assertNotRegex(text, r"EMAIL_HOST_PASSWORD\s*=\s*['\"][^'\"<]+['\"]", str(path))
        example = (PKG / "env.example").read_text()
        self.assertIn("EMAIL_HOST_PASSWORD=<env", example)


class C8SingleSourceTests(SimpleTestCase):
    def test_conf_module_removed(self):
        self.assertFalse((PKG / "conf.py").exists())

    def test_no_setting_names_or_defaults_outside_config(self):
        token = re.compile(r"ACCOUNTS_[A-Z_]+")
        legacy = re.compile(r"\b(REQUIRE_EMAIL_VERIFICATION|EMAIL_VERIFICATION_TIMEOUT|EMAIL_VERIFICATION_RESEND_COOLDOWN|ACCOUNT_DELETION_GRACE_PERIOD)\b")
        offenders = []
        for path in PKG.rglob("*"):
            if path.suffix not in {".py", ".html", ".txt"}:
                continue
            rel = path.relative_to(PKG)
            if rel.parts[0] in ("tests", "migrations") or rel == Path("config/settings.py"):
                continue
            text = path.read_text()
            if token.search(text):
                offenders.append((str(rel), "ACCOUNTS_"))
            if legacy.search(re.sub(r"accounts_settings\.[A-Z_]+", "", text)):
                offenders.append((str(rel), "legacy"))
        self.assertEqual(offenders, [])

    def test_no_numeric_defaults_duplicated(self):
        for rel in ("services.py", "validators.py", "forms.py", "models.py", "ratelimit.py"):
            text = (PKG / rel).read_text()
            for number in ("86400", "24_000_000", "6000", "2 * 1024 * 1024"):
                self.assertNotIn(number, text, (rel, number))
