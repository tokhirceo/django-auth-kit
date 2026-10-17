# accounts — qayta ishlatiladigan Django identity ilovasi

Signup, login/logout, email tasdiqlash, parol o'zgartirish/tiklash, profil + avatar, maxfiylik,
email o'zgartirish, hisobni faolsizlantirish/qayta yoqish/o'chirish, rollar, admin, audit log,
boshqa ilovalar uchun signallar. UI: server-render Django template + Tailwind (CDN). Auth sahifalari (kirish, ro'yxatdan
o'tish, parol tiklash, tasdiqlash) loyihangizning `base.html` ida; shaxsiy kabinet (profil, sozlamalar, maxfiylik, parol,
email, faolsizlantirish/o'chirish) alohida `accounts/accounts_base.html` qobig'ida (sidebar, qorong'i mavzu; kichik inline CSS/JS bor).

**Sinalgan:** Python 3.12, Django 6.1.2, Pillow 12.1.1, SQLite (154 test, hammasi o'tadi). Django ≥ 4.2 maqsad qilingan, lekin
**boshqa versiyalar va PostgreSQL tekshirilmagan**. MySQL/MariaDB (shartli/ifodali `UniqueConstraint`) — qo'llab-quvvatlanmaydi.

## O'rnatish (3 qadam)

1. `accounts/` papkasini loyiha ildiziga nusxalang. `pip install django pillow`.
2. Loyiha `settings.py` ga qo'shing:

```python
import os
from accounts.config.settings import ACCOUNTS_DEFAULTS, from_env   # toza modul: import sikli yo'q

INSTALLED_APPS += ["accounts"]          # + django.contrib.{admin,auth,contenttypes,sessions,messages}
AUTH_USER_MODEL = "accounts.User"
AUTHENTICATION_BACKENDS = ["accounts.backends.AccountsBackend"]
SILENCED_SYSTEM_CHECKS = ["auth.W004"]  # unikallik shartli constraint orqali ta'minlanadi
LOGIN_URL = "accounts:login"
LOGIN_REDIRECT_URL = "accounts:profile"
LOGOUT_REDIRECT_URL = "home"            # o'zingizning URL nomingiz
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

globals().update(ACCOUNTS_DEFAULTS)     # 1) defaultlar (ixtiyoriy; ulamasangiz ham ilova default bilan ishlaydi)
globals().update(from_env(os.environ))  # 2) env bilan (ixtiyoriy)
ACCOUNTS_REQUIRE_EMAIL_VERIFICATION = False   # 3) aniq override (oxirgi so'z)
```

3. `urls.py`:

```python
from django.conf import settings
from django.conf.urls.static import static
urlpatterns += [path("accounts/", include("accounts.urls"))]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
```

Keyin: `python manage.py migrate`. **`AUTH_USER_MODEL` ni birinchi `migrate` dan oldin o'rnating** (mavjud DB'da user modelini almashtirish Django'da qo'lda migratsiya talab qiladi).

### Shaxsiy kabinet qobig'i (`accounts/accounts_base.html`)
Profil, sozlamalar, maxfiylik, parol/email o'zgartirish, faolsizlantirish va o'chirish sahifalari shu qobiqni kengaytiradi
(sidebar, qorong'i/yorug' mavzu, `Tailwind CDN` + kichik inline CSS/JS). Talablar: `django.template.context_processors.request`,
`django.contrib.messages` va loyihada `home` nomli URL. Qobiq xabarlarni o'zi chiqaradi (kabinet sahifalarida `_messages.html` ishlatilmaydi).
Moslashtirish: loyihangizda `templates/accounts/accounts_base.html` yarating (Django o'sha faylni oladi) yoki
`{% block site_name %}`, `{% block brand_name %}`, `{% block sidebar_extra %}`, `{% block extra_head %}` bloklaridan foydalaning.
Production'da `cdn.tailwindcss.com` o'rniga kompilyatsiya qilingan CSS ulang (`{% block tailwind %}`).

### `base.html` kontrakti
Auth sahifalari (login, signup, parol tiklash, tasdiqlash...) `{% extends "base.html" %}` va `{% block title %}` / `{% block content %}` ni kutadi. Xabarlarni
`accounts/_messages.html` o'zi chiqaradi — `base.html` da `messages` ni qayta chiqarsangiz takrorlanadi.
`<html lang="uz">` tavsiya. Tailwind CDN `base.html` da ulanadi (ilova CSS yozmaydi).

## Arxitektura
```
models.py      User, PrivacySettings, EmailVerificationToken, DeletedAccount
managers.py    UserManager (create_user / find_by_identifier / live / identifier_taken)
services.py    BARCHA biznes qoidalar (view'lar yupqa): register_user, send_verification_email, confirm_email_token,
               request_email_change, deactivate/reactivate/delete_user_account, update_privileges, get_public_profile
forms.py       formalar (Tailwind klasslari, avatar qayta ishlash)      validators.py  avatar/telefon/username
ratelimit.py   cache limiter + RateLimitMixin (CBV) + rate_limit (funksiya-view dekoratori)
decorators.py  role_required, teacher_required, RoleRequiredMixin, email_verified_required, EmailVerifiedRequiredMixin
signals.py     voqealar (barchasi tranzaksiya commit bo'lgandan keyin yuboriladi)       config/settings.py  yagona manba
```
Boshqa ilovalar faqat `settings.AUTH_USER_MODEL` / `get_user_model()` va signallar orqali bog'lanadi; `accounts` hech qaysi ilovani import qilmaydi.

## Sozlamalar (kodga mos; defaultlar faqat `accounts/config/settings.py` da)

| Nom | Standart | Qabul qilinadi | Ishlatiladi |
|---|---|---|---|
| `ACCOUNTS_REQUIRE_EMAIL_VERIFICATION` | `False` | bool | login, signup, resend, decorator |
| `ACCOUNTS_EMAIL_VERIFICATION_TIMEOUT` | `86400` s | int > 0 | token muddati |
| `ACCOUNTS_EMAIL_VERIFICATION_RESEND_COOLDOWN` | `60` s | int ≥ 0 | qayta yuborish oralig'i |
| `ACCOUNTS_DELETION_GRACE_PERIOD` | `0` s | int ≥ 0 | 0 = darhol o'chirish; >0 = `purge_deleted_accounts` |
| `ACCOUNTS_SITE_URL` | `""` | `http(s)://host[:port]` | barcha xatlardagi havola |
| `ACCOUNTS_FROM_EMAIL` | `None` | email / `"Ism <e@x>"` | `None` → `DEFAULT_FROM_EMAIL` |
| `ACCOUNTS_RATE_LIMITER` | `None` | callable / dotted path `f(request, scope) -> bool` | `False` = 429 |
| `ACCOUNTS_RATE_LIMITS` | dict | `scope: "N/<s\|m\|h>"` | default limiter |
| `ACCOUNTS_CLIENT_IP_GETTER` | `None` | callable `f(request) -> str` | proxy ortida |
| `ACCOUNTS_IS_BLOCKED_CALLBACK` | `None` | callable `f(viewer, target) -> bool` | `get_public_profile` |
| `ACCOUNTS_AVATAR_MAX_BYTES` | 2 MiB | int > 0 | avatar |
| `ACCOUNTS_AVATAR_MAX_SIDE` | 6000 | int > 0 | avatar |
| `ACCOUNTS_AVATAR_MAX_PIXELS` | 24 000 000 | int > 0 | avatar |
| `ACCOUNTS_AVATAR_OUTPUT_SIZE` | 512 | int > 0 | avatar (kichraytiriladi) |

Rate scope'lar: `login, signup, password_reset, verify_email, resend_verification, email_change, reactivate`
(defaultlar: login `10/5m`, signup `10/h`, password_reset `5/h`...). Eski prefikssiz nomlar
(`REQUIRE_EMAIL_VERIFICATION`, `EMAIL_VERIFICATION_TIMEOUT`, `EMAIL_VERIFICATION_RESEND_COOLDOWN`,
`ACCOUNT_DELETION_GRACE_PERIOD`) deprecated alias: ishlaydi, `DeprecationWarning` beradi; ikkalasi berilsa kanonik yutadi.
Noto'g'ri qiymatlar `manage.py check` da `accounts.E0xx/W0xx` sifatida chiqadi. Django'ning o'z sozlamalari
(`EMAIL_*`, `DEFAULT_FROM_EMAIL`, `PASSWORD_RESET_TIMEOUT`, `AUTH_PASSWORD_VALIDATORS`, `SESSION_*`) qayta e'lon qilinmaydi.
Env namunasi: `accounts/env.example` (`EMAIL_HOST_PASSWORD` faqat env'dan).

## Email rejimlari
- **Verification yoqilgan:** signup login qilmaydi, xat yuboradi; tasdiqlanmagan login `verify/required/` ga yo'naltiriladi.
  Token: bir martalik, muddatli, faqat hash saqlanadi, yangisi eskisini bekor qiladi. Havola GET'da tokenni **sarflamaydi** — tugmali sahifa, sarflash faqat POST.
- **O'chiq (standart):** signup xat yubormaydi, foydalanuvchi darhol kiradi; eski tokenlar ishlaydi; profildagi «Emailni tasdiqlash» ixtiyoriy.
- **Har ikki rejimda** emailni o'zgartirish yangi manzilni tasdiqlashni talab qiladi; tasdiqlanguncha eski email amal qiladi.
- Rejim `False→True`: tasdiqlanmagan userlar keyingi loginda to'xtaydi, mavjud sessiyalar saqlanadi.
- Boshqa ilovalar uchun: `accounts.decorators.email_verified_required`. **Django admin login bu tekshiruvni chetlab o'tadi** (ma'lum cheklov); admin yaratgan userlar uchun admin `is_email_verified` ni belgilaydi, `createsuperuser` verified=True beradi.
- Xatlar ikki ko'rinishda (matn + HTML, `accounts/email/*.txt|html`) yuboriladi; havola muddati xatda ko'rsatiladi. Xat yuborilmasa: akkaunt saqlanadi, foydalanuvchiga «yuborib bo'lmadi, qayta yuboring» ko'rsatiladi (traceback yo'q, xato loglanadi); parol tiklashda baribir bir xil «yuborildi» sahifasi.
- Havola hosti: `ACCOUNTS_SITE_URL` berilsa — doim shu; yo'q bo'lsa tekshirilgan `request` hosti. Production'da `ACCOUNTS_SITE_URL` bering va `ALLOWED_HOSTS` da `"*"` ishlatmang.

## Rate limiting
Default limiter Django cache'ida (`cache.add` + `cache.incr`): kalit = scope+IP (login/reset'da qo'shimcha scope+IP+identifier-hash; faqat-identifier kalit yo'q, qurbonni bloklash DoS'i uchun). Cache xatosida **fail-open** + log.
`X-Forwarded-For` ni ilova parse qilmaydi: proxy ortida `ACCOUNTS_CLIENT_IP_GETTER` bering. **Ko'p worker bo'lsa Redis/Memcached/DB cache ishlating** (`LocMemCache` jarayonlar orasida ulashilmaydi).

Boshqa ilovangizdagi funksiya-view'ni ham xuddi shu limiter bilan cheklash mumkin (faqat POST sanaladi, 429 qaytadi):
```python
from accounts.decorators import rate_limit

@rate_limit("login", identifier=lambda r: r.POST.get("username"))   # scope: ACCOUNTS_RATE_LIMITS dagi kalit
def my_view(request): ...
```

## Lifecycle
`ACTIVE` → `DEACTIVATED` (o'zi; parol bilan qayta yoqadi) · `BLOCKED` (admin; o'zi yoqa olmaydi) · `DELETION_PENDING` (grace>0; login yo'q, identifikatorni band qilmaydi) → hard delete + PII'siz tombstone (`DeletedAccount`), `account_deleted(user_id)` signali.
Deactivate/delete-request `session_epoch` ni oshiradi: eski sessiyalar va reset tokenlari qayta yoqilgandan keyin ham tirilmaydi (epoch=0 bo'lgan mavjud userlar ommaviy logout bo'lmaydi).
Oxirgi faol superuser'ni o'chirib/faolsizlantirib/rolini tushirib bo'lmaydi (service, admin, `set_role`). **Privilegiyani faqat `accounts.services.update_privileges/set_role` orqali o'zgartiring** — `QuerySet.update()`/`bulk_update` himoyani chetlab o'tadi. Poyga himoyasi: foydalanuvchi qatori (deactivate, reactivate, delete, email o'zgartirish/tasdiqlash, privilegiya o'zgarishi) va barcha faol superuser qatorlari `select_for_update` bilan qulflanadi (PostgreSQL'da; SQLite'da no-op, PostgreSQL'da **tekshirilmagan**); email unikalligi DB constraint bilan ham himoyalangan (poyga bo'lsa o'zgartirish bekor qilinadi, 500 emas).

## Rollar
`user` / `teacher` / `superuser` (`is_superuser ⇒ role=superuser, is_staff=True`). Rol faqat Django admin (superuser) yoki
`python manage.py set_role <username|email> <user|teacher|superuser>` orqali o'zgaradi. Dekoratorlar: `role_required(*roles)`, `teacher_required`, `RoleRequiredMixin` (anonim → login, noto'g'ri rol → 403).

## Ochiq API
`get_user_model()` / `settings.AUTH_USER_MODEL` · `accounts.signals` (`user_signed_up`, `email_verified`, `account_deactivated`, `account_reactivated`, `account_deletion_requested`, `account_deleted(user_id)`; `send_robust`, receiver xatosi loglanadi) · `accounts.services.get_public_profile(viewer, target)` (kalitlar: `username, display_name, full_name, email, phone, bio, avatar_url, is_self`) · `accounts.decorators` (`role_required`, `teacher_required`, `RoleRequiredMixin`, `email_verified_required`, `EmailVerifiedRequiredMixin`, `rate_limit(scope, identifier=None)`).

```python
from django.dispatch import receiver
from accounts.signals import account_deleted

@receiver(account_deleted)
def cleanup(sender, user_id, **kwargs):
    Order.objects.filter(owner_id=user_id).delete()   # boshqa ilova ma'lumotlari
```

## Management commandlar
`set_role`, `purge_deleted_accounts` (cron'da; grace>0 bo'lsa), `check_identifier_collisions` (faqat o'qiydi: `@`li eski username'lar email bilan to'qnashuvi).

## Ma'lum cheklovlar
Signup username/email bandligini ko'rsatadi (ongli xavf; rate limit bilan kamaytiriladi); login/reset/resend javoblari bir xil. Django admin login email tasdiqlashni tekshirmaydi. MySQL/MariaDB qo'llab-quvvatlanmaydi. `LocMemCache` ko'p worker'da. Vizual (brauzer) tekshiruv o'tkazilmagan, faqat kod/HTML bo'yicha.

## Production tavsiyalari (settings'ga o'zingiz yozing)
`SESSION_COOKIE_SECURE=True`, `CSRF_COOKIE_SECURE=True`, `SECURE_SSL_REDIRECT=True`, HSTS (`SECURE_HSTS_SECONDS`), `SESSION_COOKIE_HTTPONLY=True`, `SESSION_COOKIE_SAMESITE="Lax"`, SMTP `EMAIL_BACKEND`, aniq `ALLOWED_HOSTS`, `DEFAULT_FROM_EMAIL`, shared cache. Audit: `LOGGING["loggers"]["accounts.audit"]` (faqat `event user_id`).

## Testlar
bash: `python manage.py test accounts`
PowerShell: `python -m venv .venv; .\.venv\Scripts\Activate.ps1; pip install django pillow; python manage.py test accounts`
(Testlar loyihangiz settings'ida ishlaydi: `AUTH_USER_MODEL`, `base.html`, `home` URL, `locmem` email, `AUTH_PASSWORD_VALIDATORS` (Django standart 4 ta validator) va `globals().update(ACCOUNTS_DEFAULTS)` (o'rnatish 2-qadamidagidek) kerak; aks holda parol/config testlari yiqiladi.)
