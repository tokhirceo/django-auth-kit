import io
import re

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from PIL import Image

from .helpers import AccountsTestCase, make_user

BASE = {"first_name": "", "last_name": "", "phone": "", "bio": ""}


def image_bytes(fmt="PNG", size=(40, 30), exif=False):
    buf = io.BytesIO()
    img = Image.new("RGB", size, (200, 10, 10))
    kw = {}
    if exif:
        e = Image.Exif()
        e[0x010F] = "SecretCameraMake"
        kw["exif"] = e
    img.save(buf, format=fmt, **kw)
    return buf.getvalue()


class AvatarTests(AccountsTestCase):
    def setUp(self):
        super().setUp()
        self.user = make_user("alice")
        self.client.force_login(self.user)
        self.url = reverse("accounts:profile_edit")

    def upload(self, name, content, ctype="image/png"):
        return self.client.post(self.url, {**BASE, "avatar": SimpleUploadedFile(name, content, content_type=ctype)})

    def rejected(self, response):
        self.user.refresh_from_db()
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.user.avatar)

    def test_valid_png_saved_with_generated_path(self):
        r = self.upload("../../evil name.png", image_bytes())
        self.assertEqual(r.status_code, 302)
        self.user.refresh_from_db()
        self.assertRegex(self.user.avatar.name, rf"^avatars/{self.user.pk}/[0-9a-f]{{32}}\.png$")
        self.assertNotIn("evil", self.user.avatar.name)

    def test_S11_fake_extension_and_html_rejected(self):
        self.rejected(self.upload("a.png", b"<html><script>alert(1)</script></html>"))
        self.rejected(self.upload("a.html", image_bytes(), "text/html"))
        self.rejected(self.upload("a.svg", b"<svg xmlns='http://www.w3.org/2000/svg'/>", "image/svg+xml"))
        self.rejected(self.upload("a.gif", image_bytes("GIF"), "image/gif"))

    @override_settings(ACCOUNTS_AVATAR_MAX_BYTES=500)
    def test_S11_too_big_bytes(self):
        self.rejected(self.upload("a.png", image_bytes(size=(400, 400))))

    @override_settings(ACCOUNTS_AVATAR_MAX_SIDE=50)
    def test_S11_too_large_side(self):
        self.rejected(self.upload("a.png", image_bytes(size=(60, 10))))

    @override_settings(ACCOUNTS_AVATAR_MAX_PIXELS=100)
    def test_S11_too_many_pixels_decompression_bomb_guard(self):
        self.rejected(self.upload("a.png", image_bytes(size=(20, 20))))

    def test_S11_exif_stripped_and_resized(self):
        with override_settings(ACCOUNTS_AVATAR_OUTPUT_SIZE=32):
            self.upload("a.jpg", image_bytes("JPEG", size=(300, 200), exif=True), "image/jpeg")
        self.user.refresh_from_db()
        data = self.user.avatar.read()
        self.assertNotIn(b"SecretCameraMake", data)
        with Image.open(io.BytesIO(data)) as img:
            self.assertLessEqual(max(img.size), 32)
            self.assertEqual(len(img.getexif()), 0)

    def test_replace_and_remove_delete_old_file(self):
        self.upload("a.png", image_bytes())
        self.user.refresh_from_db()
        first, storage = self.user.avatar.name, self.user.avatar.storage
        with self.captureOnCommitCallbacks(execute=True):
            self.upload("b.png", image_bytes(size=(10, 10)))
        self.user.refresh_from_db()
        self.assertNotEqual(self.user.avatar.name, first)
        self.assertFalse(storage.exists(first))
        with self.captureOnCommitCallbacks(execute=True):
            self.client.post(self.url, {**BASE, "remove_avatar": "on"})
        self.user.refresh_from_db()
        self.assertFalse(self.user.avatar)

    def test_existing_avatar_kept_when_no_new_upload(self):
        self.upload("a.png", image_bytes())
        self.user.refresh_from_db()
        name = self.user.avatar.name
        self.client.post(self.url, {**BASE, "first_name": "Ali"})
        self.user.refresh_from_db()
        self.assertEqual((self.user.avatar.name, self.user.first_name), (name, "Ali"))
