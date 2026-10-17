from django.contrib.auth.models import UserManager as DjangoUserManager
from django.db.models import Q


class UserManager(DjangoUserManager):
    use_in_migrations = True

    def live(self):
        """O'chirish kutilayotganlarsiz (identifikatorni band qiladiganlar)."""
        return self.filter(deletion_requested_at__isnull=True)

    def find_by_identifier(self, identifier):
        """Username yoki email bo'yicha topadi.

        Deterministik qoida: ``@`` bor identifikator avval email sifatida
        qidiriladi, topilmasa (eski ``@``li username) username sifatida.
        """
        identifier = (identifier or "").strip()
        if not identifier:
            return None
        qs = self.live().order_by("pk")
        if "@" in identifier:
            user = qs.filter(email__iexact=identifier).first()
            if user is not None:
                return user
        return qs.filter(username__iexact=identifier).first()

    def identifier_taken(self, *, username=None, email=None, exclude_pk=None):
        cond = Q()
        if username:
            cond |= Q(username__iexact=username)
        if email:
            cond |= Q(email__iexact=email)
        if not cond:
            return False
        qs = self.live().filter(cond)
        if exclude_pk is not None:
            qs = qs.exclude(pk=exclude_pk)
        return qs.exists()

    def create_superuser(self, username, email=None, password=None, **extra_fields):
        extra_fields.setdefault("is_email_verified", True)
        return super().create_superuser(username, email, password, **extra_fields)
