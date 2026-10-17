from django.core.management.base import BaseCommand
from django.db.models import Q

from accounts.models import User


class Command(BaseCommand):
    help = "Faqat o'qiydi: username boshqa foydalanuvchining emaili bilan to'qnashadigan holatlarni ro'yxatlaydi."

    def handle(self, *args, **options):
        found = 0
        for user in User.objects.live().filter(username__contains="@").order_by("pk"):
            other = (
                User.objects.live().filter(email__iexact=user.username).exclude(pk=user.pk).values_list("pk", flat=True)
            )
            for other_pk in other:
                found += 1
                self.stdout.write(f"to'qnashuv: user_id={user.pk} username == user_id={other_pk} email")
        self.stdout.write(self.style.WARNING(f"To'qnashuvlar: {found}") if found else "To'qnashuv yo'q.")
