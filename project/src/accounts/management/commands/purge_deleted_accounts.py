from django.core.management.base import BaseCommand

from accounts import services


class Command(BaseCommand):
    help = "Imtiyozli muddati tugagan hisoblarni butunlay o'chiradi."

    def handle(self, *args, **options):
        count = services.purge_deleted_accounts()
        self.stdout.write(self.style.SUCCESS(f"O'chirildi: {count}"))
