from django.core.management.base import BaseCommand, CommandError

from accounts import services
from accounts.models import User


class Command(BaseCommand):
    help = "Foydalanuvchi rolini o'zgartiradi: set_role <username|email> <user|teacher|superuser>"

    def add_arguments(self, parser):
        parser.add_argument("identifier")
        parser.add_argument("role", choices=User.Role.values)

    def handle(self, *args, identifier, role, **options):
        user = User.objects.find_by_identifier(identifier)
        if user is None:
            raise CommandError("Foydalanuvchi topilmadi.")
        try:
            services.set_role(user, role)
        except services.LastSuperuserError as exc:
            raise CommandError(str(exc)) from None
        except services.LifecycleError as exc:
            raise CommandError(str(exc)) from None
        self.stdout.write(self.style.SUCCESS(f"{user.username}: rol = {role}"))
