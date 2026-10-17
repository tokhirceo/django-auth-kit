from django.contrib.auth.tokens import PasswordResetTokenGenerator


class AccountsTokenGenerator(PasswordResetTokenGenerator):
    """Reset tokeni holatga bog'liq: faolsizlantirish/o'chirish/epoch uni bekor qiladi."""

    def _make_hash_value(self, user, timestamp):
        base = super()._make_hash_value(user, timestamp)
        return (
            f"{base}{user.is_active}{user.deactivated_at}"
            f"{user.deletion_requested_at}{user.session_epoch}"
        )


accounts_token_generator = AccountsTokenGenerator()
