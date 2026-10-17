"""Boshqa ilovalar uchun ochiq signallar va ichki receiver'lar."""
import logging

from django.db.models.signals import post_save
from django.dispatch import Signal, receiver

logger = logging.getLogger("accounts")
audit_logger = logging.getLogger("accounts.audit")

user_signed_up = Signal()            # user
email_verified = Signal()            # user
account_deactivated = Signal()       # user
account_reactivated = Signal()       # user
account_deletion_requested = Signal()  # user
account_deleted = Signal()           # user_id


def emit(signal, **kwargs):
    """``send_robust``: receiver istisnosi so'rovni buzmaydi, log'lanadi."""
    for receiver_fn, result in signal.send_robust(sender=None, **kwargs):
        if isinstance(result, Exception):
            logger.error(
                "signal receiver xatosi: %s (%s)",
                getattr(receiver_fn, "__qualname__", receiver_fn),
                result.__class__.__name__,
                exc_info=result,
            )


def audit(event, user_id):
    """Audit log: faqat voqea va user_id (email/parol/token yo'q)."""
    audit_logger.info("%s user_id=%s", event, user_id)


@receiver(post_save, sender="accounts.User", dispatch_uid="accounts_create_privacy")
def create_privacy_settings(sender, instance, created, raw=False, **kwargs):
    if raw or not created:
        return
    from .models import PrivacySettings

    PrivacySettings.objects.get_or_create(user=instance)
