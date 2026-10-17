from django.conf import settings
from django.core import checks

from .config.settings import validate


@checks.register()
def check_accounts_settings(app_configs, **kwargs):
    messages = []
    for level, check_id, text in validate(settings):
        cls = checks.Error if level == "E" else checks.Warning
        messages.append(cls(text, id=check_id))
    return messages
