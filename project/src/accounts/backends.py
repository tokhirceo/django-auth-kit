from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend


class AccountsBackend(ModelBackend):
    """Username yoki email bilan kirish; O'chirish kutilayotganlar kira olmaydi."""

    def authenticate(self, request, username=None, password=None, **kwargs):
        user_model = get_user_model()
        if username is None:
            username = kwargs.get(user_model.USERNAME_FIELD)
        if not username or password is None:
            return None
        user = user_model._default_manager.find_by_identifier(username)
        if user is None:
            # vaqt farqi orqali mavjudlik sezilmasligi uchun
            user_model().set_password(password)
            return None
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None

    def get_user(self, user_id):
        user_model = get_user_model()
        user = user_model._default_manager.filter(pk=user_id, deletion_requested_at__isnull=True).first()
        if user is not None and self.user_can_authenticate(user):
            return user
        return None
