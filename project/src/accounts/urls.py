from django.urls import path

from . import views

app_name = "accounts"

urlpatterns = [
    path("signup/", views.SignupView.as_view(), name="signup"),
    path("login/", views.LoginView.as_view(), name="login"),
    path("logout/", views.LogoutView.as_view(), name="logout"),
    path("verify/required/", views.VerificationRequiredView.as_view(), name="verification_required"),
    path("verify/resend/", views.ResendVerificationView.as_view(), name="resend_verification"),
    path("verify/<str:token>/", views.VerifyEmailView.as_view(), name="verify_email"),
    path("password/change/", views.PasswordChangeView.as_view(), name="password_change"),
    path("password/change/done/", views.PasswordChangeDoneView.as_view(), name="password_change_done"),
    path("password/reset/", views.PasswordResetView.as_view(), name="password_reset"),
    path("password/reset/done/", views.PasswordResetDoneView.as_view(), name="password_reset_done"),
    path(
        "password/reset/<uidb64>/<token>/",
        views.PasswordResetConfirmView.as_view(),
        name="password_reset_confirm",
    ),
    path("password/reset/complete/", views.PasswordResetCompleteView.as_view(), name="password_reset_complete"),
    path("profile/", views.ProfileView.as_view(), name="profile"),
    path("profile/edit/", views.ProfileEditView.as_view(), name="profile_edit"),
    path("settings/", views.SettingsView.as_view(), name="settings"),
    path("profile/privacy/", views.PrivacySettingsView.as_view(), name="privacy"),
    path("profile/email/", views.EmailChangeView.as_view(), name="email_change"),
    path("profile/deactivate/", views.DeactivateView.as_view(), name="deactivate"),
    path("profile/delete/", views.DeleteAccountView.as_view(), name="delete"),
    path("deleted/", views.DeletedView.as_view(), name="deleted"),
    path("reactivate/", views.ReactivateView.as_view(), name="reactivate"),
    path("u/<str:username>/", views.PublicProfileView.as_view(), name="public_profile"),
]
