from django.urls import path, re_path
from authentication.views import auth_views
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)

# from . import views

urlpatterns = [
    path("users/", auth_views.AuthView.as_view()),
    path("users/<int:pk>", auth_views.AuthView.as_view()),
    path(
        "verify-email/<str:uidb64>/<str:token>/",
        auth_views.EmailVerificationView.as_view(),
    ),
    path("reset-password/", auth_views.PasswordResetView.as_view()),
    path(
        "reset-password/<str:uidb64>/<str:token>/",
        auth_views.PasswordResetView.as_view(),
    ),
    path("login/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("login/refresh-token/", TokenRefreshView.as_view(), name="token_refresh"),
    path("profile/", auth_views.ProfileView.as_view()),
    path("update-password/", auth_views.UpdatePasswordView.as_view()),
]
