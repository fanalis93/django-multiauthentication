from asgiref import local
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.core.mail import EmailMultiAlternatives

from core import settings


class ActivationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return f"{user.pk}{timestamp}{user.is_active}"


account_activation_token = ActivationTokenGenerator()


def send_verification_email(user, request):
    token = account_activation_token.make_token(user)
    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    frontend_url = settings.FRONTEND_URL + "/api/v1/auth"

    verification_url = f"{frontend_url}/verify-email/{uidb64}/{token}/"

    subject = "Activate your account"
    message = f"""
    Hi {user.username},
    
    Please click on the link below to verify your email address:
    {verification_url}
    
    If you did not create an account, please ignore this email.
    """

    email = EmailMultiAlternatives(
        subject=subject,
        body=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[user.email],
    )
    email.send()


def send_password_reset_email(user, request):
    token = account_activation_token.make_token(user)

    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
    frontend_url = settings.FRONTEND_URL + "/api/v1/auth"

    reset_url = f"{frontend_url}/reset-password/{uidb64}/{token}"

    subject = "Reset your password"
    message = f"""
    Hi {user.username},
    
    Please click on the link below to reset your password:
    {reset_url}
    
    If you did not request a password reset, please ignore this email.
    """

    email = EmailMultiAlternatives(
        subject=subject,
        body=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[user.email],
    )
    email.send()
    user.password_reset_token = token
    user.save()
