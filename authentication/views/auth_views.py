from ast import Is
from functools import partial
from profile import Profile
from django.core.serializers import serialize
from django.utils import timezone
import re
from webbrowser import get
from django.http import JsonResponse
from rest_framework import status
from rest_framework.decorators import permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

from authentication.models import Client, Student, User
from authentication.serializers import (
    ClientProfileSerializer,
    PasswordResetConfirmationSerializer,
    PasswordResetSerializer,
    ProfileSerializer,
    StudentProfileSerializer,
    StudentSerializer,
    ClientSerializer,
    UpdatePasswordSerializer,
    UserSerializer,
)

User = get_user_model()


class AuthView(APIView):
    permission_classes = [
        AllowAny,
    ]

    def get_serializer(self, role):
        serializers = {
            "student": StudentSerializer,
            "client": ClientSerializer,
            None: UserSerializer,
        }
        return serializers.get(role, UserSerializer)

    """
    Get all users or a specific user
    """

    def get(self, request, pk=None):

        try:
            if pk is None:
                users = User.objects.all()
                serializer = UserSerializer(users, many=True)
                return Response(serializer.data)

            user = User.objects.get(pk=pk)
            # print(user)
            serializer = UserSerializer(user)
            return Response(serializer.data)

        except User.DoesNotExist:
            return Response(
                {"message": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    """
    Register a new user
    """

    def post(self, request):
        try:
            role = request.data.get("role")
            SerializerClass = UserSerializer

            serializer = SerializerClass(data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

    """
    Update a user's details
    """

    def put(self, request, pk):
        try:
            get_user = User.objects.get(pk=pk)
            role = request.data.get("role", get_user.role)

            serializer_class = UserSerializer
            serializer = serializer_class(get_user, data=request.data, partial=True)
            serializer.is_valid(raise_exception=True)
            serializer.save()

            return Response(serializer.data, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response(
                {"message": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    """
    Delete a user and their related profile
    """

    def delete(self, request, pk):
        try:
            user = User.objects.get(pk=pk)
            user.delete()
            return Response(
                {"message": "User deleted."}, status=status.HTTP_204_NO_CONTENT
            )

        except User.DoesNotExist:
            return Response(
                {"message": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            return Response(
                {"message": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class EmailVerificationView(APIView):
    """
    POST request to verify account using the token sent to the user's email
    """

    authentication_classes = []  # Disable authentication for this view
    permission_classes = []  # Disable permission checks

    def post(self, request, uidb64, token):
        from authentication.utils import account_activation_token

        User = get_user_model()  # Import user model dynamically

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)

            if account_activation_token.check_token(user, token):
                user.is_active = True
                user.email_verified_at = timezone.now()
                user.save()

                return Response(
                    {"message": "Email verified successfully"},
                    status=status.HTTP_200_OK,
                )

            return Response(
                {"error": "Invalid verification link"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"error": "Invalid verification link"},
                status=status.HTTP_400_BAD_REQUEST,
            )


class PasswordResetView(APIView):
    authentication_classes = []
    permission_classes = [
        AllowAny,
    ]

    """
    Send Password Reset Email
    """

    def post(self, request):
        email = request.data.get("email")

        if not email:
            return Response(
                {"error": "Email is required"}, status=status.HTTP_400_BAD_REQUEST
            )

        User = get_user_model()

        try:
            user = User.objects.get(email=email)
            serializer = PasswordResetSerializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response(
                {
                    "message": "Password reset link sent to your email",
                    "data": serializer.data,
                },
                status=status.HTTP_200_OK,
            )

        except User.DoesNotExist:
            return Response(
                {"error": "User not found"}, status=status.HTTP_404_NOT_FOUND
            )

        except Exception as e:
            return Response(
                {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    """
    Update Password
    """

    def patch(self, request, uidb64, token):
        uid = urlsafe_base64_decode(uidb64)
        user = User.objects.get(pk=uid)

        serializer = PasswordResetConfirmationSerializer(
            data=request.data, context={"uidb64": uidb64, "token": token}, partial=True
        )

        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        serializer.save()
        return Response(
            {"message": "Password reset successful"}, status=status.HTTP_200_OK
        )


# class LogoutView(APIView):


class ProfileView(APIView):
    permission_classes = [
        IsAuthenticated,
    ]

    def get_model(self, user):
        """
        Retrieve the related model instance based on the user's role.
        If no specific role is found, return the user object itself.
        """
        if not user or not hasattr(user, "role"):
            return (
                user,
                ProfileSerializer,
            )  # Return the user itself if it is None or does not have a role

        try:
            if user.role == "student":
                return Student.objects.get(user=user), StudentProfileSerializer
            elif user.role == "client":
                return Client.objects.get(user=user), ClientProfileSerializer
        except AttributeError:
            # Handle cases where the related profile does not exist
            return user, ProfileSerializer

        return user, ProfileSerializer

    def get(self, request):
        user, serializer_class = self.get_model(request.user)

        serializer = serializer_class(user, context={"request": request})
        return Response(serializer.data)

    def put(self, request):
        user = self.get_model(request.user)

        serializer_class = self.get_serializer(user)

        serializer = serializer_class(user, data=request.data, partial=True)

        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(
                {"message": "Profile updated successfully", "data": serializer.data},
                status=status.HTTP_200_OK,
            )
        else:
            raise Exception(serializer.errors)


class UpdatePasswordView(APIView):
    permission_classes = [
        IsAuthenticated,
    ]

    serializer_class = UpdatePasswordSerializer

    def put(self, request):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}, partial=True
        )
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response(
                {"message": "Password updated successfully"},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
