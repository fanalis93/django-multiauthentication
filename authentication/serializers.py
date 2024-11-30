from email.policy import default
from http import client
from os import error, read
from typing import Self
from webbrowser import get
from debug_toolbar.panels.signals import post_save
from django.dispatch import receiver
from django.utils.http import urlsafe_base64_decode
from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password

from authentication.utils import send_password_reset_email
from .models import Client, Student
from django.contrib.auth.forms import PasswordResetForm
from authentication.utils import account_activation_token

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        required=True,
        # validators=[validate_password]
    )
    password2 = serializers.CharField(
        write_only=True,
        required=True,
    )

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "password",
            "password2",
            "email",
            "first_name",
            "last_name",
            "role",
        )
        extra_kwargs = {
            "first_name": {"required": False},
            "last_name": {"required": False},
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance is not None:
            self.fields["password"].required = False
            self.fields["password2"].required = False

    def validate(self, attrs):
        if "password" in attrs and "password2" in attrs:
            if attrs["password"] != attrs["password2"]:
                raise serializers.ValidationError("Password fields didn't match.")

        return attrs

    def create(self, validated_data):
        del validated_data["password2"]
        user = User.objects.create(**validated_data)
        user.set_password(validated_data["password"])

        user.save(update_fields=["password"])

        return user

    def update(self, instance, validated_data):
        # Handle password update if provided
        if "password" in validated_data:
            password = validated_data.pop("password")
            instance.set_password(password)

        # Remove password2 if it exists
        if "password2" in validated_data:
            validated_data.pop("password2")

        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance


class ClientSerializer(UserSerializer):
    class Meta(UserSerializer.Meta):
        model = Client
        fields = UserSerializer.Meta.fields

    def update(self, instance, validated_data):
        # Handle password update if provided
        if "password" in validated_data:
            password = validated_data.pop("password")
            instance.set_password(password)

        # Remove password2 if it exists
        if "password2" in validated_data:
            validated_data.pop("password2")

        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        instance.user.update_user_fields(**validated_data)

        return instance


class StudentSerializer(UserSerializer):

    class Meta(UserSerializer.Meta):
        model = Student
        user_id = serializers.IntegerField(source="user.id", read_only=True)
        fields = UserSerializer.Meta.fields + ("client", "user_id")

    def create(self, validated_data):
        # Extract client from validated_data
        del validated_data["password2"]
        client = validated_data.pop("client", None)
        validate_password(validated_data["password"])

        # Create the User instance
        user = User.objects.create(**validated_data)
        user.set_password(validated_data["password"])
        user.save(update_fields=["password"])

        client = Client.objects.get(pk=client.id) if client else None

        # Create the Student instance
        data = {
            "user": user,
            "client": client,
            "username": user.username,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email,
            "role": user.role,
        }

        student = Student.objects.create(**data)
        return student

    def update(self, instance, validated_data):

        # Handle password update if provided
        if "password" in validated_data:
            password = validated_data.pop("password")
            print(2)
            instance.set_password(password)
            print(3)

        # Remove password2 if it exists
        if "password2" in validated_data:
            validated_data.pop("password2")
        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        instance.user.update_user_fields(**validated_data)

        return instance


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        user = User.objects.filter(email=value)
        if not user.exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value

    def save(self):
        email = self.validated_data["email"]
        user = User.objects.get(email=email)
        send_password_reset_email(user, None)
        return user


class PasswordResetConfirmationSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        if attrs["password"] != attrs["password2"]:
            raise serializers.ValidationError({"error": "Passwords did not match."})

        # validate user and token

        uidb64 = urlsafe_base64_decode(self.context["uidb64"])
        token = self.context["token"]
        try:
            user = User.objects.get(pk=uidb64)
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid user.")

        if not account_activation_token.check_token(user, token):
            raise serializers.ValidationError("Invalid token.")

        attrs["user"] = user
        return attrs

    def save(self):
        user = self.validated_data["user"]
        password = self.validated_data["password"]
        user.set_password(password)
        user.save()

        user.password_reset_token = None
        user.save()

        return user


class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "email",
            "first_name",
            "last_name",
            "role",
        )

    # def get(self, request):
    #     if request.role == "student":
    #         student = Student.objects.get(user=request)
    #         return StudentSerializer(student).data
    #     elif request.role == "client":
    #         client = Client.objects.get(user=request)
    #         return ClientSerializer(client).data


class ClientProfileSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = Client
        fields = (
            "id",
            "user",
            "phone",
            "address",
            "website",
            "logo",
            "average_progress",
            "password",
        )

    def validate(self, attrs):
        # Handle password if it's present
        if "password" in attrs:
            password = attrs.pop("password")  # Remove password from attrs
            if password:
                self.context["password"] = (
                    password  # Store in context for update method
                )
        return attrs

    def update(self, instance, validated_data):
        # Handle password if it was provided
        if "password" in self.context:
            instance.user.set_password(self.context["password"])
            instance.user.save()

        # Handle other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        instance.user.update_user_fields(**validated_data)

        return instance


class StudentProfileSerializer(serializers.ModelSerializer):
    user = UserSerializer(read_only=True)
    client = serializers.SerializerMethodField(read_only=True)
    courses = serializers.PrimaryKeyRelatedField(many=True, read_only=True)

    class Meta:
        model = Student
        fields = [
            "id",
            "dob",
            "phone",
            "address",
            "profile_photo",
            "average_progress",
            "courses",
            "user",
            "client",
        ]

    def get_client(self, obj):

        if "client" in self.context.get("request", {}).query_params:
            return ClientProfileSerializer(obj.client).data
        return obj.client.id if obj.client else None

    def validate(self, attrs):
        return attrs

    def update(self, instance, validated_data):
        # Handle other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        instance.user.update_user_fields(**validated_data)

        return instance


class UpdatePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    new_password2 = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        user = self.context["request"].user
        if not user.check_password(attrs["old_password"]):
            raise serializers.ValidationError("Old password is incorrect.")

        if attrs["new_password"] != attrs["new_password2"]:
            raise serializers.ValidationError("Passwords did not match.")

        return attrs

    def save(self):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        user.save()
        return user
