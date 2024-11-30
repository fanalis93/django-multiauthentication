from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.http import HttpRequest
from .models import Client, Student, User


class CustomUserAdmin(UserAdmin):
    model = User
    list_display = [
        "id",
        "username",
        "email",
        "first_name",
        "last_name",
        "role",
        "is_active",
        "is_staff",
    ]
    readonly_fields = ["created_at", "updated_at"]
    list_filter = ["role", "is_active", "is_staff"]
    filter_horizontal = []
    fieldsets = (
        (None, {"fields": ("username", "password")}),
        (
            "Personal Info",
            {"fields": ("first_name", "last_name", "email", "profile_photo")},
        ),
        ("Permissions", {"fields": ("role", "is_active", "is_staff", "is_superuser")}),
        (
            "Important dates",
            {"fields": ("created_at", "updated_at", "email_verified_at")},
        ),
    )
    add_fieldsets = (
        (
            None,
            {
                "classes": ("wide",),
                "fields": (
                    "username",
                    "email",
                    "password1",
                    "password2",
                    "role",
                    "is_staff",
                ),
            },
        ),
    )


class ClientAdmin(admin.ModelAdmin):

    def delete_model(self, request, obj):
        # Delete the associated user first
        if obj.user:
            obj.user.delete()
        # Then delete the student
        obj.delete()

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            if obj.user:
                obj.user.delete()
        queryset.delete()


class StudentAdmin(admin.ModelAdmin):
    def delete_model(self, request, obj):
        # Delete the associated user first
        if obj.user:
            obj.user.delete()
        # Then delete the student
        obj.delete()

    def delete_queryset(self, request, queryset):
        for obj in queryset:
            if obj.user:
                obj.user.delete()
        queryset.delete()


# Register models with their respective admin classes
admin.site.register(User)
admin.site.register(Client, ClientAdmin)
admin.site.register(Student, StudentAdmin)
