from math import e
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from authentication.models import Client, Student, User
from authentication.utils import send_verification_email


@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        if instance.role == "client":
            Client.objects.create(
                user=instance,
            )
        elif instance.role == "student":
            Student.objects.create(
                user=instance,
            )

        send_verification_email(instance, None)


# @receiver(post_delete, sender=Client)
# def delete_user_with_client(sender, instance, **kwargs):
#     # Delete the associated user if it exists
#     if instance.user:
#         instance.user.delete()


# @receiver(post_delete, sender=Student)
# def delete_user_with_student(sender, instance, **kwargs):
#     # Delete the associated user if it exists
#     if instance.user:
#         instance.user.delete()
