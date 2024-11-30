# from django.test import TestCase
# from django.urls import reverse
# from django.contrib.auth import get_user_model
# from django.utils.encoding import force_bytes
# from django.utils.http import urlsafe_base64_encode
# from rest_framework import status
# from rest_framework.test import APIClient

# UserModel = get_user_model()


# class AuthViewTestCase(TestCase):
#     def setUp(self):
#         self.client = APIClient()
#         self.student_data = {
#             "username": "student1",
#             "email": "student1@example.com",
#             "password": "testpass123",
#             "role": "student",
#         }
#         self.client_data = {
#             "username": "client1",
#             "email": "client1@example.com",
#             "password": "testpass123",
#             "role": "client",
#         }

#     def test_get_all_users(self):
#         UserModel.objects.create_user(**self.student_data)
#         UserModel.objects.create_user(**self.client_data)

#         response = self.client.get("/api/v1/auth/users")

#         self.assertEqual(response.status_code, status.HTTP_200_OK)
#         self.assertEqual(len(response.data), 2)

#     # def test_get_single_user(self):
