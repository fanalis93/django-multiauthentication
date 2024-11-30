from django.http import JsonResponse


class APIKeyMiddleware:
    """
    Middleware to check for a valid Bearer token in the Authorization header.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        # Example token for validation (replace with dynamic validation logic)
        self.valid_token = "G8f3k2Z9q1R8s4T0v5Wj6Yl7mN0p"

    def __call__(self, request):
        # Retrieve the Authorization header
        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return JsonResponse(
                {"error": "Authorization header is missing"}, status=401
            )

        # Ensure the header starts with "Bearer"
        if not auth_header.startswith("Bearer "):
            return JsonResponse(
                {"error": "Invalid Authorization header format"}, status=401
            )

        # Extract the token (everything after "Bearer ")
        token = auth_header.split(" ", 1)[1]

        # Validate the token (static or dynamic check)
        if token != self.valid_token:
            return JsonResponse({"error": "Invalid or expired token"}, status=403)

        # Proceed with the request
        response = self.get_response(request)
        return response
