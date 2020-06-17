def get_api_default_permissions(self):
    from rest_framework.decorators import permission_classes
    from rest_framework.permissions import IsAdminUser, IsAuthenticated
    if self.action == 'list':
        permission_classes = [IsAuthenticated]
    else:
        permission_classes = [IsAdminUser]
    return [permission() for permission in permission_classes]
