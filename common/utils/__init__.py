from django.contrib.auth.decorators import user_passes_test


def pro_permission_required(*args):
    """
    Check user has any of the given permissions.

    Permission required can not be used in its place as that takes only a
    single permission.
    """
    def test_func(user):
        from django.conf import settings
        if not settings.PRO_EDITION or user.is_superuser:
            return True
        for perm in args:
            if user.has_perm(perm):
                return True
        return False
    return user_passes_test(test_func)


def pro_group_required(*group_names):
    """Require user membership in at least one of the groups passed in."""
    def in_groups(u):
        from django.conf import settings
        if not settings.PRO_EDITION or u.is_superuser:
            return True
        if u.is_authenticated:
            if bool(u.groups.filter(name__in=group_names)):
                return True
        return False
    return user_passes_test(in_groups)


def get_api_default_permissions(self):
    from rest_framework.decorators import permission_classes
    from rest_framework.permissions import IsAdminUser, IsAuthenticated
    if self.action == 'list':
        permission_classes = [IsAuthenticated]
    else:
        permission_classes = [IsAdminUser]
    return [permission() for permission in permission_classes]


def chunked_queryset(queryset, chunk_size):
    """ Slice a queryset into chunks. """

    start_pk = 0
    queryset = queryset.order_by('pk')

    while True:
        # No entry left
        if not queryset.filter(pk__gt=start_pk).exists():
            break

        try:
            # Fetch chunk_size entries if possible
            end_pk = queryset.filter(pk__gt=start_pk).values_list(
                'pk', flat=True)[chunk_size - 1]

            # Fetch rest entries if less than chunk_size left
        except IndexError:
            end_pk = queryset.values_list('pk', flat=True).last()

        yield queryset.filter(pk__gt=start_pk).filter(pk__lte=end_pk)

        start_pk = end_pk
