from django.conf import settings


def selected_settings(request):
    r = {
        'PATROWL_VERSION': settings.PATROWL_VERSION,
        'PATROWL_REFRESH_ENGINE': settings.PATROWL_REFRESH_ENGINE,
        'PRO_EDITION': settings.PRO_EDITION,
        'LOGOUT_URL': settings.LOGOUT_URL
    }

    if hasattr(settings, 'LOGIN_SSO_URL'):
        r.update({'LOGIN_SSO_URL': settings.LOGIN_SSO_URL})

    return r
