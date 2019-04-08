from django.conf import settings


def selected_settings(request):
    # return the version value as a dictionary
    # you may add other values here as well
    return {'PATROWL_VERSION': settings.PATROWL_VERSION}
