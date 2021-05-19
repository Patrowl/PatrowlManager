from django.shortcuts import render


# HTTP Error 400
def custom_bad_request(request, exception=None):
    response = render(request, 'errors/400.html', {})
    response.status_code = 400

    return response


# HTTP Error 403
def custom_permission_denied(request, exception=None):
    response = render(request, 'errors/403.html', {})
    response.status_code = 403

    return response


# HTTP Error 404
def custom_page_not_found(request, exception):
    response = render(request, 'errors/404.html', {})
    response.status_code = 404

    return response


# HTTP Error 500
def custom_error(request, exception=None):
    response = render(request, 'errors/500.html', {})
    response.status_code = 500

    return response
