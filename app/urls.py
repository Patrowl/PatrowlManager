# -*- coding: utf-8 -*-

from django.conf import settings
from django.conf.urls import include, url
from django.conf.urls import handler400, handler403, handler404, handler500
from django.urls import path
from django.contrib import admin
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.contrib.auth.views import LogoutView
from django.views.generic import RedirectView
from rest_framework_swagger.views import get_swagger_view
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from users import views as user_views


def i18n_javascript(request):
    return admin.site.i18n_javascript(request)


handler400 = 'app.views.custom_bad_request'
handler403 = 'app.views.custom_permission_denied'
handler404 = 'app.views.custom_page_not_found'
handler500 = 'app.views.custom_error'


api_schema_view = get_swagger_view(title='PatrowlManager REST-API')

urlpatterns = [
    url(r'^apis-doc', api_schema_view),
    url(r'^ht/', include('health_check.urls')),
    url(r'^auth-jwt/obtain_jwt_token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    url(r'^auth-jwt/refresh_jwt_token/', TokenRefreshView.as_view(), name='token_refresh'),
    url(r'^auth-jwt/verify/', TokenVerifyView.as_view(), name='token_verify'),
    url(r'^admin/', admin.site.urls),
    url(r'^engines/', include('engines.urls')),
    url(r'^findings/', include('findings.urls')),
    url(r'^assets/', include('assets.urls')),
    url(r'^users/', include('users.urls')),
    url(r'^scans/', include('scans.urls')),
    url(r'^events/', include('events.urls')),
    url(r'^rules/', include('rules.urls')),
    url(r'^reportings/', include('reportings.urls')),
    url(r'^settings/', include('settings.urls')),
    url(r'^search', include('search.urls')),
    url(r'^', include('users.urls'), name='home'),

    url(r'^login$', user_views.login, name='login'),
    url(r'^logout$', LogoutView.as_view(), {'next_page': settings.LOGOUT_REDIRECT_URL}, name='logout'),
    # url(r'^signup$', user_views.signup, name='signup'),

    url(r'^favicon\.ico$', RedirectView.as_view(url='/static/favicon.ico')),
]

# Debug toolbar & download file
# if settings.DEBUG:
#     import debug_toolbar
#     urlpatterns = [
#         path('__debug__/', include(debug_toolbar.urls)),
#     ] + urlpatterns
# if settings.DEBUG:
import debug_toolbar
urlpatterns = [
    path('__debug__/', include(debug_toolbar.urls)),
] + urlpatterns

# urlpatterns += staticfiles_urlpatterns()

# Add PRO edition urls
if settings.PRO_EDITION:
    # print("urls-PRO_EDITION", settings.PRO_EDITION)
    try:
        from pro.urls import pro_urlpatterns
        urlpatterns += pro_urlpatterns
    except ImportError as e:
        print(e)

urlpatterns += staticfiles_urlpatterns()
