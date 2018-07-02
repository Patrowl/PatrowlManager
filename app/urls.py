from django.conf import settings
from django.conf.urls import include, url
from django.contrib import admin

from django.contrib.auth import views as auth_views
from users.forms import LoginForm
from users import views as user_views

def i18n_javascript(request):
  return admin.site.i18n_javascript(request)

urlpatterns = [
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

    #url(r'^login/$', auth_views.login, kwargs={'template_name': 'login.html'}, name='login'),
    url(r'^login$', auth_views.login, {
        'template_name': 'login.html',
        'authentication_form': LoginForm}, name='login'),
    url(r'^logout$', auth_views.logout, {'next_page': '/login'}, name='logout'),
    url(r'^signup$', user_views.signup, name='signup'),

    url(r'^admin/jsi18n/', i18n_javascript),

    #url(r'^api-auth/', include('rest_framework.urls')),
    # url(r'^api-auth/', include('rest_framework.urls')),
]

# debug toolbar & download file
if settings.DEBUG:
    import debug_toolbar
    urlpatterns = [
        url(r'^__debug__/', include(debug_toolbar.urls)),
    ] + urlpatterns

    from django.conf.urls.static import static
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
