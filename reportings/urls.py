from django.conf.urls import url
from . import views
from . import api


urlpatterns = [
    # VIEWS
    # ex: /reportings/patch_management
    url(r'^patch_management$', views.patch_management_view, name='patch_management_view'),
    # ex: /reportings/dashboard
    url(r'^dashboard$', views.homepage_dashboard_view, name='homepage_dashboard_view'),

    ## API
    url(r'^api/v1/global_stats$', api.global_stats_api, name='global_stats_api'),
]
