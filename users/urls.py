# -*- coding: utf-8 -*-

from django.conf.urls import url
from . import views, apis
from reportings import views as rep_views


urlpatterns = [

    # Views
    url(r'^$', rep_views.homepage_dashboard_view,
        name='homepage_dashboard_view'),
    url(r'^list$', views.list_users_view,
        name='list_users_view'),
    url(r'^dashboard$', rep_views.homepage_dashboard_view,
        name='homepage_dashboard_view'),
    url(r'^details$', views.user_details_view,
        name='user_details_view'),
    url(r'^add$', views.add_user_view,
        name='add_user_view'),

    # REST-API Endpoints
    url(r'^users/api/v1/details/(?P<user_id>[0-9]+)$',
        apis.user_details_api, name='user_details_api'),
    url(r'^users/api/v1/delete/(?P<user_id>[0-9]+)$',
        apis.delete_user_api, name='delete_user_api'),
    url(r'^users/api/v1/list$',
        apis.list_users_api, name='list_users_api'),
    url(r'^users/api/v1/authtoken/get$',
        apis.get_curruser_authtoken_api, name='get_curruser_authtoken_api'),
    url(r'^users/api/v1/authtoken/get/(?P<user_id>[0-9]+)$',
        apis.get_user_authtoken_api, name='get_user_authtoken_api'),
    url(r'^users/api/v1/authtoken/renew$',
        apis.renew_curruser_authtoken_api, name='renew_curruser_authtoken_api'),
    url(r'^users/api/v1/authtoken/renew/(?P<user_id>[0-9]+)$',
        apis.renew_user_authtoken_api, name='renew_user_authtoken_api'),
    url(r'^users/api/v1/authtoken/delete$',
        apis.delete_curruser_authtoken_api, name='delete_curruser_authtoken_api'),
    url(r'^users/api/v1/authtoken/delete/(?P<user_id>[0-9]+)$',
        apis.delete_user_authtoken_api, name='delete_user_authtoken_api'),
]
