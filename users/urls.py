# -*- coding: utf-8 -*-

from django.conf.urls import url
from . import views
from reportings import views as rep_views


urlpatterns = [
    url(r'^$', rep_views.homepage_dashboard_view, name='homepage_dashboard_view'),
    url(r'^list$', views.list_users_view, name='list_users_view'),
    url(r'^home$', views.home, name='home'),
    url(r'^dashboard$', rep_views.homepage_dashboard_view, name='homepage_dashboard_view'),
    url(r'^details$', views.user_details_view, name='user_details_view'),
    url(r'^add$', views.add_user_view, name='add_user_view'),
    # url(r'^login/$', auth_views.login, name='login'),
    # url(r'^logout/$', auth_views.logout, name='logout'),
    # url(r'^admin/', admin.site.urls),
]
