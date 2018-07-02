from django.conf.urls import url
from django.contrib import admin
from . import views
import users.views as users_views


urlpatterns = [
    ## WEB Views
    # ex: /settings/
    url(r'^$', views.show_settings_menu, name='show_settings_menu'),
    # ex: /settings/users/
    #url(r'^$', users_views.list_users_view, name='list_users_view'),
    # ex: /settings/alerts
    #url(r'^$', views.list_events, name='list_events'),

    ## API views
    # ex: /settings/api/v1/update
    url(r'^api/v1/update$', views.update_setting_api, name='update_setting_api'),
    # ex: /settings/api/v1/add
    url(r'^api/v1/add$', views.add_setting_api, name='add_setting_api'),
    # ex: /settings/api/v1/delete/3
    url(r'^api/v1/delete/(?P<setting_id>[0-9]+)$', views.delete_setting_api, name='delete_setting_api'),
    # ex: /settings/api/v1/export
    url(r'^api/v1/export$', views.export_settings_api, name='export_settings_api'),

]
