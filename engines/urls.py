# -*- coding: utf-8 -*-

from django.conf.urls import url
from . import views, apis


urlpatterns = [

    ## WEB templates
    # ex: /engines/list
    url(r'^list$', views.list_engines_view, name='list_engines_view'),
    # ex: /engines/add
    url(r'^add$', views.add_engine_view, name='add_engine_view'),
    # ex: /engines/edit/1
    url(r'^edit/(?P<engine_id>[0-9]+)$', views.edit_engine_view, name='edit_engine_view'),
    # # ex: /engines/delete/1
    # url(r'^delete/(?P<engine_id>[0-9]+)$', views.delete_engine_view, name='delete_engine_view'),
    # ex: /engines/policies/list
    url(r'^policies/list$', views.list_policies_view, name='list_policies_view'),
    # ex: /engines/policies/add
    url(r'^policies/add$', views.add_policy_view, name='add_policy_view'),
    # ex: /engines/policies/edit/2
    url(r'^policies/edit/(?P<policy_id>[0-9]+)$', views.edit_policy_view, name='edit_policy_view'),
    # ex: /engines/policies/import
    url(r'^policies/import$', views.import_policies_view, name='import_policies_view'),
    # ex: /engines/types/list
    url(r'^types/list$', views.list_engine_types_view, name='list_engine_types_view'),
    # ex: /engines/types/add
    url(r'^types/add$', views.add_engine_types_view, name='add_engine_types_view'),
    # ex: /engines/types/edit/1
    url(r'^types/edit/(?P<engine_id>[0-9]+)$', views.edit_engine_type_view, name='edit_engine_type_view'),
    # ex: /engines/types/delete/1
    url(r'^types/delete/(?P<engine_id>[0-9]+)$', views.delete_engine_type_view, name='delete_engine_type_view'),

    ## JSON API
    # ex: /engines/api/v1/test
    url(r'^api/v1/test$', apis.test_task_api, name='test_task_api'),
    # ex: /engines/api/v1/list
    url(r'^api/v1/list$', apis.list_engines_api, name='list_engines_api'),
    # ex: /engines/api/v1/types
    url(r'^api/v1/types$', apis.list_engine_types_api, name='list_engine_types_api'),
    # ex: /engines/api/v1/refresh
    url(r'^api/v1/refresh$', apis.refresh_engines_status_api, name='refresh_engines_status_api'),
    # ex: /engines/api/v1/delete/1
    url(r'^api/v1/delete/(?P<engine_id>[0-9]+)$', apis.delete_engine_api, name='delete_engine_api'),
    # ex: /engines/api/v1/autorefresh
    url(r'^api/v1/autorefresh$', apis.toggle_autorefresh_engine_status_api, name='toggle_autorefresh_engine_status_api'),
    # ex: /engines/api/v1/list/by_id/1
    url(r'^api/v1/by-id/(?P<engine_id>[0-9]+)$', apis.list_instances_by_id_api, name='list_instances_by_id_api'),
    # ex: /engines/api/v1/list
    url(r'^api/v1/instances/list$', apis.list_engines_intances_api, name='list_engines_intances_api'),
    # ex: /engines/api/v1/list/by_name/nmap
    url(r'^api/v1/list/by_name/(?P<engine_name>[a-zA-Z]+)$', apis.list_instances_by_name_api, name='list_instances_by_name_api'),
    # ex: /engines/api/v1/instances/by-id/1
    url(r'^api/v1/instances/by-id/(?P<engine_id>[0-9]+)$', apis.get_engine_api, name='get_engine_api'),
    # ex: /engines/api/v1/instances/status/1
    url(r'^api/v1/instances/status/(?P<engine_id>[0-9]+)$', apis.get_engine_status_api, name='get_engine_status_api'),
    # ex: /engines/api/v1/instances/info/1
    url(r'^api/v1/instances/info/(?P<engine_id>[0-9]+)$', apis.get_engine_info_api, name='get_engine_info_api'),
    # ex: /engines/api/v1/instances/status/change/8
    url(r'^api/v1/instances/status/change/(?P<engine_id>[0-9]+)$', apis.toggle_engine_status_api, name='toggle_engine_status_api'),
    # ex: /engines/api/v1/instance/info/1
    url(r'^api/v1/instance/info/(?P<engine_id>[0-9]+)$', apis.info_engine_api, name='info_engine_api'),
    # ex: /engines/api/v1/policies/list
    url(r'^api/v1/policies/list$', apis.get_policies_api, name='get_policies_api'),
    # ex: /engines/api/v1/policies/by-id/2
    url(r'^api/v1/policies/by-id/(?P<policy_id>[0-9]+)$', apis.get_policy_api, name='get_policy_api'),
    # ex: /engines/api/v1/nmap/policies
    url(r'^api/v1/policies/list/by_name/(?P<engine_name>[a-zA-Z]+)$', apis.list_policies_by_engine_api, name='list_policies_by_engine_api'),
    # ex: /engines/api/v1/policies/delete/2
    url(r'^api/v1/policies/delete/(?P<policy_id>[0-9]+)$', apis.delete_policy_api, name='delete_policy_api'),
    # ex: /engines/api/v1/policies/export
    url(r'^api/v1/policies/export$', apis.export_policies_api, name='export_policies_api'),
    # ex: /engines/api/v1/policies/export/2
    url(r'^api/v1/policies/export/(?P<policy_id>[0-9]+)$', apis.export_policy_api, name='export_policy_api'),
    # ex: /engines/api/v1/policies/duplicate/2
    url(r'^api/v1/policies/duplicate/(?P<policy_id>[0-9]+)$', apis.duplicate_policy_api, name='duplicate_policy_api'),
]
