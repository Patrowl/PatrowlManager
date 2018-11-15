from django.conf.urls import url
from . import views


urlpatterns = [

    ## WEB templates
    # ex: /engines/list
    url(r'^list$', views.list_engines_view, name='list_engines_view'),
    # ex: /engines/change_status/8
    url(r'^change_status/(?P<engine_id>[0-9]+)$', views.toggle_engine_status, name='toggle_engine_status'),
    # ex: /engines/add
    url(r'^add$', views.add_engine_view, name='add_engine_view'),
    # ex: /engines/edit/1
    url(r'^edit/(?P<engine_id>[0-9]+)$', views.edit_engine_view, name='edit_engine_view'),
    # ex: /engines/info/1
    url(r'^info/(?P<engine_id>[0-9]+)$', views.info_engine_api, name='info_engine_api'),
    # ex: /engines/delete/1
    url(r'^delete/(?P<engine_id>[0-9]+)$', views.delete_engine_view, name='delete_engine_view'),
    # ex: /engines/1/startscan
    #url(r'^(?P<engine_id>[0-9]+)/startscan$', views.startscan_by_engine_id, name='startscan_by_engine_id'),
    # ex: /engines/nmap/startscan
    #url(r'^(?P<engine_name>[a-zA-Z]+)/startscan$', views.startscan_by_engine_name, name='startscan_by_engine_name'),
    # ex: /engines/policies/list
    url(r'^policies/list$', views.list_policies_view, name='list_policies_view'),
    # ex: /engines/policies/add
    url(r'^policies/add$', views.add_policy_view, name='add_policy_view'),
    # ex: /engines/policies/delete/2
    url(r'^policies/delete/(?P<policy_id>[0-9]+)$', views.delete_policy_view, name='delete_policy_view'),
    # ex: /engines/policies/edit/2
    url(r'^policies/edit/(?P<policy_id>[0-9]+)$', views.edit_policy_view, name='edit_policy_view'),
    # ex: /engines/policies/duplicate/2
    url(r'^policies/duplicate/(?P<policy_id>[0-9]+)$', views.duplicate_policy_view, name='duplicate_policy_view'),
    # ex: /engines/policies/import
    url(r'^policies/import$', views.import_policies_view, name='import_policies_view'),
    # ex: /engines/policies/export/2
    url(r'^policies/export/(?P<policy_id>[0-9]+)$', views.export_policy, name='export_policy'),
    # ex: /engines/policies/export
    url(r'^policies/export$', views.export_policies, name='export_policies'),
    # ex: /engines/types/list
    url(r'^types/list$', views.list_engine_types_view, name='list_engine_types_view'),
    # ex: /engines/types/add
    url(r'^types/add$', views.add_engine_types_view, name='add_engine_types_view'),
    # ex: /engines/types/edit/1
    url(r'^types/edit/(?P<engine_id>[0-9]+)$', views.edit_engine_type_view, name='edit_engine_type_view'),
    # ex: /engines/types/delete/1
    url(r'^types/delete/(?P<engine_id>[0-9]+)$', views.delete_engine_type_view, name='delete_engine_type_view'),

    ## JSON API
    # ex: /engines/
    url(r'^$', views.list_engines, name='list_engines'),
    # ex: /engines/refresh
    url(r'^refresh$', views.refresh_engines_status, name='refresh_engines_status'),
    # ex: /engines/autorefresh
    url(r'^autorefresh$', views.toggle_autorefresh_engine_status, name='toggle_autorefresh_engine_status'),
    # ex: /engines/1
    url(r'^(?P<engine_id>[0-9]+)$', views.list_instances_by_id, name='list_instances_by_id'),
    # ex: /engines/nmap
    url(r'^(?P<engine_name>[a-zA-Z]+)$', views.list_instances_by_name, name='list_instances_by_name'),
    # ex: /engines/1/status
    url(r'^(?P<engine_id>[0-9]+)/status$', views.get_engine_status, name='get_engine_status'),
    # ex: /engines/1/refresh
    url(r'^(?P<engine_id>[0-9]+)/refresh$', views.get_engine_status, name='get_engine_status'),

    # ex: /engines/1/info
    url(r'^(?P<engine_id>[0-9]+)/info$', views.get_engine_info, name='get_engine_info'),
    # ex: /engines/nmap/policies
    url(r'^(?P<engine_name>[a-zA-Z]+)/policies$', views.list_policies_by_engine, name='list_policies_by_engine'),
    # ex: /engines/types
    url(r'^types$', views.list_engine_types, name='list_engine_types'),

    # ex: /engines/api/v1/list
    url(r'^api/v1/list$', views.list_engines_api, name='list_engines_api'),
]
