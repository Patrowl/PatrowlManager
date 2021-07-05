# -*- coding: utf-8 -*-

from django.urls import path
from django.conf.urls import url
from . import views, apis, serializers


urlpatterns = [
    ## WEB Views
    # ex: /findings/list
    url(r'^list$', views.list_findings_view, name='list_findings_view'),
    # ex: /findings/import
    url(r'^import$', views.import_findings_view, name='import_findings_view'),
    # ex: /findings/list/8.8.8.8
    url(r'^list/(?P<asset_name>[\w\.-]+)$', views.list_asset_findings_view, name='list_asset_findings_view'),
    # ex: /findings/delete/8
    url(r'^delete/(?P<finding_id>[0-9]+)$', views.delete_finding_view, name='delete_finding_view'),
    # ex: /findings/details/8
    url(r'^details/(?P<finding_id>[0-9]+)$', views.details_finding_view, name='details_finding_view'),
    # ex: /findings/edit/8
    url(r'^edit/(?P<finding_id>[0-9]+)$', views.edit_finding_view, name='edit_finding_view'),
    # ex: /findings/add
    url(r'^add$', views.add_finding_view, name='add_finding_view'),
    # ex: /findings/compare
    url(r'^compare$', views.compare_findings_view, name='compare_findings_view'),


    # REST-API endpoints
    # ex: /findings/api/v1/list
    url(r'^api/v1/list$', apis.list_findings_api, name='list_findings_api'),
    # ex: /findings/api/v1/add (POST params)
    url(r'^api/v1/add$', apis.add_finding_api, name='add_finding_api'),
    # ex: /findings/api/v1/delete (POST params)
    url(r'^api/v1/delete$', apis.delete_findings_api, name='delete_findings_api'),
    # ex: /findings/api/v1/rdelete (POST params)
    url(r'^api/v1/rdelete$', apis.delete_rawfindings_api, name='delete_rawfindings_api'),
    # ex: /findings/api/v1/status (POST params)
    url(r'^api/v1/status$', apis.change_findings_status_api, name='change_findings_status_api'),
    # ex: /findings/api/v1/2/ack
    url(r'^api/v1/(?P<finding_id>[0-9]+)/ack$', apis.ack_findings_status_api, name='ack_findings_status_api'),
    # ex: /findings/api/v1/rstatus (POST params)
    url(r'^api/v1/rstatus$', apis.change_rawfindings_status_api, name='change_rawfindings_status_api'),
    # ex: /findings/export (POST params)
    url(r'^api/v1/export$', apis.export_findings_csv_api, name='export_findings_csv_api'),
    # ex: /findings/filtered-export (GET params)
    url(r'^api/v1/filteredexport$', apis.export_filtered_findings_csv_api, name='export_filtered_findings_csv_api'),
    # ex: /findings/api/v1/stats
    url(r'^api/v1/stats$', apis.get_findings_stats_api, name='get_findings_stats_api'),
    # ex: /findings/api/v1/gen_alerts/2
    url(r'^api/v1/gen_alerts/(?P<finding_id>[0-9]+)$', apis.generate_finding_alerts_api, name='generate_finding_alerts_api'),
    # ex: /findings/api/v1/gen_alerts/2
    url(r'^api/v1/update_comments/(?P<finding_id>[0-9]+)$', apis.update_finding_comments_api, name='update_finding_comments_api'),
    # ex: /findings/api/v1/alert/2
    url(r'^api/v1/alert/(?P<finding_id>[0-9]+)$', apis.send_finding_alerts_api, name='send_finding_alerts_api'),
    # ex: /findings/api/v1/update/2?severity=high
    url(r'^api/v1/update/(?P<finding_id>[0-9]+)$', apis.update_finding_api, name='update_finding_api'),
    # ex: /findings/api/v1/export/2?format=html|csv
    url(r'^api/v1/export/(?P<finding_id>[0-9]+)$', apis.export_finding_api, name='export_finding_api'),
    # ex: /findings/api/v1/8
    url(r'^api/v1/(?P<finding_id>[0-9]+)$', apis.get_finding_api, name='get_finding_api'),
    # ex: /findings/api/v1/8
    url(r'^api/v1/by-id/(?P<finding_id>[0-9]+)$', apis.get_finding_api, name='get_finding_byid_api'),
    # ex: /findings/api/v1/raw/8
    url(r'^api/v1/raw/(?P<finding_id>[0-9]+)$', apis.get_raw_finding_api, name='get_raw_finding_api'),
]

# Serialized data
urlpatterns += [
    # path('api/list', serializers.FindingList.as_view()),
    # path('api/raw/list', serializers.RawFindingList.as_view()),
]
