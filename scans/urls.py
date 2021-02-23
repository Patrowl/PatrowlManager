# -*- coding: utf-8 -*-

from django.conf.urls import url
from . import views, apis


urlpatterns = [
    ## JSON API
    # ex: /scans/api/v1/defs/list
    url(r'^api/v1/defs/list$', apis.get_scan_definitions_api, name='get_scan_definitions_api'),
    # ex: /scans/api/v1/defs/export
    url(r'^api/v1/defs/export$', apis.export_scan_definitions_api, name='export_scan_definitions_api'),
    # ex: /scans/api/v1/defs/export/1
    url(r'^api/v1/defs/export/(?P<scan_id>[0-9]+)$', apis.export_scan_definition_api, name='export_scan_definition_api'),
    # ex: /scans/api/v1/defs/by-id/1
    url(r'^api/v1/defs/by-id/(?P<scan_id>[0-9]+)$', apis.get_scan_definition_api, name='get_scan_definition_api'),
    # ex: /scans/api/v1/by-id/1
    url(r'^api/v1/by-id/(?P<scan_id>[0-9]+)$', apis.get_scan_api, name='get_scan_api'),
    # ex: /scans/api/v1/stats
    url(r'^api/v1/stats$', apis.get_scans_stats_api, name='get_scans_stats_api'),
    # ex: /scans/api/v1/list
    url(r'^api/v1/list$', apis.get_scans_api, name='get_scans_api'),
    # ex: /scans/api/v1/heatmap
    url(r'^api/v1/heatmap$', apis.get_scans_heatmap_api, name='get_scans_heatmap_api'),
    # ex: /scans/api/v1/listbydate
    url(r'^api/v1/listbydate$', apis.get_scans_by_date_api, name='get_scans_by_date_api'),
    # ex: /scans/api/v1/list
    url(r'^api/v1/filter$', apis.get_scans_by_period_api, name='get_scans_by_period_api'),
    # ex: /scans/api/v1/delete/1
    url(r'^api/v1/delete/(?P<scan_id>[0-9]+)$', apis.delete_scan_api, name='delete_scan_api'),
    # ex: /scans/api/v1/delete (add multiple scans in POST)
    url(r'^api/v1/delete$', apis.delete_scans_api, name='delete_scans_api'),
    # ex: /scans/api/v1/stop (POST)
    url(r'^api/v1/stop$', apis.stop_scans_api, name='stop_scans_api'),
    # ex: /scans/api/v1/stop/33
    url(r'^api/v1/stop/(?P<scan_id>[0-9]+)$', apis.stop_scan_api, name='stop_scan_api'),
    # ex: /scans/api/v1/stop/33
    url(r'^api/v1/retest/(?P<finding_id>[0-9]+)$', apis.add_retest_finding_scan_def_api, name='add_retest_finding_scan_def_api'),
    # ex: /scans/api/v1/report/json/33
    url(r'^api/v1/report/json/(?P<scan_id>[0-9]+)$', apis.get_scan_report_json_api, name='get_scan_report_json_api'),
    # ex: /scans/api/v1/report/csv/33
    url(r'^api/v1/report/csv/(?P<scan_id>[0-9]+)$', apis.get_scan_report_csv_api, name='get_scan_report_csv_api'),
    # ex: /scans/api/v1/report/html/33
    url(r'^api/v1/report/html/(?P<scan_id>[0-9]+)$', apis.get_scan_report_html_api, name='get_scan_report_html_api'),
    # ex: /scans/api/v1/reportzip/33
    # url(r'^api/v1/reportzip/(?P<scan_id>[0-9]+)$', apis.send_scan_reportzip_api, name='send_scan_reportzip_api'),
    # ex: /scans/api/v1/defs/change_status/33
    url(r'^api/v1/defs/change_status/(?P<scan_def_id>[0-9]+)$', apis.toggle_scan_def_status_api, name='toggle_scan_def_status_api'),
    # ex: /scans/api/v1/defs/run/33
    url(r'^api/v1/defs/run/(?P<scan_def_id>[0-9]+)$', apis.run_scan_def_api, name='run_scan_def_api'),
    # ex: /scans/api/v1/defs/add
    url(r'^api/v1/defs/add$', apis.add_scan_def_api, name='add_scan_def_api'),
    # ex: /scans/api/v1/defs/delete/1
    url(r'^api/v1/defs/delete/(?P<scan_id>[0-9]+)$', apis.delete_scan_def_api, name='delete_scan_def_api'),
    # ex: /scans/api/v1/defs/delete/1
    url(r'^api/v1/defs/delete$', apis.delete_scan_defs_api, name='delete_scan_defs_api'),


    ## WEB Views
    # ex: /scans/defs/list
    url(r'^list$', views.list_scans_view, name='list_scans_view'),
    # ex: /scans/details/33
    url(r'^details/(?P<scan_id>[0-9]+)$', views.detail_scan_view, name='detail_scan_view'),
    # ex: /scans/compare?scan_a_id=2&scan_b_id=32
    url(r'^compare$', views.compare_scans_view, name='compare_scans_view'),
    # ex: /scans/defs/list
    url(r'^defs/list$', views.list_scan_def_view, name='list_scan_def_view'),
    # ex: /scans/defs/delete/33
    url(r'^defs/delete/(?P<scan_def_id>[0-9]+)$', views.delete_scan_def_view, name='delete_scan_def_view'),
    # ex: /scans/defs/delete/33
    url(r'^defs/edit/(?P<scan_def_id>[0-9]+)$', views.edit_scan_def_view, name='edit_scan_def_view'),
    # ex: /scans/defs/add/33
    url(r'^defs/add$', views.add_scan_def_view, name='add_scan_def_view'),
    # ex: /scans/defs/details/33
    url(r'^defs/details/(?P<scan_definition_id>[0-9]+)$', views.detail_scan_def_view, name='detail_scan_def_view'),

]
