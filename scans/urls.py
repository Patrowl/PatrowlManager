from django.conf.urls import url
from django.contrib import admin
from . import views


urlpatterns = [
    ## JSON API
    # ex: /scans
    # url(r'^$', views.list_scans, name='list_scans'),
    # ex: /scans/api/v1/stats
    url(r'^api/v1/stats$', views.get_scans_stats, name='get_scans_stats'),
    # ex: /scans/api/v1/list
    url(r'^api/v1/list$', views.get_scans_heatmap, name='get_scans_heatmap'),
    # ex: /scans/api/v1/listbydate
    url(r'^api/v1/listbydate$', views.get_scans_by_date, name='get_scans_by_date'),
    # ex: /scans/api/v1/list
    url(r'^api/v1/filter$', views.get_scans_by_period, name='get_scans_by_period'),
    # ex: /scans/delete (add multiple scans in POST)
    url(r'^delete$', views.delete_scans, name='delete_scans'),
    # ex: /scans/stop/33
    url(r'^stop/(?P<scan_id>[0-9]+)$', views.stop_scan, name='stop_scan'),
    # ex: /scans/report/json/33
    url(r'^report/json/(?P<scan_id>[0-9]+)$', views.get_scan_report_json, name='get_scan_report_json'),
    # ex: /scans/report/csv/33
    url(r'^report/csv/(?P<scan_id>[0-9]+)$', views.get_scan_report_csv, name='get_scan_report_csv'),
    # ex: /scans/report/html/33
    url(r'^report/html/(?P<scan_id>[0-9]+)$', views.get_scan_report_html, name='get_scan_report_html'),
    # ex: /scans/reportzip/33
    url(r'^reportzip/(?P<scan_id>[0-9]+)$', views.send_scan_reportzip, name='send_scan_reportzip'),
    # ex: /scans/campaigns
    url(r'^campaigns$', views.list_scan_campaigns, name='list_scan_campaigns'),
    # ex: /scans/periodic/change_status/33
    url(r'^campaigns/change_status/(?P<scan_campaign_id>[0-9]+)$', views.toggle_scan_campaign_status, name='toggle_scan_campaign_status'),
    # ex: /scans/defs/delete/33
    url(r'^campaigns/run/(?P<scan_campaign_id>[0-9]+)$', views.run_scan_campaign, name='run_scan_campaign'),
    # ex: /scans/defs/change_status/33
    url(r'^defs/change_status/(?P<scan_def_id>[0-9]+)$', views.toggle_scan_def_status, name='toggle_scan_def_status'),
    # ex: /scans/defs/delete/33
    url(r'^defs/run/(?P<scan_def_id>[0-9]+)$', views.run_scan_def, name='run_scan_def'),


    ## WEB Views
    # ex: /scans/defs/list
    url(r'^list$', views.list_scans_view, name='list_scans_view'),
    # ex: /scans/delete/83
    url(r'^delete/(?P<scan_id>[0-9]+)$', views.delete_scan_view, name='delete_scan_view'),
    # ex: /scans/details/33
    url(r'^details/(?P<scan_id>[0-9]+)$', views.detail_scan_view, name='detail_scan_view'),
    # # ex: /scans/details/33/findings/34?raw=true
    # url(r'^details/(?P<scan_id>[0-9]+)/findings/(?P<finding_id>[0-9]+)$', views.detail_scan_finding_view, name='detail_scan_finding_view'),
    # ex: /scans/compare?scan_a_id=2&scan_b_id=32
    url(r'^compare$', views.compare_scans_view, name='compare_scans_view'),
    # ex: /scans/campaigns/list
    url(r'^campaigns/list$', views.list_scan_campaigns_view, name='list_scan_campaigns_view'),
    # ex: /scans/campaigns/delete/33
    url(r'^campaigns/delete/(?P<scan_campaign_id>[0-9]+)$', views.delete_scan_campaign_view, name='delete_scan_campaign_view'),
    # ex: /scans/campaigns/edit/33
    url(r'^campaigns/edit/(?P<scan_campaign_id>[0-9]+)$', views.edit_scan_campaign_view, name='edit_scan_campaign_view'),
    # ex: /scans/campaigns/add/33
    url(r'^campaigns/add$', views.add_scan_campaign_view, name='add_scan_campaign_view'),
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
