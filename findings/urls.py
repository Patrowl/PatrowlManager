# -*- coding: utf-8 -*-

from django.conf.urls import url
from . import views


urlpatterns = [
    ## WEB Views
    # ex: /findings
    url(r'^$', views.list_findings, name='list_findings'),
    # ex: /findings/list
    url(r'^list$', views.list_findings_view, name='list_findings_view'),
    # ex: /findings/import
    url(r'^import$', views.import_findings_view, name='import_findings_view'),
    # ex: /findings/list/8.8.8.8
    url(r'^list/(?P<asset_name>[\w\.-]+)$', views.list_asset_findings_view, name='list_asset_findings_view'),
    # url(r'^list/(?P<asset_name>[0-9A-Fa-f-\.]+)$', views.list_asset_findings_view, name='list_asset_findings_view'),
    # ex: /findings/delete/8
    url(r'^delete/(?P<finding_id>[0-9]+)$', views.delete_finding_view, name='delete_finding_view'),
    # ex: /findings/details/8
    url(r'^details/(?P<finding_id>[0-9]+)$', views.details_finding_view, name='details_finding_view'),
    # ex: /findings/edit/8
    url(r'^edit/(?P<finding_id>[0-9]+)$', views.edit_finding_view, name='edit_finding_view'),
    # ex: /findings/add
    url(r'^add$', views.add_finding_view, name='add_finding_view'),
    # ex: /findings/compare
    url(r'^compare$', views.compare_rawfindings_view, name='compare_rawfindings_view'),



    ## JSON API
    # ex: /findings/add (POST params)
    url(r'^add$', views.add_finding, name='add_finding'),
    # ex: /findings/delete (POST params)
    url(r'^delete$', views.delete_findings, name='delete_findings'),
    # ex: /findings/rdelete (POST params)
    url(r'^rdelete$', views.delete_rawfindings, name='delete_rawfindings'),
    # ex: /findings/status (POST params)
    url(r'^status$', views.change_findings_status, name='change_findings_status'),
    # ex: /findings/rstatus (POST params)
    url(r'^rstatus$', views.change_rawfindings_status, name='change_rawfindings_status'),
    # ex: /findings/export (POST params)
    url(r'^export$', views.export_findings_csv, name='export_findings_csv'),
    # ex: /findings/api/v1/stats
    url(r'^api/v1/stats$', views.get_findings_stats, name='get_findings_stats'),
    # ex: /findings/api/v1/gen_alerts/2
    url(r'^api/v1/gen_alerts/(?P<finding_id>[0-9]+)$', views.generate_finding_alerts, name='generate_finding_alerts'),
    # ex: /findings/api/v1/gen_alerts/2
    url(r'^api/v1/update_comments/(?P<finding_id>[0-9]+)$', views.update_finding_comments, name='update_finding_comments'),
    # ex: /findings/api/v1/alert/2
    url(r'^api/v1/alert/(?P<finding_id>[0-9]+)$', views.send_finding_alerts, name='send_finding_alerts'),
    # ex: /findings/api/v1/update?severity=high
    url(r'^api/v1/update/(?P<finding_id>[0-9]+)$', views.update_finding_api, name='update_finding_api'),
    # ex: /findings/8/export?format=html|csv
    url(r'^api/v1/export/(?P<finding_id>[0-9]+)$', views.export_finding_api, name='export_finding_api'),
    # ex: /findings/8
    url(r'^(?P<finding_id>[0-9]+)$', views.get_finding, name='get_finding'),
    # ex: /findings/8/remove
    url(r'^(?P<finding_id>[0-9]+)/remove$', views.remove_finding, name='remove_finding'),
    # ex: /findings/8/update?severity=high
    url(r'^(?P<finding_id>[0-9]+)/update$', views.update_finding, name='update_finding'),
    # ex: /findings/raw/8
    url(r'^(?P<finding_id>[0-9]+)/raw$', views.raw_finding, name='raw_finding'),
]
