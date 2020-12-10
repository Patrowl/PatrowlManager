# -*- coding: utf-8 -*-
from django.urls import path
from django.conf.urls import url
from . import views, apis, serializers


urlpatterns = [
    # ex: /assets/list
    url(r'^list$', views.list_assets_view, name='list_assets_view'),
    # ex: /assets/add
    url(r'^add$', views.add_asset_view, name='add_asset_view'),
    # ex: /assets/bulkadd
    url(r'^bulkadd$', views.bulkadd_asset_view, name='bulkadd_asset_view'),
    # ex: /assets/addgroup
    url(r'^addgroup$', views.add_asset_group_view, name='add_asset_group_view'),
    # ex: /assets/edit/8
    url(r'^edit/(?P<asset_id>[0-9]+)$', views.edit_asset_view, name='edit_asset_view'),
    # ex: /assets/edit/8
    url(r'^groups/edit/(?P<assetgroup_id>[0-9]+)$', views.edit_asset_group_view, name='edit_asset_group_view'),
    # ex: /assets/details/8
    url(r'^details/(?P<asset_id>[0-9]+)$', views.detail_asset_view, name='detail_asset_view'),
    # # ex: /assets/groups/details/8
    url(r'^groups/details/(?P<assetgroup_id>[0-9]+)$', views.detail_asset_group_view, name='detail_asset_group_view'),
    # ex: /assets/eval/8
    url(r'^eval/(?P<asset_name>[\w\.-]+)$', views.evaluate_asset_risk_view, name='evaluate_asset_risk_view'),
    # ex: /assets/owners/list
    url(r'^owners/list$', views.list_asset_owners_view, name='list_asset_owners_view'),
    # ex: /assets/owners/add
    url(r'^owners/add$', views.add_asset_owner_view, name='add_asset_owner_view'),
    # ex: /assets/owners/delete/8
    url(r'^owners/delete/(?P<asset_owner_id>[0-9]+)$', views.delete_asset_owner_view, name='delete_asset_owner_view'),
    # ex: /assets/owners/details/8
    url(r'^owners/details/(?P<asset_owner_id>[0-9]+)$', views.details_asset_owner_view, name='details_asset_owner_view'),



    # REST-API endpoints
    # ex: /assets/api/v1/by-id/2
    url(r'^api/v1/by-id/(?P<asset_id>[0-9]+)$', apis.get_asset_api, name='get_asset_api'),
    # ex: /assets/api/v1/by-id/2
    url(r'^api/v1/by-id/(?P<asset_id>[0-9]+)/findings$', apis.get_asset_findings_api, name='get_asset_findings_api'),
    # ex: /assets/api/v1/list
    url(r'^api/v1/list$', apis.list_assets_api, name='list_assets_api'),
    # ex: /assets/api/v1/by-id/2/ack
    url(r'^api/v1/by-id/(?P<asset_id>[0-9]+)/ack$', apis.ack_asset_api, name='ack_asset_api'),
    # ex: /assets/api/v1/export
    url(r'^api/v1/export$', apis.export_assets_api, name='export_assets_api'),
    # ex: /assets/api/v1/add
    url(r'^api/v1/add$', apis.add_asset_api, name='add_asset_api'),
    # ex: /assets/api/v1/update_criticity
    url(r'^api/v1/update_criticity$', apis.update_criticity_assets_api, name='update_criticity_assets_api'),
    # ex: /assets/api/v1/update_groups
    url(r'^api/v1/update_groups$', apis.update_groups_assets_api, name='update_groups_assets_api'),
    # ex: /assets/api/v1/delete
    url(r'^api/v1/delete$', apis.delete_assets_api, name='delete_assets_api'),
    # ex: /assets/api/v1/delete/2
    url(r'^api/v1/delete/(?P<asset_id>[0-9]+)$', apis.delete_asset_api, name='delete_asset_api'),
    # ex: /assets/api/v1/groups/export
    url(r'^api/v1/groups/export$', apis.export_assetgroups_api, name='export_assetgroups_api'),
    # ex: /assets/api/v1/groups/add
    url(r'^api/v1/groups/add$', apis.add_asset_group_api, name='add_asset_group_api'),
    # ex: /assets/api/v1/groups/delete/2
    url(r'^api/v1/groups/delete/(?P<assetgroup_id>[0-9]+)$', apis.delete_assetgroup_api, name='delete_assetgroup_api'),
    # ex: /assets/api/v1/groups/delete-assets/2
    url(r'^api/v1/groups/delete-assets/(?P<assetgroup_id>[0-9]+)$', apis.delete_assets_from_group_api, name='delete_assets_from_group_api'),
    # ex: /assets/api/v1/groups/delete-assets/2
    url(r'^api/v1/groups/delete-asset/(?P<assetgroup_id>[0-9]+)/(?P<asset_id>[0-9]+)$', apis.delete_asset_from_group_api, name='delete_asset_from_group_api'),
    # ex: /assets/api/v1/groups/edit/2
    url(r'^api/v1/groups/edit/(?P<assetgroup_id>[0-9]+)$', apis.edit_assetgroup_api, name='edit_assetgroup_api'),
    # ex: /assets/api/v1/export/8
    url(r'^api/v1/export/(?P<assetgroup_id>[0-9]+)$', apis.export_assets_api, name='export_assets_api'),
    # ex: /assets/api/v1/details/3
    url(r'^api/v1/details/(?P<asset_name>[\w\.-]+)$', apis.get_asset_details_api, name='get_asset_details_api'),
    # ex: /assets/api/v1/report/html/2
    url(r'^api/v1/report/html/(?P<asset_id>[0-9]+)$', apis.get_asset_report_html_api, name='get_asset_report_html_api'),
    # ex: /assets/api/v1/groups/report/html/2
    url(r'^api/v1/groups/report/html/(?P<asset_group_id>[0-9]+)$', apis.get_asset_group_report_html_api, name='get_asset_group_report_html_api'),
    # ex: /assets/api/v1/report/json/2
    url(r'^api/v1/report/json/(?P<asset_id>[0-9]+)$', apis.get_asset_report_json_api, name='get_asset_report_json_api'),
    # ex: /assets/api/v1/report/csv/2
    url(r'^api/v1/report/csv/(?P<asset_id>[0-9]+)$', apis.get_asset_report_csv_api, name='get_asset_report_csv_api'),
    # ex: /assets/api/v1/groups/report/json/2
    url(r'^api/v1/groups/report/json/(?P<asset_group_id>[0-9]+)$', apis.get_asset_group_report_json_api, name='get_asset_group_report_json_api'),
    # ex: /assets/api/v1/groups/report/json/2
    url(r'^api/v1/groups/report/csv/(?P<asset_group_id>[0-9]+)$', apis.get_asset_group_report_csv_api, name='get_asset_group_report_csv_api'),
    # ex: /assets/api/v1/tags
    url(r'^api/v1/tags$', apis.get_asset_tags_api, name='get_asset_tags_api'),
    # ex: /assets/api/v1/stats
    url(r'^api/v1/stats$', apis.get_assets_stats_api, name='get_assets_stats_api'),
    # ex: /assets/api/v1/trends/4
    url(r'^api/v1/trends/(?P<asset_id>[0-9]+)$', apis.get_asset_trends_api, name='get_asset_trends_api'),
    # ex: /assets/api/v1/details/3/add_tag
    url(r'^api/v1/details/(?P<asset_id>[0-9]+)/add_tag$', apis.add_asset_tags_api, name='add_asset_tags_api'),
    # ex: /assets/api/v1/details/3/del_tag
    url(r'^api/v1/details/(?P<asset_id>[0-9]+)/del_tag$', apis.delete_asset_tags_api, name='delete_asset_tags_api'),
    # ex: /assets/api/v1/refresh_all_grades
    url(r'^api/v1/refresh_all_grades$', apis.refresh_all_asset_grade_api, name='refresh_all_asset_grade_api'),
    # ex: /assets/api/v1/asset_grade_refresh
    url(r'^api/v1/asset_grade_refresh$', apis.refresh_asset_grade_api, name='refresh_asset_grade_api'),
    # ex: /assets/api/v1/asset_grade_refresh/2
    url(r'^api/v1/asset_grade_refresh(?P<asset_id>[0-9]+)$', apis.refresh_asset_grade_api, name='refresh_asset_grade_api'),

    # ex: /assets/api/v1/groups/list
    url(r'^api/v1/groups/list$', apis.list_asset_groups_api, name='list_asset_groups_api'),
    # ex: /assets/api/v1/groups/by-id/2
    url(r'^api/v1/groups/by-id/(?P<assetgroup_id>[0-9]+)$', apis.get_asset_group_api, name='get_asset_group_api'),
    # ex: /assets/api/v1/groups/details/3/add_tag
    url(r'^api/v1/groups/details/(?P<assetgroup_id>[0-9]+)/add_tag$', apis.add_asset_group_tags_api, name='add_asset_group_tags_api'),
    # ex: /assets/api/v1/groups/details/3/del_tag
    url(r'^api/v1/groups/details/(?P<assetgroup_id>[0-9]+)/del_tag$', apis.delete_asset_group_tags_api, name='delete_asset_group_tags_api'),
    # ex: /assets/api/v1/assetgroup_grade_refresh
    url(r'^api/v1/assetgroup_grade_refresh$', apis.refresh_assetgroup_grade_api, name='refresh_assetgroup_grade_api'),
    # ex: /assets/api/v1/assetgroup_grade_refresh/4
    url(r'^api/v1/assetgroup_grade_refresh/(?P<assetgroup_id>[0-9]+)$', apis.refresh_assetgroup_grade_api, name='refresh_assetgroup_grade_api'),
    # ex: /assets/api/v1/owners/adddoc/8
    url(r'^api/v1/owners/adddoc/(?P<asset_owner_id>[0-9]+)$', apis.add_asset_owner_document_api, name='add_asset_owner_document_api'),
    # ex: /assets/api/v1/owners/getdoc/8
    url(r'^api/v1/owners/getdoc/(?P<asset_owner_doc_id>[0-9]+)$', apis.get_asset_owner_doc_api, name='get_asset_owner_doc_api'),
    # ex: /assets/owners/deletedoc/8
    url(r'^api/v1/owners/deletedoc/(?P<asset_owner_id>[0-9]+)$', apis.delete_asset_owner_document_api, name='delete_asset_owner_document_api'),
    # ex: /assets/api/v1/owners/deletecontact/8
    url(r'^api/v1/owners/deletecontact/(?P<asset_owner_id>[0-9]+)$', apis.delete_asset_owner_contact_api, name='delete_asset_owner_contact_api'),
    # ex: /assets/api/v1/owners/adddoc/8
    url(r'^api/v1/owners/addcontact/(?P<asset_owner_id>[0-9]+)$', apis.add_asset_owner_contact_api, name='add_asset_owner_contact_api'),
    # ex: /assets/api/v1/owners/editcom/8
    url(r'^api/v1/owners/editcom/(?P<asset_owner_id>[0-9]+)$', apis.edit_asset_owner_comments_api, name='edit_asset_owner_comments_api'),
]

urlpatterns += [
    path('api/list', serializers.AssetList.as_view()),
    path('api/groups/list', serializers.AssetGroupList.as_view()),
]
