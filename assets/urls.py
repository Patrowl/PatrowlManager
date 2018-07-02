from django.conf.urls import url
from django.contrib import admin
from . import views


urlpatterns = [
    # ex: /assets
    url(r'^$', views.list_assets, name='list_assets'),
    # ex: /assets/list
    url(r'^list$', views.list_assets_view, name='list_assets_view'),
    # ex: /assets/get_tags
    url(r'^get_tags$', views.get_asset_tags_api, name='get_asset_tags_api'),
    # ex: /assets/export
    url(r'^export$', views.export_assets, name='export_assets'),
    # ex: /assets/export/8
    url(r'^export/(?P<assetgroup_id>[0-9]+)$', views.export_assets, name='export_assets'),
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
    # ex: /assets/delete
    url(r'^delete$', views.delete_assets, name='delete_assets'),
    # ex: /assets/delete/8
    url(r'^delete/(?P<asset_id>[0-9]+)$', views.delete_asset_view, name='delete_asset_view'),
    # ex: /assets/deletegroup/8
    url(r'^deletegroup/(?P<assetgroup_id>[0-9]+)$', views.delete_asset_group_view, name='delete_asset_group_view'),
    # ex: /assets/details/8
    url(r'^details/(?P<asset_id>[0-9]+)$', views.detail_asset_view, name='detail_asset_view'),
    # ex: /assets/details/3/add_tag
    url(r'^details/(?P<asset_id>[0-9]+)/add_tag$', views.add_asset_tags_api, name='add_asset_tags_api'),
    # ex: /assets/details/3/add_tag
    url(r'^details/(?P<asset_id>[0-9]+)/del_tag$', views.delete_asset_tags_api, name='delete_asset_tags_api'),
    # # ex: /assets/groups/details/8
    url(r'^groups/details/(?P<assetgroup_id>[0-9]+)$', views.detail_asset_group_view, name='detail_asset_group_view'),
    # ex: /assets/groups/details/3/add_tag
    url(r'^groups/details/(?P<assetgroup_id>[0-9]+)/add_tag$', views.add_asset_group_tags_api, name='add_asset_group_tags_api'),
    # ex: /assets/groups/details/3/add_tag
    url(r'^groups/details/(?P<assetgroup_id>[0-9]+)/del_tag$', views.delete_asset_group_tags_api, name='delete_asset_group_tags_api'),
    # ex: /assets/eval/8
    url(r'^eval/(?P<asset_name>[\w\.-]+)$', views.evaluate_asset_risk_view, name='evaluate_asset_risk_view'),
    # ex: /assets/report/html/2
    url(r'^report/html/(?P<asset_id>[0-9]+)$', views.get_asset_report_html, name='get_asset_report_html'),
    # ex: /assets/groups/report/html/2
    url(r'^groups/report/html/(?P<asset_group_id>[0-9]+)$', views.get_asset_group_report_html, name='get_asset_group_report_html'),
    # ex: /assets/report/json/2
    url(r'^report/json/(?P<asset_id>[0-9]+)$', views.get_asset_report_json, name='get_asset_report_json'),
    # ex: /assets/8 (GET, PUT, DELETE)
    url(r'^(?P<asset_id>[0-9]+)$', views.asset_details, name='asset_details'),
    # ex: /assets/owners/list
    url(r'^owners/list$', views.list_asset_owners_view, name='list_asset_owners_view'),
    # ex: /assets/owners/add
    url(r'^owners/add$', views.add_asset_owner_view, name='add_asset_owner_view'),
    # ex: /assets/owners/delete/8
    url(r'^owners/delete/(?P<asset_owner_id>[0-9]+)$', views.delete_asset_owner_view, name='delete_asset_owner_view'),
    # ex: /assets/owners/delete/8
    url(r'^owners/details/(?P<asset_owner_id>[0-9]+)$', views.details_asset_owner_view, name='details_asset_owner_view'),
    # ex: /assets/owners/editassets/8
    #url(r'^owners/editassets/(?P<asset_owner_id>[0-9]+)$', views.editassets_asset_owner_view, name='editassets_asset_owner_view'),
    # ex: /assets/owners/adddoc/8
    url(r'^owners/adddoc/(?P<asset_owner_id>[0-9]+)$', views.add_asset_owner_document, name='add_asset_owner_document'),
    # ex: /assets/owners/getdoc/8
    url(r'^owners/getdoc/(?P<asset_owner_doc_id>[0-9]+)$', views.get_asset_owner_doc, name='get_asset_owner_doc'),
    # ex: /assets/owners/deletedoc/8
    url(r'^owners/deletedoc/(?P<asset_owner_id>[0-9]+)$', views.delete_asset_owner_document, name='delete_asset_owner_document'),
    # ex: /assets/owners/adddoc/8
    url(r'^owners/addcontact/(?P<asset_owner_id>[0-9]+)$', views.add_asset_owner_contact, name='add_asset_owner_contact'),
    # ex: /assets/owners/deletecontact/8
    url(r'^owners/deletecontact/(?P<asset_owner_id>[0-9]+)$', views.delete_asset_owner_contact, name='delete_asset_owner_contact'),
    # ex: /assets/owners/editcom/8
    url(r'^owners/editcom/(?P<asset_owner_id>[0-9]+)$', views.edit_asset_owner_comments, name='edit_asset_owner_comments'),

    # ex: /assets/api/v1/list
    url(r'^api/v1/list$', views.list_assets_api, name='list_assets_api'),
    # ex: /assets/api/v1/details/3
    url(r'^api/v1/details/(?P<asset_name>[\w\.-]+)$', views.get_asset_details_api, name='get_asset_details_api'),
    # ex: /assets/api/v1/stats
    url(r'^api/v1/stats$', views.get_assets_stats, name='get_assets_stats'),
    # ex: /assets/api/v1/trends/4
    url(r'^api/v1/trends/(?P<asset_id>[0-9]+)$', views.get_asset_trends, name='get_asset_trends'),
    # ex: /assets/api/v1/refresh_all_grades
    url(r'^api/v1/refresh_all_grades$', views.refresh_all_asset_grade_api, name='refresh_all_asset_grade_api'),
    # ex: /assets/api/v1/asset_grade_refresh
    url(r'^api/v1/asset_grade_refresh$', views.refresh_asset_grade_api, name='refresh_asset_grade_api'),
    # ex: /assets/api/v1/asset_grade_refresh/2
    url(r'^api/v1/asset_grade_refresh(?P<asset_id>[0-9]+)$', views.refresh_asset_grade_api, name='refresh_asset_grade_api'),
    # ex: /assets/api/v1/assetgroup_grade_refresh
    url(r'^api/v1/assetgroup_grade_refresh$', views.refresh_assetgroup_grade_api, name='refresh_assetgroup_grade_api'),
    # ex: /assets/api/v1/assetgroup_grade_refresh/4
    url(r'^api/v1/assetgroup_grade_refresh/(?P<assetgroup_id>[0-9]+)$', views.refresh_assetgroup_grade_api, name='refresh_assetgroup_grade_api'),


    # url(r'^add$', views.add_asset, name='add_asset'),
    # # ex: /assets/8
    # url(r'^(?P<asset_id>[0-9]+)$', views.get_asset, name='get_asset'),
    # # ex: /assets/8/remove
    # url(r'^(?P<asset_id>[0-9]+)/remove$', views.remove_asset, name='remove_asset'),
    # # ex: /assets/8/update?name=ip
    # url(r'^(?P<asset_id>[0-9]+)/update$', views.update_asset, name='update_asset'),
]
