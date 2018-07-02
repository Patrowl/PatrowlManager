from django.conf.urls import url
from django.contrib import admin
from . import views


urlpatterns = [
    ## API Views
    # ex: /rules/api/v1/list
    url(r'^api/v1/list$', views.list_rules_api, name='list_rules_api'),
    # ex: /rules/api/v1/delete
    url(r'^api/v1/delete$', views.delete_rules_api, name='delete_rules_api'),
    # ex: /rules/api/v1/add
    url(r'^api/v1/add$', views.add_rule_api, name='add_rule_api'),
    # ex: /rules/api/v1/duplicate/3
    url(r'^api/v1/duplicate/(?P<rule_id>[0-9]+)$', views.duplicate_rule_api, name='duplicate_rule_api'),
    # ex: /rules/api/v1/change_status/3
    url(r'^api/v1/change_status/(?P<rule_id>[0-9]+)$', views.toggle_rule_status_api, name='toggle_rule_status_api'),
    # # ex: /rules/api/v1/evaluate/3
    # url(r'^api/v1/evaluate/(?P<rule_id>[0-9]+)$', views.evaluate_rule_api, name='evaluate_rule_api'),
    # ex: /rules/api/v1/send/slack
    url(r'^api/v1/send/slack$', views.send_slack_message_api, name='send_slack_message_api'),

    ## WEB Views
    # ex: /rules/list
    url(r'^list$', views.list_rules_view, name='list_rules_view'),

]
