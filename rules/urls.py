# -*- coding: utf-8 -*-

"""URL routes for alerting rules."""

from django.conf.urls import url
from . import views, apis


urlpatterns = [
    # API Views
    # ex: /rules/api/v1/alerting/list
    url(r'^api/v1/alerting/list$',
        apis.list_alerting_rules_api, name='list_alerting_rules_api'),
    # ex: /rules/api/v1/alerting/1
    url(r'^api/v1/alerting/by-id/(?P<rule_id>[0-9]+)$',
        apis.get_alerting_rule_api, name='get_alerting_rule_api'),
    # ex: /rules/api/v1/delete
    url(r'^api/v1/delete$',
        apis.delete_rules_api, name='delete_rules_api'),
    # ex: /rules/api/v1/delete/1
    url(r'^api/v1/delete/(?P<rule_id>[0-9]+)$',
        apis.delete_rule_api, name='delete_rule_api'),
    # ex: /rules/api/v1/add
    url(r'^api/v1/add$',
        apis.add_rule_api, name='add_rule_api'),
    # ex: /rules/api/v1/duplicate/3
    url(r'^api/v1/alerting/duplicate/(?P<rule_id>[0-9]+)$',
        apis.duplicate_rule_api, name='duplicate_rule_api'),
    # ex: /rules/api/v1/change_status/3
    url(r'^api/v1/change_status/(?P<rule_id>[0-9]+)$',
        apis.toggle_rule_status_api, name='toggle_rule_status_api'),
    # ex: /rules/api/v1/send/slack
    # url(r'^api/v1/send/slack$',
    #     apis.send_slack_message_api, name='send_slack_message_api'),

    # WEB Views
    # ex: /rules/list
    url(r'^list$',
        views.list_rules_view, name='list_rules_view'),

]
