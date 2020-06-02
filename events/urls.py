# -*- coding: utf-8 -*-

from django.urls import path
from django.conf.urls import url
from . import views, apis, serializers


urlpatterns = [
    # API Views
    # ex: /events/api/v1/list
    url(r'^api/v1/list$',
        apis.list_events_api, name='list_events_api'),
    # ex: /events/api/v1/delete/2
    url(r'^api/v1/delete/(?P<event_id>[0-9]+)$',
        apis.delete_event_api, name='delete_event_api'),
    url(r'^api/v1/alerts/ack$', apis.ack_alerts_api, name='ack_alerts_api'),
    url(r'^api/v1/alerts/archive$', apis.archive_alerts_api, name='archive_alerts_api'),

    # WEB Views
    # ex: /events/delete [POST]
    url(r'^delete/(?P<event_id>[0-9]+)$',
        views.delete_event_view, name='delete_event_view'),
]

# Serialized data
urlpatterns += [
    path('alerts/list', views.list_alerts_view, name='list_alerts_view'),
    path('api/list', serializers.EventListCreate.as_view()),
    path('api/alerts/list', serializers.AlertListCreate.as_view()),
]
