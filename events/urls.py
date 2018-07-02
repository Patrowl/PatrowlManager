from django.conf.urls import url
from django.contrib import admin
from . import views


urlpatterns = [
    ## API Views
    # ex: /events
    url(r'^$', views.list_events, name='list_events'),

    ## WEB Views
    # ex: /events/delete [POST]
    url(r'^delete/(?P<event_id>[0-9]+)$', views.delete_event_view, name='delete_event_view'),

]
