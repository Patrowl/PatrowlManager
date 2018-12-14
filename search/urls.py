# -*- coding: utf-8 -*-

from django.conf.urls import url
from . import views, apis


urlpatterns = [
    ## WEB Views
    # ex: /search
    url(r'^$', views.search_view, name='search_view'),
    # ex: /search
    url(r'/api/v1/$', apis.search_api, name='search_api'),

]
