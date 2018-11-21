# -*- coding: utf-8 -*-

from django.conf.urls import url
from . import views


urlpatterns = [
    ## WEB Views
    # ex: /search
    url(r'^$', views.search_view, name='search_view'),
    # ex: /findings/list

]
