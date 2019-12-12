# -*- coding: utf-8 -*-
from rest_framework.pagination import PageNumberPagination


class StandardResultsSetPagination(PageNumberPagination):
    page_size_query_param = 'limit'
