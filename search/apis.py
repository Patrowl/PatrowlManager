# -*- coding: utf-8 -*-

from django.http import JsonResponse
from .views import _search
from rest_framework.decorators import api_view


@api_view(['GET'])
def search_api(request):
    """REST-API: Search based on keywords."""
    kw = request.GET.get('srch-term', None)

    if not kw:
        return JsonResponse([])

    results = _search(kw)
    return JsonResponse({'results': results, 'search_term': kw})
