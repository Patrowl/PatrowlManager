from django.http import JsonResponse
from assets.models import Asset, AssetGroup
from findings.models import Finding


def global_stats_api(request):
    data = None
    return JsonResponse(data)
