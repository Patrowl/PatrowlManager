# -*- coding: utf-8 -*-
"""REST-API definitions for Events."""

from django.http import JsonResponse
from django.forms.models import model_to_dict
from rest_framework.decorators import api_view
from .models import Event


@api_view(['GET'])
def list_events_api(request):
    """List Events."""
    events = []
    for e in Event.objects.all().order_by('-id')[:100]:
        events.append(model_to_dict(e))

    return JsonResponse(events, json_dumps_params={'indent': 2}, safe=False)
