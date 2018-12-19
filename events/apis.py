# -*- coding: utf-8 -*-
"""REST-API definitions for Events."""

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
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


@api_view(['DELETE'])
def delete_event_api(request, event_id):
    """Delete an event."""
    event = get_object_or_404(Event, id=event_id)
    event.delete()

    return JsonResponse({
        "status": "deleted",
        "message": "event '{}' deleted.".format(event_id)
    })
