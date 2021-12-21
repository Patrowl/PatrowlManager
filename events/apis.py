# -*- coding: utf-8 -*-
"""REST-API definitions for Events and Alerts."""

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.forms.models import model_to_dict
# from common.utils.pagination import StandardResultsSetPagination
from rest_framework.decorators import api_view
# from rest_framework import viewsets
# from django_filters import rest_framework as filters
from .models import Event, Alert
# from .serializers import AlertSerializer


@api_view(['GET'])
def list_events_api(request):
    """List last 100 events."""
    events = []
    for e in Event.objects.all().order_by('-id')[:100]:
        events.append(model_to_dict(e))

    return JsonResponse(events, safe=False)


@api_view(['DELETE'])
def delete_event_api(request, event_id):
    """Delete an event."""
    event = get_object_or_404(Event, id=event_id)
    event.delete()

    return JsonResponse({
        "status": "deleted",
        "message": "event '{}' deleted.".format(event_id)
    })


@api_view(['POST'])
def ack_alerts_api(request):
    """Acknowledge an alert."""
    alerts = request.data
    for alert_id in alerts:
        a = Alert.objects.filter(id=alert_id).first()
        if a is not None:
            a.status = "read"
            a.save()

    return JsonResponse({'status': 'success'})


@api_view(['POST'])
def archive_alerts_api(request):
    """Archive an alert."""
    alerts = request.data
    for alert_id in alerts:
        a = Alert.objects.filter(id=alert_id).first()
        if a is not None:
            a.status = "archived"
            a.save()

    return JsonResponse({'status': 'success'})
