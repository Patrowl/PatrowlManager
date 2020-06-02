# -*- coding: utf-8 -*-
"""View definitions for Events."""

from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Event, Alert


def delete_event_view(request, event_id):
    """Delete an event."""
    event = get_object_or_404(Event, id=event_id)
    if request.method == 'POST':
        event.delete()

        # reevaluate related asset critity
        messages.success(request, 'Event successfully deleted!')
    return render(request, 'delete-event.html', {'event': event})


def list_alerts_view(request):
    """List new and read Alerts."""
    page = request.GET.get('p_alerts', 1)
    status = request.GET.get('status', "")
    severity = request.GET.get('severity', "")
    alerts_list = []
    if status in ["archived", "read", "new"]:
        alerts_list = Alert.objects.filter(status=status).order_by('-updated_at')
    else:
        # alerts_list = Alert.objects.all().order_by('-updated_at')
        alerts_list = Alert.objects.filter(status__in=["new", "read"]).order_by('-updated_at')

    if severity in ["info", "low", "medium", "high", "critical"]:
        alerts_list = alerts_list.filter(severity=severity)

    paginator = Paginator(alerts_list, 50)
    try:
        alerts = paginator.page(page)
    except PageNotAnInteger:
        alerts = paginator.page(1)
    except EmptyPage:
        alerts = paginator.page(paginator.num_pages)
    return render(request, 'list-alerts.html', {'alerts': alerts})
