# -*- coding: utf-8 -*-
"""View definitions for Events."""

from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.conf import settings
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Event, Alert
from users.models import Team, TeamUser


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
    # Check team
    teamid_selected = -1
    if settings.PRO_EDITION is True and request.GET.get('team', '').isnumeric() and int(request.GET.get('team', -1)) >= 0:
        teamid = int(request.GET.get('team'))
        # @Todo: ensure the team is allowed for this user
        teamid_selected = teamid

    teams = []
    if settings.PRO_EDITION and request.user.is_superuser:
        teams = Team.objects.all().order_by('name')
    elif settings.PRO_EDITION and not request.user.is_superuser:
        for tu in TeamUser.objects.filter(user=request.user):
            teams.append({
                'id': tu.organization.id,
                'name': tu.organization.name
            })

    status = request.GET.get('status', "")
    severity = request.GET.get('severity', "")
    alerts_list = []
    if teamid_selected >= 0:
        if status in ["archived", "read", "new"]:
            alerts_list = Alert.objects.for_team(request.user, teamid_selected).filter(status=status).order_by('-updated_at')
        else:
            alerts_list = Alert.objects.for_team(request.user, teamid_selected).filter(status__in=["new", "read"]).order_by('-updated_at')
    else:
        if status in ["archived", "read", "new"]:
            alerts_list = Alert.objects.for_user(request.user).filter(status=status).order_by('-updated_at')
        else:
            alerts_list = Alert.objects.for_user(request.user).filter(status__in=["new", "read"]).order_by('-updated_at')

    if severity in ["info", "low", "medium", "high", "critical"]:
        alerts_list = alerts_list.filter(severity=severity)

    nb_alerts = alerts_list.count()
    # Pagination assets
    nb_rows = int(request.GET.get('n', 20))
    alert_paginator = Paginator(alerts_list, nb_rows)
    page = request.GET.get('p_alerts', 1)
    try:
        alerts = alert_paginator.page(page)
    except PageNotAnInteger:
        alerts = alert_paginator.page(1)
    except EmptyPage:
        alerts = alert_paginator.page(alert_paginator.num_pages)

    return render(request, 'list-alerts.html', {
        'alerts': alerts,
        'nb_alerts': nb_alerts,
        'teams': teams
    })
