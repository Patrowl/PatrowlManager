# -*- coding: utf-8 -*-
"""View definitions for Events."""

from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from .models import Event


def delete_event_view(request, event_id):
    """Delete an event."""
    event = get_object_or_404(Event, id=event_id)
    if request.method == 'POST':
        event.delete()

        # reevaluate related asset critity
        messages.success(request, 'Event successfully deleted!')
    return render(request, 'delete-event.html', {'event': event})
