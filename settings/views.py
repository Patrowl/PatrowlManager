# -*- coding: utf-8 -*-
"""View and API definitions for Settings."""

from django.shortcuts import render
from django.contrib.auth.models import User
from django.db.models import F
from django.db import connection
from .models import Setting
from events.models import Event

import base64


def show_settings_menu(request):
    """View: List settings menus."""
    from cursor_pagination import CursorPaginator

    users = User.objects.all().annotate(apitoken=F('auth_token'))
    settings = Setting.objects.all().order_by("key")
    events_list = Event.objects.all()

    nb_rows = int(request.GET.get('n', 16))
    events_paginator = CursorPaginator(events_list, ordering=['id'])
    page_events = request.GET.get('p_events', 1)
    if type(page_events) == 'unicode' and not page_events.isnumeric():
        page_events = 1
    else:
        page_events = int(page_events)
    if page_events > 1:
        after = base64.b64encode(str((page_events-1)*nb_rows).encode()).decode("UTF-8")
    else:
        after = None

    events = events_paginator.page(first=nb_rows, after=after)
    has_previous = after is not None and base64.b64decode(after) > b"0"
    previous_decoded_cursor = "1"
    if after is not None and base64.b64decode(after) > b"0":
        previous_decoded_cursor = page_events - 1
    next_decoded_cursor = "1"
    if events.has_next:
        next_decoded_cursor = page_events + 1

    # Estimate number or events
    cursor = connection.cursor()
    cursor.execute("SELECT reltuples FROM pg_class WHERE relname = 'events'")
    nb_events = int(cursor.fetchone()[0])

    return render(request, 'menu-settings.html', {
        'users': users,
        'settings': settings,
        'events': events,
        'events_page_info': {
            'end_cursor': nb_events//(nb_rows),
            'has_previous': has_previous,
            'has_next': events.has_next,
            'next_page_number': next_decoded_cursor,
            'previous_page_number': previous_decoded_cursor
        }
    })
