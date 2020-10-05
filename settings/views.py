# -*- coding: utf-8 -*-
"""View and API definitions for Settings."""

from django.shortcuts import render
# from django.contrib.auth.models import User
from django.contrib.auth import get_user_model
from django.db.models import F
from .models import Setting
from events.models import Event
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger


def show_settings_menu(request):
    """View: List settings menus."""
    users = get_user_model().objects.all().annotate(apitoken=F('auth_token'))
    settings = Setting.objects.all().order_by("key")
    events_list = Event.objects.all().order_by("-id")

    nb_events_rows = int(request.GET.get('n_events', 25))
    # events_paginator = CursorPaginator(events_list, ordering=['-id'])
    page_events = request.GET.get('p_events', 1)
    paginator_events = Paginator(events_list, nb_events_rows)
    try:
        events = paginator_events.page(page_events)
    except PageNotAnInteger:
        events = paginator_events.page(1)
    except EmptyPage:
        events = paginator_events.page(paginator_events.num_pages)

    return render(request, 'menu-settings.html', {
        'users': users,
        'settings': settings,
        'events': events
    })


def show_support_page(request):
    """View: Support page."""
    return render(request, 'support.html')
