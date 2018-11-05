"""View and API definitions for Settings."""

from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

from .models import Setting
from events.models import Event

import json
import csv
import base64

# Create your views here.


def show_settings_menu(request):
    """View: List settings menus."""
    from cursor_pagination import CursorPaginator

    users = User.objects.all()
    settings = Setting.objects.all().order_by("key")
    events_list = Event.objects.all()
    # events_list = Event.objects.all().order_by("-id")

    nb_rows = int(request.GET.get('n', 16))
    # events_paginator = CursorPaginator(events_list, ordering=('id',))
    events_paginator = CursorPaginator(events_list, ordering=['id'])
    page_events = request.GET.get('p_events', 1)
    if type(page_events) == 'unicode' and not page_events.isnumeric():
        page_events = 1
    else:
        page_events = int(page_events)
    if page_events > 0:
        after = base64.b64encode(str((page_events-1)*nb_rows))
    else:
        after = base64.b64encode("0")

    events = events_paginator.page(first=nb_rows, after=after)
    #events = events_paginator.page(first=nb_rows, before=after)

    has_previous = after is not None and base64.b64decode(after) > "0"

    previous_decoded_cursor = "1"
    if after is not None and base64.b64decode(after) > "0":
        previous_decoded_cursor = page_events - 1
    next_decoded_cursor = "1"
    if events.has_next:
        next_decoded_cursor = page_events + 1

    return render(request, 'menu-settings.html', {
        'users': users,
        'settings': settings,
        'events': events,
        'events_page_info': {
            'end_cursor': events_list.count()//nb_rows,
            'has_previous': has_previous,
            'has_next': events.has_next,
            'next_page_number': next_decoded_cursor,
            'previous_page_number': previous_decoded_cursor
        }
    })


@csrf_exempt
def update_setting_api(request):
    """API: Update a setting value."""
    if not request.POST:
        return JsonResponse(data={'status': 'error'}, status=403)

    setting_id = json.loads(request.body)["setting_id"]
    setting = get_object_or_404(Setting, id=setting_id)
    setting.value = json.loads(request.body)["setting_value"]
    setting.save(force_update=True)
    messages.success(request, 'Setting successfully updated!')

    return JsonResponse({'status': 'success'})


@csrf_exempt
def add_setting_api(request):
    """API: Add a setting key/value."""
    if not request.POST:
        return JsonResponse(data={'status': 'error'}, status=403)

    setting_key = json.loads(request.body)["setting_key"]
    if Setting.objects.filter(key=setting_key).count() == 0:
        new_settings_args = {
            "key": json.loads(request.body)["setting_key"],
            "value": json.loads(request.body)["setting_value"],
            "comments": "n/a",
        }
        new_setting = Setting.objects.create(**new_settings_args)
        new_setting.save()

        messages.success(request, 'Setting successfully updated!')

        return JsonResponse({'status': 'success'})

    return JsonResponse(data={'status': 'error'}, status=403)


def delete_setting_api(request, setting_id):
    """API: Delete a setting key/value."""
    setting = get_object_or_404(Setting, id=setting_id)
    setting.delete()
    messages.success(request, 'Setting successfully deleted!')

    return JsonResponse({'status': 'success'})


def export_settings_api(request):
    """API: Export settings."""
    response = HttpResponse(content_type='text/csv')
    filename = "patrowl_settings.csv"
    response['Content-Disposition'] = 'attachment; filename=' + filename
    writer = csv.writer(response, delimiter=';')

    settings = Setting.objects.all()

    writer.writerow(['keys', 'values', 'comments'])
    for setting in settings:
        writer.writerow([setting.key, setting.value, setting.comments])

    return response


def import_settings_api(request):
    """API: Export settings."""
    pass
