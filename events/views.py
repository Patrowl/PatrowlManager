# -*- coding: utf-8 -*-

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse
from django.forms.models import model_to_dict
from django.contrib import messages
from .models import Event


# Create your views here.
def list_events(request):
    events = []
    for e in Event.objects.all():
        events.append(model_to_dict(e))

    return JsonResponse({"data": events}, json_dumps_params={'indent': 2}, safe=False)


def delete_event_view(request, event_id):
    event = get_object_or_404(Event, id=event_id)
    if request.method == 'POST':
        event.delete()

        # reevaluate related asset critity
        messages.success(request, 'Event successfully deleted!')
    return render(request, 'delete-event.html', {'event': event})
