# -*- coding: utf-8 -*-
"""View and API definitions for Settings."""

from django.shortcuts import get_object_or_404
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from rest_framework.decorators import api_view
from .models import Setting
import csv


@api_view(['POST'])
def update_setting_api(request):
    """API: Update a setting value."""
    setting_id = request.data["setting_id"]
    setting = get_object_or_404(Setting, id=setting_id)
    setting.value = request.data["setting_value"]
    setting.save(force_update=True)
    messages.success(request, 'Setting successfully updated!')

    return JsonResponse({'status': 'success'})


@api_view(['POST'])
def add_setting_api(request):
    """API: Add a setting key/value."""
    setting_key = request.data["setting_key"]
    if Setting.objects.filter(key=setting_key).count() == 0:
        new_settings_args = {
            "key": request.data["setting_key"],
            "value": request.data["setting_value"],
            "comments": "n/a",
        }
        new_setting = Setting.objects.create(**new_settings_args)
        new_setting.save()

        messages.success(request, 'Setting successfully updated!')
        return JsonResponse({'status': 'success'})

    return JsonResponse(data={'status': 'error'}, status=403)


@api_view(['GET'])
def delete_setting_api(request, setting_id):
    """API: Delete a setting key/value."""
    setting = get_object_or_404(Setting, id=setting_id)
    setting.delete()
    messages.success(request, 'Setting successfully deleted!')

    return JsonResponse({'status': 'success'})


@api_view(['GET'])
def export_settings_api(request):
    """API: Export settings."""
    response = HttpResponse(content_type='text/csv')
    filename = "patrowl_settings.csv"
    response['Content-Disposition'] = 'attachment; filename=' + filename
    writer = csv.writer(response, delimiter=';')

    settings = Setting.objects.all()

    writer.writerow(['keys', 'values', 'comments'])  # headers
    for setting in settings:
        writer.writerow([setting.key, setting.value, setting.comments])

    return response


@api_view(['GET'])
def import_settings_api(request):
    """API: Export settings."""
    # @Todo
    pass
