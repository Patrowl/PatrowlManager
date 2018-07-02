from django.shortcuts import render, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt


from .models import Setting

import json, csv

# Create your views here.


def show_settings_menu(request):
    users = User.objects.all()
    settings = Setting.objects.all().order_by("key")

    return render(request, 'menu-settings.html', {
        'users': users,
        'settings': settings})

@csrf_exempt
def update_setting_api(request):
    if not request.POST:
        return JsonResponse(data={'status': 'error'}, status=403)

    setting_id = json.loads(request.body)["setting_id"]
    setting = get_object_or_404(Setting, id=setting_id)
    setting.value=json.loads(request.body)["setting_value"]
    setting.save(force_update=True)
    messages.success(request, 'Setting successfully updated!')

    return JsonResponse({'status': 'success'})


@csrf_exempt
def add_setting_api(request):
    if not request.POST:
        return JsonResponse(data={'status': 'error'}, status=403)

    if Setting.objects.filter(key=json.loads(request.body)["setting_key"]).count() == 0:
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
    setting = get_object_or_404(Setting, id=setting_id)
    setting.delete()
    messages.success(request, 'Setting successfully deleted!')

    return JsonResponse({'status': 'success'})


def export_settings_api(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="patrowl_settings.csv"'
    writer = csv.writer(response, delimiter=';')

    settings = Setting.objects.all()

    writer.writerow(['keys', 'values', 'comments'])
    for setting in settings:
        writer.writerow([setting.key, setting.value, setting.comments])

    return response


def import_settings_api(request):
    pass
