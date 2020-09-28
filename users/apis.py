# -*- coding: utf-8 -*-

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.forms.models import model_to_dict
from django_celery_beat.models import PeriodicTask
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token
from common.utils import pro_group_required
from common.utils.password import get_random_alphanumeric_string
from events.models import AuditLog, Alert
from rules.models import Rule
from findings.models import Finding, RawFinding
from scans.utils import _update_celerybeat


@api_view(['GET'])
@pro_group_required('UsersManager')
def user_details_api(request, user_id):
    user = get_object_or_404(get_user_model(), id=user_id)
    res = model_to_dict(user, exclude=['groups', 'password'])
    res.update({
        "teams": list(user.users_team.values("id", "name"))
    })
    return JsonResponse(res, safe=False)


@api_view(['GET'])
# @pro_group_required('UsersManager')
def list_users_api(request):
    users = []
    for user in get_user_model().objects.all().order_by('username'):
        udata = model_to_dict(user, exclude=['groups', 'password'])
        udata.update({
            "teams": list(user.users_team.values("id", "name"))
        })
        users.append(udata)
    return JsonResponse(users, safe=False)


@api_view(['GET'])
@pro_group_required('UsersManager')
def delete_user_api(request, user_id):
    user = get_object_or_404(get_user_model(), id=user_id)

    # Remove alerts
    user.alert_set.filter(teams__isnull=True).delete()
    Alert.objects.filter(owner=user, teams__isnull=True).delete()

    # Remove Rules
    Rule.objects.filter(owner=user).delete()

    # Remove scan definitions
    for scan_def in user.scandefinition_set.filter(teams__isnull=True):
        # Remove periodic_task if any
        try:
            periodic_task = scan_def.periodic_task
            if periodic_task:
                periodic_task.enabled = False   # maybe useless
                periodic_task.save()            # maybe useless
                periodic_task.delete()
                _update_celerybeat()
        except PeriodicTask.DoesNotExist:
            pass
        scan_def.delete()
    user.scandefinition_set.filter(teams__isnull=True).delete()

    # Remove findings and rawfindings
    Finding.objects.filter(owner=user, asset__teams__isnull=True).delete()
    RawFinding.objects.filter(owner=user, asset__teams__isnull=True).delete()

    # Remove private assets and asset groups
    user.assetgroup_set.filter(teams__isnull=True).delete()
    user.asset_set.filter(teams__isnull=True).delete()

    # Finally delete the user
    user.delete()
    return JsonResponse({'status': 'deleted'})


# Auth token management
@api_view(['GET'])
def get_curruser_authtoken_api(request):
    token = Token.objects.get_or_create(user=request.user)[0]
    return JsonResponse({"token": token.key})


@api_view(['GET'])
@pro_group_required('UsersManager')
def get_user_authtoken_api(request, user_id):
    uid = get_object_or_404(get_user_model(), id=user_id)
    token = Token.objects.get_or_create(user=uid)[0]
    return JsonResponse({"token": token.key})


@api_view(['GET'])
def delete_curruser_authtoken_api(request):
    for token in Token.objects.filter(user=request.user):
        token.delete()

    AuditLog.objects.create(
        message="Token delete for user '{}'".format(request.user),
        scope='user', type='user_curr_delete_authtoken', owner=request.user,
        context=request)
    return JsonResponse({})


@api_view(['GET'])
@pro_group_required('UsersManager')
def delete_user_authtoken_api(request, user_id):
    uid = get_object_or_404(get_user_model(), id=user_id)
    for token in Token.objects.filter(user=uid):
        token.delete()
    AuditLog.objects.create(
        message="Token delete for user '{}'".format(uid),
        scope='user', type='user_delete_authtoken', owner=request.user,
        context=request)
    return JsonResponse({})


@api_view(['GET'])
def renew_curruser_authtoken_api(request):
    for token in Token.objects.filter(user=request.user):
        token.delete()
    token = Token.objects.get_or_create(user=request.user)[0]
    AuditLog.objects.create(
        message="Token renew for user '{}'".format(request.user),
        scope='user', type='user_curr_renew_authtoken', owner=request.user,
        context=request)
    return JsonResponse({"token": token.key})


@api_view(['GET'])
@pro_group_required('UsersManager')
def renew_user_authtoken_api(request, user_id):
    uid = get_object_or_404(get_user_model(), id=user_id)
    for token in Token.objects.filter(user=uid):
        token.delete()
    token = Token.objects.get_or_create(user=uid)[0]
    AuditLog.objects.create(
        message="Token renew for user '{}'".format(uid),
        scope='user', type='user_renew_authtoken', owner=request.user,
        context=request)
    return JsonResponse({"token": token.key})


@api_view(['GET'])
@pro_group_required('UsersManager')
def renew_user_password_api(request, user_id):
    user = get_object_or_404(get_user_model(), id=user_id)
    new_password = get_random_alphanumeric_string(16)
    user.set_password(new_password)
    user.save()
    AuditLog.objects.create(
        message="Password renew for user '{}'".format(user),
        scope='user', type='user_renew_password', owner=request.user,
        context=request)
    return JsonResponse({"password": new_password})
