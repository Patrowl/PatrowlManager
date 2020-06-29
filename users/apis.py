# -*- coding: utf-8 -*-

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token
from django.forms.models import model_to_dict


@api_view(['GET'])
def user_details_api(request, user_id):
    user = get_object_or_404(get_user_model(), id=user_id)
    res = model_to_dict(user, exclude=['groups', 'password'])
    res.update({
        "teams": list(user.users_team.values("id", "name"))
    })
    return JsonResponse(res, safe=False)


@api_view(['GET'])
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
def delete_user_api(request, user_id):
    user = get_object_or_404(get_user_model(), id=user_id)
    user.delete()
    return JsonResponse({'status': 'deleted'})


# Auth token management
@api_view(['GET'])
def get_curruser_authtoken_api(request):
    token = Token.objects.get_or_create(user=request.user)[0]
    return JsonResponse({"token": token.key})


@api_view(['GET'])
def get_user_authtoken_api(request, user_id):
    uid = get_object_or_404(get_user_model(), id=user_id)
    token = Token.objects.get_or_create(user=uid)[0]
    return JsonResponse({"token": token.key})


@api_view(['GET'])
def delete_curruser_authtoken_api(request):
    for token in Token.objects.filter(user=request.user):
        token.delete()
    return JsonResponse({})


@api_view(['GET'])
def delete_user_authtoken_api(request, user_id):
    uid = get_object_or_404(get_user_model(), id=user_id)
    for token in Token.objects.filter(user=uid):
        token.delete()
    return JsonResponse({})


@api_view(['GET'])
def renew_curruser_authtoken_api(request):
    for token in Token.objects.filter(user=request.user):
        token.delete()
    token = Token.objects.get_or_create(user=request.user)[0]
    return JsonResponse({"token": token.key})


@api_view(['GET'])
def renew_user_authtoken_api(request, user_id):
    uid = get_object_or_404(get_user_model(), id=user_id)
    for token in Token.objects.filter(user=uid):
        token.delete()
    token = Token.objects.get_or_create(user=uid)[0]
    return JsonResponse({"token": token.key})
