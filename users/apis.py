# -*- coding: utf-8 -*-

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework.authtoken.models import Token


@api_view(['GET'])
def user_details_api(request, user_id):
    user = get_object_or_404(User, id=user_id)
    return JsonResponse(user, safe=False)


@api_view(['GET'])
def list_users_api(request):
    users = User.objects.all()
    return JsonResponse(users, safe=False)


@api_view(['GET'])
def get_user_authtoken(request):
    token = Token.objects.get_or_create(user=request.user)[0]
    return JsonResponse({"token": token.key})


@api_view(['GET'])
def delete_user_authtoken(request):
    for token in Token.objects.filter(user=request.user):
        token.delete()
    return JsonResponse({})


@api_view(['GET'])
def renew_user_authtoken(request):
    for token in Token.objects.filter(user=request.user):
        token.delete()
    token = Token.objects.get_or_create(user=request.user)[0]
    return JsonResponse({"token": token.key})
