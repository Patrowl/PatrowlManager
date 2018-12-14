# -*- coding: utf-8 -*-

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib.auth.models import User
from rest_framework.decorators import api_view


@api_view(['GET'])
def user_details_api(request, user_id):
    user = get_object_or_404(User, id=user_id)
    return JsonResponse(user, safe=False)


@api_view(['GET'])
def list_users_api(request):
    users = User.objects.all()
    return JsonResponse(users, safe=False)
