# -*- coding: utf-8 -*-

from rest_framework import serializers
from assets.models import Asset
from django.contrib.auth.models import User


class UserSerializer(serializers.HyperlinkedModelSerializer):
    assets = serializers.HyperlinkedRelatedField(queryset=Asset.objects.using('db').all(), view_name='asset-detail', many=True)

    class Meta:
        model = User
        fields = ('url', 'username', 'assets')
