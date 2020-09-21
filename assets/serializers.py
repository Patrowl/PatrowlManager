# -*- coding: utf-8 -*-

from rest_framework import serializers, generics
from common.utils.pagination import StandardResultsSetPagination
from django.utils.translation import gettext_lazy as _
from django_filters import rest_framework as filters
from django_filters import FilterSet, OrderingFilter
from .models import Asset, AssetGroup


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = ('id', 'value', 'name', 'type', 'owner', 'description',
            'criticity', 'status', 'created_at', 'updated_at', 'teams', 'exposure')


class AssetFilter(FilterSet):
    sorted_by = OrderingFilter(
        # tuple-mapping retains order
        choices=(
            ('value', _('Value')),
            ('-value', _('Value (desc)')),
            ('name', _('Name')),
            ('-name', _('Name (desc)')),
            ('criticity', _('Criticity')),
            ('-criticity', _('Criticity (desc)')),
            ('type', _('Type')),
            ('-type', _('Type (desc)')),
            ('exposure', _('Exposure')),
            ('-exposure', _('Exposure (desc)')),
        )
    )

    class Meta:
        model = Asset
        fields = {
            'name': ['icontains'],
            'value': ['icontains'],
            'description': ['icontains'],
        }


class AssetList(generics.ListAPIView):
    serializer_class = AssetSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = AssetFilter
    filterset_fields = ('id', 'name', 'value', 'criticity', 'type')
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        return Asset.objects.for_user(self.request.user).all().order_by('value')


class AssetGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = AssetGroup
        fields = ('id', 'name', 'owner', 'description', 'assets',
            'criticity', 'created_at', 'updated_at', 'teams')


class AssetGroupFilter(FilterSet):
    sorted_by = OrderingFilter(
        choices=(
            ('name', _('Name')),
            ('-name', _('Name (desc)')),
            ('criticity', _('Criticity')),
            ('-criticity', _('Criticity (desc)')),
        )
    )

    class Meta:
        model = AssetGroup
        fields = {
            'name': ['icontains'],
            'description': ['icontains'],
        }


class AssetGroupList(generics.ListAPIView):
    serializer_class = AssetGroupSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = AssetGroupFilter
    filterset_fields = ('id', 'name', 'criticity')
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        return AssetGroup.objects.for_user(self.request.user).all().order_by('name')
