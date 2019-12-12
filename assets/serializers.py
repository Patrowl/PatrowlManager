# -*- coding: utf-8 -*-

from rest_framework import serializers, generics
from django_filters import rest_framework as filters
from .models import Asset
from common.utils.pagination import StandardResultsSetPagination

from django_filters import CharFilter, FilterSet

class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = ('id', 'value', 'name', 'type', 'owner', 'description',
                  'status', 'created_at', 'updated_at')


class AssetFilter(FilterSet):
    # name = CharFilter(lookup_expr='icontains')

    class Meta:
        model = Asset
        fields = {
            'name': ['icontains'],
            'value': ['icontains'],
            'description': ['icontains'],
        }


class AssetList(generics.ListAPIView):
    # queryset = Asset.objects.all()
    serializer_class = AssetSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = AssetFilter
    filterset_fields = ('id', 'name', 'value', 'criticity', 'type')
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        return Asset.objects.all().order_by('value')
