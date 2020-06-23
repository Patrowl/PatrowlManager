from rest_framework import serializers, generics
from django_filters import rest_framework as filters
from django_filters import FilterSet, OrderingFilter
from django.utils.translation import gettext_lazy as _
from .models import Finding, RawFinding


class FindingSerializer(serializers.ModelSerializer):
    # scopes_list = serializers.SerializerMethodField()

    def get_scopes_list(self, instance):
        names = []
        a = instance.scopes.get_queryset().only("name")
        for i in a:
            names.append(i.name)
        return names

    class Meta:
        model = Finding
        fields = [
            'id',
            'title',
            'type',
            'hash',
            'severity',
            'confidence',
            'description',
            'solution',
            'comments',
            'risk_info',
            'vuln_refs',
            'links',
            'tags',
            'status',
            'engine_type',
            'found_at',
            'checked_at',
            'created_at',
            'updated_at',
            'asset_id',
            'asset_name',
            'raw_finding_id',
            'scan_id',
            # 'scopes',
            # 'scopes_list'
        ]


class FindingFilter(FilterSet):
    sorted_by = OrderingFilter(
        # tuple-mapping retains order
        choices=(
            ('title', _('Title')),
            ('-title', _('Title (desc)')),
            ('asset_name', _('Asset')),
            ('-asset_name', _('Asset (desc)')),
            ('severity', _('Severity')),
            ('-severity', _('Severity (desc)')),
            ('status', _('Status')),
            ('-status', _('Status (desc)')),
            ('engine_type', _('Engine')),
            ('-engine_type', _('Engine (desc)')),
        )
    )

    class Meta:
        model = Finding
        fields = {
            'title': ['icontains'],
            'description': ['icontains'],
            'asset_name': ['icontains'],
        }


class FindingList(generics.ListAPIView):
    # queryset = Finding.objects.all().order_by('title')
    serializer_class = FindingSerializer
    filterset_class = FindingFilter
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('title', 'severity', 'engine_type')

    def get_queryset(self):
        return Finding.objects.for_user(self.request.user).all().order_by('title')


class RawFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = Finding
        fields = [
            'id',
            'title',
            'type',
            'hash',
            'severity',
            'confidence',
            'description',
            'solution',
            'comments',
            'risk_info',
            'vuln_refs',
            'links',
            'tags',
            'status',
            'engine_type',
            'found_at',
            'checked_at',
            'created_at',
            'updated_at',
            'asset_id',
            'asset_name',
            'scopes',
            'scan_id',
        ]


class RawFindingList(generics.ListCreateAPIView):
    # queryset = RawFinding.objects.all().order_by('title')
    serializer_class = RawFindingSerializer
    filterset_class = FindingFilter
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('title', 'severity', 'engine_type')

    def get_queryset(self):
        return RawFinding.objects.for_user(self.request.user).all().order_by('title')
