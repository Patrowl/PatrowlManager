from rest_framework import serializers, generics
from django_filters import rest_framework as filters
from .models import Finding, RawFinding


class FindingSerializer(serializers.ModelSerializer):
    scopes_list = serializers.SerializerMethodField()

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
            'scopes_list'
        ]


class FindingList(generics.ListAPIView):
    queryset = Finding.objects.all()
    serializer_class = FindingSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('title', 'severity', 'engine_type')


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
    queryset = RawFinding.objects.all()
    serializer_class = RawFindingSerializer
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_fields = ('title', 'severity', 'engine_type')
