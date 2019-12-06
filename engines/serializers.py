from rest_framework import serializers, generics
from .models import EnginePolicyScope


class EnginePolicyScopeSerializer(serializers.ModelSerializer):
    class Meta:
        model = EnginePolicyScope
        # fields = '__all__'
        fields = [
            'id',
            'name',
            'priority',
            'created_at',
            'updated_at'
        ]


class EnginePolicyScopeListCreate(generics.ListCreateAPIView):
    queryset = EnginePolicyScope.objects.all()
    serializer_class = EnginePolicyScopeSerializer
