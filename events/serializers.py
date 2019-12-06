from rest_framework import serializers, generics
from .models import Event


class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        # fields = '__all__'
        fields = [
            'id',
            'message',
            'description',
            'type',
            'severity',
            'code',
            'created_at',
            'updated_at',
            'scan_id',
            'finding_id',
            'rawfinding_id'
        ]


class EventListCreate(generics.ListCreateAPIView):
    queryset = Event.objects.all()
    serializer_class = EventSerializer
