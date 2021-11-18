from rest_framework import serializers, generics
from .models import Event, Alert


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


class AlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = Alert
        # fields = '__all__'
        fields = [
            'id',
            'message',
            'severity',
            'status',
            'metadata',
            'created_at',
            'updated_at',
        ]


class AlertListCreate(generics.ListCreateAPIView):
    # queryset = Alert.objects.all()
    serializer_class = AlertSerializer

    def get_queryset(self):
        return Alert.objects.for_user(self.request.user).all().order_by('-updated_at')
