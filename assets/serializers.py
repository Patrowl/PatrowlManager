from rest_framework import serializers
from .models import Asset
from django.contrib.auth.models import User


class AssetSerializer(serializers.Serializer):
    asset_id = serializers.UUIDField(read_only=True)
    #asset_id = serializers.IntegerField(read_only=True)
    value = serializers.CharField(required=False)
    name = serializers.CharField(required=False)
    type = serializers.CharField(required=False)
    #owner = serializers.CharField(required=False)
    owner_id = serializers.ReadOnlyField(source='owner.id')
    description = serializers.CharField(required=False)
    status = serializers.CharField(required=False)
    created_at = serializers.DateTimeField(required=False)
    updated_at = serializers.DateTimeField(required=False)


    def create(self, validated_data):
        return Asset.objects.create(**validated_data)

    def update(self, instance, validated_data):
        instance.value = validated_data.get('value', instance.value)
        instance.name = validated_data.get('name', instance.name)
        instance.type = validated_data.get('type', instance.type)
        instance.owner = validated_data.get('owner', instance.owner)
        instance.description = validated_data.get('description', instance.description)
        instance.status = validated_data.get('status', instance.status)
        instance.save()
        return instance

    class Meta:
        model = Asset

# class AssetSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Asset
#         fields = ('asset_id', 'value', 'name', 'type', 'owner', 'description',
#                   'status', 'created_at', 'updated_at')
