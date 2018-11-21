# -*- coding: utf-8 -*-

from django.contrib import admin

# Register your models here.
from .models import Asset, AssetGroup, AssetOwner, AssetOwnerContact, AssetOwnerDocument, AssetCategory

admin.site.register(Asset)
admin.site.register(AssetGroup)
admin.site.register(AssetOwner)
admin.site.register(AssetOwnerContact)
admin.site.register(AssetOwnerDocument)
admin.site.register(AssetCategory)
