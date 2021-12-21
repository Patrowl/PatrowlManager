# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Scan, ScanCampaign, ScanDefinition


class ScanAssetInline(admin.TabularInline):
    model = Scan.assets.through


class ScanAdmin(admin.ModelAdmin):
    raw_id_fields = ('scan_definition',)
    exclude = ('assets',)
    inlines = [
        ScanAssetInline,
    ]


class ScanDefAssetInline(admin.TabularInline):
    model = ScanDefinition.assets_list.through


class ScanDefAssetGroupInline(admin.TabularInline):
    model = ScanDefinition.assetgroups_list.through


class ScanDefTagGroupInline(admin.TabularInline):
    model = ScanDefinition.taggroups_list.through


class ScanDefAdmin(admin.ModelAdmin):
    exclude = ('assets_list', 'assetgroups_list', 'taggroups_list',)
    inlines = [
        ScanDefAssetInline, ScanDefAssetGroupInline, ScanDefTagGroupInline
    ]


admin.site.register(Scan, ScanAdmin)
admin.site.register(ScanCampaign)
admin.site.register(ScanDefinition, ScanDefAdmin)
