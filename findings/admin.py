# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Finding, RawFinding, FindingOverride


class FindingAdmin(admin.ModelAdmin):
    raw_id_fields = ('raw_finding', 'asset', 'scan',)


class RawFindingAdmin(admin.ModelAdmin):
    raw_id_fields = ('asset', 'scan',)


admin.site.register(Finding, FindingAdmin)
admin.site.register(RawFinding, RawFindingAdmin)
admin.site.register(FindingOverride)
