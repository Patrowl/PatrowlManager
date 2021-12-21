# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Event, Alert, AlertOverride


class EventAdmin(admin.ModelAdmin):
    raw_id_fields = ('finding', 'rawfinding', 'scan',)


admin.site.register(Event, EventAdmin)
admin.site.register(Alert)
admin.site.register(AlertOverride)
