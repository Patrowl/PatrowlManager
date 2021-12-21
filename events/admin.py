# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Event, Alert, AlertOverride

admin.site.register(Event)
admin.site.register(Alert)
admin.site.register(AlertOverride)
