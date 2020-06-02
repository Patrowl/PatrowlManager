# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Event, Alert

admin.site.register(Event)
admin.site.register(Alert)
