# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Rule, AlertRule

admin.site.register(Rule)
admin.site.register(AlertRule)
