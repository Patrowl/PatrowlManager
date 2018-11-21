# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Finding, RawFinding

admin.site.register(Finding)
admin.site.register(RawFinding)
