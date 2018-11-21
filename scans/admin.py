# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Scan, ScanCampaign, ScanDefinition

admin.site.register(Scan)
admin.site.register(ScanCampaign)
admin.site.register(ScanDefinition)
