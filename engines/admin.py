# -*- coding: utf-8 -*-

from django.contrib import admin
from .models import Engine, EngineInstance, EnginePolicy, EnginePolicyScope

admin.site.register(Engine)
admin.site.register(EngineInstance)
admin.site.register(EnginePolicy)
admin.site.register(EnginePolicyScope)
