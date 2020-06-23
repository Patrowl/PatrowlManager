# -*- coding: utf-8 -*-

from django.contrib import admin

# Register your models here.
from .models import Profile, Team, TeamUser, TeamOwner

admin.site.register(Profile)
admin.site.register(Team)
admin.site.register(TeamUser)
admin.site.register(TeamOwner)
