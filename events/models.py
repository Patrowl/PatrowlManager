# -*- coding: utf-8 -*-

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import JSONField
from django.db.models import Q
from django.conf import settings
from app.settings import LOGGING_LEVEL
from django.db.models import Value
from django.db.models.functions import Concat


import json
import operator
from functools import reduce

from django.apps import apps


SEVERITY_LEVELS = (
    ('INFO',    'INFO'),
    ('WARNING', 'WARNING'),
    ('ERROR',   'ERROR'),
    ('DEBUG',   'DEBUG')
)

EVENT_TYPES = (
    ('CREATE', 'CREATE'),
    ('UPDATE', 'UPDATE'),
    ('DELETE', 'DELETE'),
    ('ERROR', 'ERROR'),
    ('NOTIFICATION', 'NOTIFICATION'),
    ('ALERT', 'ALERT'),
    ('UNSPECIFIED', 'UNSPECIFIED'),
)


class Event(models.Model):
    message = models.CharField(max_length=250)
    description = models.TextField(default="n/a")
    type = models.CharField(choices=EVENT_TYPES, default='UNSPECIFIED', max_length=15)
    severity = models.CharField(choices=SEVERITY_LEVELS, default='INFO', max_length=10)
    code = models.CharField(max_length=10, null=True, blank=True)
    scan = models.ForeignKey('scans.Scan', null=True, blank=True, on_delete=models.SET_NULL)
    finding = models.ForeignKey('findings.Finding', null=True, blank=True, on_delete=models.SET_NULL)
    rawfinding = models.ForeignKey('findings.RawFinding', null=True, blank=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'events'

    def __str__(self):
        return "[{}] {} - {} - {}".format(self.severity, self.message, self.code, self.created_at)

    def save(self, *args, **kwargs):
        if self.severity in LOGGING_LEVEL.split(','):
            self.message = self.message[:250]  # Just to be sure ...
            return super(Event, self).save(*args, **kwargs)

## Alerts
# Alerts are notification messages displayed on several events:
# - New finding detected
# - A finding is missing between 2 scans
# - A finding reapears
# - A finding changed (ex: score)
# ?- A scan is finished (success / fail)
# ?- An engine changed its operational status

#
# ALERT_TYPES = (
#     ('NEW_FINDING', 'New Finding'),
#     ('MISSING_FINDING', 'Missing Finding'),
#     ('CHANGE_FINDING', 'Finding change'),
# )


ALERT_SEVERITIES = (
    ('info', 'info'),
    ('low', 'low'),
    ('medium', 'medium'),
    ('high', 'high'),
    ('critical', 'critical'),
)

ALERT_STATUSES = (
    ('new', 'New'),
    ('read', 'Read'),
    ('archived', 'Archived'),
)


class AlertManager(models.Manager):
    """Class definition of AlertManager."""

    def for_user(self, user):
        """Check if user is allowed to manage the object."""
        if settings.PRO_EDITION and not user.is_superuser:
            return super().get_queryset().filter(
                Q(teams__in=user.users_team.all(), teams__is_active=True) |
                Q(owner=user)
            ).distinct()
        return super().get_queryset()

    def for_team(self, user, team):
        """Check if user is allowed to manage the object in a team."""
        if settings.PRO_EDITION:
            if user.is_superuser:
                return super().get_queryset().filter(
                    teams__in=[team],
                    teams__is_active=True).distinct()
            else:
                return super().get_queryset().filter(
                    teams__in=user.users_team.filter(id=team),
                    teams__is_active=True).distinct()
        return super().get_queryset()


class Alert(models.Model):
    """Class definition of Alert."""

    # Manager
    objects = AlertManager()

    # Attributes
    message = models.CharField(max_length=250)
    severity = models.CharField(choices=ALERT_SEVERITIES, default='info', max_length=10)
    status = models.CharField(choices=ALERT_STATUSES, default='new', max_length=10)
    metadata = JSONField(default=dict)
    owner = models.ForeignKey(get_user_model(), null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    teams = models.ManyToManyField('users.team', blank=True)

    class Meta:
        db_table = 'alerts'

    def __str__(self):
        return "[{}] {} - {} - {}".format(self.severity, self.message, self.status, self.created_at)

    def save(self, *args, **kwargs):
        self.message = self.message[:250]  # Just to be sure ...
        return super(Alert, self).save(*args, **kwargs)

    def evaluate_alert_rules(self, trigger='all'):
        Rule = apps.get_model(app_label='rules', model_name='Rule')
        Asset = apps.get_model(app_label='assets', model_name='Asset')
        if trigger == "all":
            rules = Rule.objects.filter(enabled=True, scope='alert')
        else:
            rules = Rule.objects.filter(enabled=True, scope='alert', trigger=trigger)
        nb_matches = 0
        kwargs =[]
        for rule in rules:
            kwargs.append(Q(**{'id': self.id}))
            # kwargs = {
            #     "id": self.id,
            #     # rule.scope_attr+next(iter(rule.condition)): rule.condition.itervalues().next()
            # }
            if rule.scope_attr =="title":
                scope_attr = "concated"
            else:
                scope_attr ="concated"
            try:
                conv = json.loads(rule.condition)
                for line in conv:
                    for key, value in line.items():
                        kwargs.append(Q(**{scope_attr + key: value}))
                        # kwargs[rule.scope_attr + key]=value
            except:
                conv = rule.condition
                for key, value in conv.items():
                    kwargs.append(Q(**{rule.scope_attr + key: value}))
                    #kwargs[rule.scope_attr + key]=value

            if Alert.objects.annotate(concated=Concat('message', Value(' '), 'metadata__finding_title', Value(' '), output_field=models.CharField(),)).filter(reduce(operator.and_, kwargs)):
                nb_matches += 1
                asset = Asset.objects.get(id=self.metadata.get('asset_id'))
                rule.notify(message="", asset=asset, description="")
        return nb_matches


AUDIT_SCOPES = (
    ('asset',   'Asset'),
    ('scan',    'Scan'),
    ('engine',  'Engine'),
    ('finding', 'Finding'),
    ('user',    'User'),
    ('rule',    'Rule'),
    ('setting', 'Setting'),
    ('other',   'Other')
)


class AuditLog(models.Model):
    """Class definition of AuditLog."""

    # Attributes
    message = models.TextField(default="n/a")
    scope = models.CharField(choices=AUDIT_SCOPES, default='other', max_length=10)
    type = models.CharField(default='n-a', max_length=250)
    owner = models.ForeignKey(get_user_model(), null=True, on_delete=models.SET_NULL)
    owner_username = models.TextField(default="n/a")
    metadata = models.TextField(default="")
    created_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'audit_logs'

    def __init__(self, *args, **kwargs):
        self.context = kwargs.pop('context', None)
        self.request_context = kwargs.pop('request_context', None)
        return super(AuditLog, self).__init__(*args, **kwargs)

    def __str__(self):
        return "{}/{}: {} ({})".format(self.scope, self.owner, self.message, self.created_at)

    def save(self, *args, **kwargs):

        # Metadata
        try:
            if hasattr(self, 'context') and self.context is not None:
                self.metadata += "PATH_INFO: {}\n".format(self.context.META.get('PATH_INFO', None))
                self.metadata += "REQUEST_METHOD: {}\n".format(self.context.META.get('REQUEST_METHOD', None))
                self.metadata += "QUERY_STRING: {}\n".format(self.context.META.get('QUERY_STRING', None))
                self.metadata += "CONTENT_TYPE: {}\n".format(self.context.META.get('CONTENT_TYPE', None))
                self.metadata += "REMOTE_ADDR: {}\n".format(self.context.META.get('REMOTE_ADDR', None))
                self.metadata += "HTTP_USER_AGENT: {}\n".format(self.context.META.get('HTTP_USER_AGENT', None))
                self.metadata += "HTTP_REFERER: {}".format(self.context.META.get('HTTP_REFERER', None))
        except Exception:
            pass

        # User
        try:
            for frame_record in self.request_context:
                if frame_record[3] == 'get_response':
                    self.owner = frame_record[0].f_locals['request'].user
                    break
        except Exception:
            pass

        # Username
        try:
            self.owner_username = self.owner.username
        except Exception:
            pass
        return super(AuditLog, self).save(*args, **kwargs)
