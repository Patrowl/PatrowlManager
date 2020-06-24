# -*- coding: utf-8 -*-

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import JSONField
from django.db.models import Q
from django.conf import settings
from app.settings import LOGGING_LEVEL

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
    # scan = models.ForeignKey('scans.Scan', null=True, blank=True, on_delete=models.SET_NULL, related_name="event_scan")
    # finding = models.ForeignKey('findings.Finding', null=True, blank=True, on_delete=models.SET_NULL, related_name="event_finding")
    # rawfinding = models.ForeignKey('findings.RawFinding', null=True, blank=True, on_delete=models.SET_NULL, related_name="event_rawfinding")
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
            )
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
