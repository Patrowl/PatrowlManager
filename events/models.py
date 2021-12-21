# -*- coding: utf-8 -*-

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import JSONField
from django.db.models import Q
from django.conf import settings
from app.settings import LOGGING_LEVEL

SEVERITY_LEVELS = (
    ('INFO', 'INFO'),
    ('WARNING', 'WARNING'),
    ('ERROR', 'ERROR'),
    ('DEBUG', 'DEBUG')
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
    """Class definition of Event."""

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
        """Metadata options."""

        db_table = 'events'

    def __str__(self):
        """Return string representation of an Event."""
        return "[{}] {} - {} - {}".format(self.severity, self.message, self.code, self.created_at)

    def save(self, *args, **kwargs):
        """Override save method."""
        if self.severity in LOGGING_LEVEL.split(','):
            self.message = self.message[:250]  # Just to be sure ...
            return super(Event, self).save(*args, **kwargs)


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

ALERT_TYPES = (
    ('other', 'Other'),
    ('new_finding', 'New Finding'),
    ('missing_finding', 'Missing Finding'),
    ('reopened_finding', 'Reopened Finding'),
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
    type = models.CharField(choices=ALERT_TYPES, default='other', max_length=20)
    owner = models.ForeignKey(get_user_model(), null=True, on_delete=models.SET_NULL)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    teams = models.ManyToManyField('users.team', blank=True)

    class Meta:
        """Metadata options."""

        db_table = 'alerts'

    def __str__(self):
        """Return string representation of an Alert."""
        return "[{}] {} - {} - {}".format(self.severity, self.message, self.status, self.created_at)

    def save(self, *args, **kwargs):
        """Override save method."""
        self.message = self.message[:250]  # Just to be sure ...
        return super(Alert, self).save(*args, **kwargs)


ALERT_OVERRIDE_ACTIONS = (
    ('disable-alert', 'Disable alert'),
    ('set-severity', 'Set custom severity'),
)

ALERT_OVERRIDE_PARAMS = {
    'disable-alert': {
        'filters': {
            'title__icontains': '###CHANGEME###',
        },
        'actions': {
            'disable-alert': True,
        },
    },
    'set-severity': {
        'filters': {
            'title__icontains': '###CHANGEME###',
        },
        'actions': {
            'final_severity': 'info',
        },
    },
}


def get_default_alert_override_params():
    """Return default alert overriding parameters."""
    return dict(ALERT_OVERRIDE_PARAMS['disable-alert'])


class AlertOverride(models.Model):
    """Class definition of AlertOverride."""

    # Manager
    objects = AlertManager()

    # Attributes
    name = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)
    engine_type = models.CharField(max_length=20)
    action = models.CharField(choices=ALERT_OVERRIDE_ACTIONS, default="disable-alert", max_length=32)
    params = JSONField(default=get_default_alert_override_params)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)
    teams = models.ManyToManyField('users.team', blank=True)

    class Meta:
        """Metadata options."""

        db_table = 'alert_override'

    def __str__(self):
        """Return string representation of an AlertOverride."""
        return "{}/{}".format(self.id, self.name)

    def save(self, *args, **kwargs):
        """Update timestamp is not created."""
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(AlertOverride, self).save(*args, **kwargs)


AUDIT_SCOPES = (
    ('asset', 'Asset'),
    ('scan', 'Scan'),
    ('engine', 'Engine'),
    ('finding', 'Finding'),
    ('user', 'User'),
    ('rule', 'Rule'),
    ('setting', 'Setting'),
    ('other', 'Other')
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
        """Metadata options."""

        db_table = 'audit_logs'

    def __init__(self, *args, **kwargs):
        self.context = kwargs.pop('context', None)
        self.request_context = kwargs.pop('request_context', None)
        return super(AuditLog, self).__init__(*args, **kwargs)

    def __str__(self):
        """Return string representation of an AuditLog."""
        return "{}/{}: {} ({})".format(self.scope, self.owner, self.message, self.created_at)

    def save(self, *args, **kwargs):
        """Override save method."""
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
