from django.db import models
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import JSONField
from django.db.models.signals import post_save, post_delete
from django.db.models import Q
from django.dispatch import receiver
from django.forms.models import model_to_dict
from django_celery_beat.models import PeriodicTask
from common.utils.encoding import json_serial

import os
import json
import inspect

SCAN_STATUS = ('created', 'enqueued', 'started', 'finished', 'error', 'trashed')

PERIOD_CHOICES = (
    ('days', 'Days'),
    ('hours', 'Hours'),
    ('minutes', 'Minutes'),
    ('seconds', 'Seconds'),
)

SCAN_TYPES = (
    ('single', 'single'),
    ('periodic', 'periodic'),
    ('scheduled', 'scheduled'),
)
#
# SCAN_STATUS = (
#     ('created', 'Created'),
#     ('enqueued', 'Enqueued'),
#     ('started', 'Started'),
#     ('finished', 'Finished'),
#     ('error', 'Error'),
# )

DEFAULT_SCAN_OPTIONS = {
    'assets': {
        'enable_auto_add': False
    },
    'notification': {
        'email': {
            'enable': False,
            'attach_report': False,
            'recipients': [],
            'subject': "[Patrowl] New report available",
            'condition': {
                'type': 'always',
                'criteria': None
            },
        }
    }
}


class ScanDefinitionManager(models.Manager):
    """Class definition of ScanDefinitionManager."""

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


class ScanDefinition(models.Model):

    # Manager
    objects = ScanDefinitionManager()

    # Attributes
    scan_type        = models.CharField(choices=SCAN_TYPES, default='single', max_length=10)
    assets_list      = models.ManyToManyField('assets.Asset',  blank=True)
    assetgroups_list = models.ManyToManyField('assets.AssetGroup', blank=True)
    taggroups_list   = models.ManyToManyField('assets.AssetCategory', blank=True)
    title            = models.CharField(max_length=256)
    description      = models.CharField(max_length=256, blank=True)
    every            = models.IntegerField(null=True, blank=True)
    period           = models.CharField(choices=PERIOD_CHOICES, default='hours', max_length=10, null=True, blank=True)
    enabled          = models.BooleanField(default=False)
    periodic_task    = models.ForeignKey(PeriodicTask, null=True, blank=True, on_delete=models.CASCADE)
    #scheduled_task   = models.UUIDField(editable=True, null=True, blank=True)
    status           = models.CharField(max_length=20, null=True, blank=True)
    engine_type      = models.ForeignKey('engines.Engine', null=True, on_delete=models.SET_NULL)
    engine           = models.ForeignKey('engines.EngineInstance', null=True, blank=True, on_delete=models.SET_NULL) #Force scan instance
    engine_policy    = models.ForeignKey('engines.EnginePolicy', null=True, on_delete=models.SET_NULL)
    owner            = models.ForeignKey(get_user_model(), null=True, on_delete=models.SET_NULL)
    timeout_delay    = models.IntegerField(null=True, blank=True)
    scheduled_at     = models.DateTimeField(null=True, blank=True)
    expire_at        = models.DateTimeField(null=True, blank=True)
    # options          = JSONField(null=True, blank=True)
    created_at       = models.DateTimeField(default=timezone.now)
    updated_at       = models.DateTimeField(default=timezone.now)
    teams            = models.ManyToManyField('users.team', blank=True)

    class Meta:
        db_table = 'scan_definitions'

    def __str__(self):
        return "{}/{}".format(self.id, self.title)

    def to_dict(self):
        data = model_to_dict(self, exclude=["assets_list", "assetgroups_list", "taggroups_list"])
        data.update({"assets_list": [model_to_dict(a, fields=["value", "id", "name"]) for a in self.assets_list.all()]})
        data.update({"assetgroups_list": [model_to_dict(a, fields=["id", "name"]) for a in self.assetgroups_list.all()]})
        data.update(
            {"taggroups_list": [model_to_dict(a, fields=["id", "value"]) for a in self.taggroups_list.all()]})
        data.update({"teams": [model_to_dict(t, fields=["name", "id"]) for t in self.teams.all()]})
        return json.loads(json.dumps(data, default=json_serial))

    def save(self, *args, **kwargs):
        # update the 'updated_at' entry on each update except on creation
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(ScanDefinition, self).save(*args, **kwargs)


@receiver(post_save, sender=ScanDefinition)
def scandef_create_update_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = ""
    if kwargs['created']:
        message = "[ScanDefinition] New scan defition created (id={}): {}".format(kwargs['instance'].id, kwargs['instance'])
        Event.objects.create(message=message, type="CREATE", severity="DEBUG")
    else:
        message = "[ScanDefinition] Scan definition '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id)
        Event.objects.create(message=message, type="UPDATE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='scan', type='scandef_create_update',
        request_context=inspect.stack())


@receiver(post_delete, sender=ScanDefinition)
def scandef_delete_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = "[ScanDefinition] Scan definition '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")
    AuditLog.objects.create(
        message=message,
        scope='scan', type='scandef_delete',
        request_context=inspect.stack())


class ScanManager(models.Manager):
    """Class definition of ScanManager."""

    def for_user(self, user):
        """Check if user is allowed to manage the object."""
        if settings.PRO_EDITION and not user.is_superuser:
            return super().get_queryset().filter(
                Q(scan_definition__teams__in=user.users_team.all(), scan_definition__teams__is_active=True) |
                Q(owner=user)
            )
        return super().get_queryset()

    def for_team(self, user, team):
        """Check if user is allowed to manage the object in a team."""
        if settings.PRO_EDITION:
            if user.is_superuser:
                return super().get_queryset().filter(
                    scan_definition__teams__in=[team],
                    scan_definition__teams__is_active=True)
            else:
                return super().get_queryset().filter(
                    scan_definition__teams__in=user.users_team.filter(id=team),
                    scan_definition__teams__is_active=True)
        return super().get_queryset()


class Scan(models.Model):
    # Manager
    objects = ScanManager()

    # Attributes
    scan_settings   = models.CharField(max_length=256, null=True, blank=True)
    scan_definition = models.ForeignKey(ScanDefinition, null=True, on_delete=models.CASCADE)
    assets          = models.ManyToManyField('assets.Asset')
    task_id         = models.UUIDField(editable=True, null=True, blank=True)
    title           = models.CharField(max_length=256)
    status          = models.CharField(max_length=20)
    engine          = models.ForeignKey('engines.EngineInstance', null=True, blank=True, on_delete=models.SET_NULL)
    engine_type     = models.ForeignKey('engines.Engine', null=True, on_delete=models.SET_NULL)
    engine_policy   = models.ForeignKey('engines.EnginePolicy', null=True, on_delete=models.SET_NULL)
    owner           = models.ForeignKey(get_user_model(), null=True, on_delete=models.SET_NULL)
    summary         = JSONField(null=True, blank=True)
    timeout_delay   = models.IntegerField(null=True, blank=True)
    report_filepath = models.CharField(max_length=256, null=True, blank=True)        # /media/reports/2/nmap/nmap_6054be57-1ce9-493e-9801-9cb049e3672.json
    started_at      = models.DateTimeField(null=True, blank=True)
    finished_at     = models.DateTimeField(null=True, blank=True)
    created_at      = models.DateTimeField(default=timezone.now)
    updated_at      = models.DateTimeField(default=timezone.now)
    nessscan_id = models.IntegerField(null=True, blank=True)

    class Meta:
        db_table = 'scans'

    def __str__(self):
        return "{}/{}".format(self.id, self.title)

    def to_dict(self):
        data = model_to_dict(self, exclude=["assets"])
        data.update({"assets": [model_to_dict(a, fields=["value", "id", "name"]) for a in self.assets.all()]})
        return json.loads(json.dumps(data, default=json_serial))

    def save(self, *args, **kwargs):
        # update the 'updated_at' entry on each update except on creation
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(Scan, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.report_filepath and os.path.exists(self.report_filepath):
            os.remove(self.report_filepath)
        return super(Scan, self).delete(*args, **kwargs)

    def update_sumary(self):
        raw_findings = self.rawfinding_set.all()
        self.summary = {
            "total": raw_findings.count(),
            "critical": raw_findings.filter(severity='critical').exclude(status='false-positive').exclude(status='duplicate').count(),
            "high":  raw_findings.filter(severity='high').exclude(status='false-positive').exclude(status='duplicate').count(),
            "medium": raw_findings.filter(severity='medium').exclude(status='false-positive').exclude(status='duplicate').count(),
            "low":   raw_findings.filter(severity='low').exclude(status='false-positive').exclude(status='duplicate').count(),
            "info":  raw_findings.filter(severity='info').exclude(status='duplicate').count(),
            "new":   self.finding_set.count(),
            "false-positive": raw_findings.filter(status='false-positive').exclude(status='duplicate').count(),
            "missing": 0  # todo
        }

        return self.summary


@receiver(post_save, sender=Scan)
def scan_create_update_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = ""
    if kwargs['created']:
        message = "[Scan] New scan created (id={}): {}".format(kwargs['instance'].id, kwargs['instance'])
        Event.objects.create(message=message, type="CREATE", severity="DEBUG")
    else:
        message = "[Scan] Scan '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id)
        Event.objects.create(message=message, type="UPDATE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='scan', type='scan_create_update',
        request_context=inspect.stack())


@receiver(post_delete, sender=Scan)
def scan_delete_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = "[Scan] Scan '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")
    AuditLog.objects.create(
        message=message,
        scope='scan', type='scan_delete',
        request_context=inspect.stack())


class ScanCampaign(models.Model):
    scan_def_list   = models.ManyToManyField(ScanDefinition)
    title           = models.CharField(max_length=256)
    description     = models.CharField(max_length=256)
    enabled         = models.BooleanField(default=False)
    status          = models.CharField(max_length=20)
    owner           = models.ForeignKey(get_user_model(), null=True, on_delete=models.SET_NULL)
    timeout_delay   = models.IntegerField(null=True, blank=True)
    report_filepath = models.CharField(max_length=256,null=True, blank=True)
    scheduled_at    = models.DateTimeField(null=True, blank=True)
    expire_at       = models.DateTimeField(null=True, blank=True)
    created_at      = models.DateTimeField(default=timezone.now)
    updated_at      = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'scan_campaigns'

    def __str__(self):
        return "{}/{}".format(self.id, self.title)

    def save(self, *args, **kwargs):
        # update the 'updated_at' entry on each update except on creation
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(ScanCampaign, self).save(*args, **kwargs)


@receiver(post_save, sender=ScanCampaign)
def scancampaign_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[ScanCampaign] New scan campaign created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
                             type="CREATE", severity="DEBUG")
    else:
        Event.objects.create(message="[ScanCampaign] Scan campaign '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
                             type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=ScanCampaign)
def scancampaign_delete_log(sender, **kwargs):
    from events.models import Event
    Event.objects.create(message="[ScanCampaign] Scan campaign '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
                 type="DELETE", severity="DEBUG")
