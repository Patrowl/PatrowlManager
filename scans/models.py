from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.postgres.fields import JSONField
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.forms.models import model_to_dict
from django_celery_beat.models import PeriodicTask

# from events.models import Event
# from assets.models import Asset, AssetGroup
# from engines.models import Engine, EnginePolicy, EngineInstance
from common.utils.encoding import json_serial

import os
import json

SCAN_STATUS = ('created', 'started', 'finished', 'error', 'trashed')

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


class ScanDefinition(models.Model):
    scan_type        = models.CharField(choices=SCAN_TYPES, default='single', max_length=10)
    # assets_list      = models.ManyToManyField(Asset,  blank=True)
    assets_list      = models.ManyToManyField('assets.Asset',  blank=True)
    # assetgroups_list = models.ManyToManyField(AssetGroup, blank=True)
    assetgroups_list = models.ManyToManyField('assets.AssetGroup', blank=True)
    title            = models.CharField(max_length=256)
    description      = models.CharField(max_length=256, blank=True)
    every            = models.IntegerField(null=True, blank=True)
    period           = models.CharField(choices=PERIOD_CHOICES, default='hours', max_length=10, null=True, blank=True)
    enabled          = models.BooleanField(default=False)
    periodic_task    = models.ForeignKey(PeriodicTask, null=True, blank=True, on_delete=models.CASCADE)
    #scheduled_task   = models.UUIDField(editable=True, null=True, blank=True)
    status           = models.CharField(max_length=20, null=True, blank=True)
    # engine_type      = models.ForeignKey(Engine, null=True, on_delete=models.SET_NULL)
    engine_type      = models.ForeignKey('engines.Engine', null=True, on_delete=models.SET_NULL)
    # engine           = models.ForeignKey(EngineInstance, null=True, blank=True, on_delete=models.SET_NULL) #Force scan instance
    engine           = models.ForeignKey('engines.EngineInstance', null=True, blank=True, on_delete=models.SET_NULL) #Force scan instance
    # engine_policy    = models.ForeignKey(EnginePolicy, null=True, on_delete=models.SET_NULL)
    engine_policy    = models.ForeignKey('engines.EnginePolicy', null=True, on_delete=models.SET_NULL)
    owner            = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    timeout_delay    = models.IntegerField(null=True, blank=True)
    scheduled_at     = models.DateTimeField(null=True, blank=True)
    expire_at        = models.DateTimeField(null=True, blank=True)
    created_at       = models.DateTimeField(default=timezone.now)
    updated_at       = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'scan_definitions'

    def __str__(self):
        return "{}/{}".format(self.id, self.title)

    def to_dict(self):
        data = model_to_dict(self, exclude=["assets_list", "assetgroups_list"])
        data.update({"assets_list": [model_to_dict(a, fields=["value", "id", "name"]) for a in self.assets_list.all()]})
        data.update({"assetgroups_list": [model_to_dict(a, fields=["id", "name"]) for a in self.assetgroups_list.all()]})
        return json.loads(json.dumps(data, default=json_serial))

    def save(self, *args, **kwargs):
        # update the 'updated_at' entry on each update except on creation
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(ScanDefinition, self).save(*args, **kwargs)


@receiver(post_save, sender=ScanDefinition)
def scandef_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[ScanDefinition] New scan defition created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
                             type="CREATE", severity="DEBUG")
    else:
        Event.objects.create(message="[ScanDefinition] Scan definition '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
                             type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=ScanDefinition)
def scandef_delete_log(sender, **kwargs):
    from events.models import Event
    Event.objects.create(message="[ScanDefinition] Scan definition '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
                 type="DELETE", severity="DEBUG")


class Scan(models.Model):
    scan_settings   = models.CharField(max_length=256, null=True, blank=True)
    # scan_definition = models.ForeignKey(ScanDefinition, null=True, on_delete=models.SET_NULL)
    scan_definition = models.ForeignKey(ScanDefinition, null=True, on_delete=models.CASCADE)
    # assets          = models.ManyToManyField(Asset)
    assets          = models.ManyToManyField('assets.Asset')
    task_id         = models.UUIDField(editable=True, null=True, blank=True)
    title           = models.CharField(max_length=256)
    status          = models.CharField(max_length=20)
    # engine          = models.ForeignKey(EngineInstance, null=True, blank=True, on_delete=models.SET_NULL)
    engine          = models.ForeignKey('engines.EngineInstance', null=True, blank=True, on_delete=models.SET_NULL)
    # engine_type     = models.ForeignKey(Engine,null=True, on_delete=models.SET_NULL)
    engine_type     = models.ForeignKey('engines.Engine', null=True, on_delete=models.SET_NULL)
    # engine_policy   = models.ForeignKey(EnginePolicy, null=True, on_delete=models.SET_NULL)
    engine_policy   = models.ForeignKey('engines.EnginePolicy', null=True, on_delete=models.SET_NULL)
    owner           = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    summary         = JSONField(null=True, blank=True)
    timeout_delay   = models.IntegerField(null=True, blank=True)
    report_filepath = models.CharField(max_length=256, null=True, blank=True)        # /media/reports/2/nmap/nmap_6054be57-1ce9-493e-9801-9cb049e3672.json
    started_at      = models.DateTimeField(null=True, blank=True)
    finished_at     = models.DateTimeField(null=True, blank=True)
    created_at      = models.DateTimeField(default=timezone.now)
    updated_at      = models.DateTimeField(default=timezone.now)

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
            "critical": raw_findings.filter(severity='critical').count(),
            "high":  raw_findings.filter(severity='high').count(),
            "medium":raw_findings.filter(severity='medium').count(),
            "low":   raw_findings.filter(severity='low').count(),
            "info":  raw_findings.filter(severity='info').count(),
            "new":   self.finding_set.count(),
            "missing": 0 #todo
        }

        return self.summary


@receiver(post_save, sender=Scan)
def scan_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[Scan] New scan created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
                             type="CREATE", severity="DEBUG")
    else:
        Event.objects.create(message="[Scan] Scan '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
                             type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=Scan)
def scan_delete_log(sender, **kwargs):
    from events.models import Event
    Event.objects.create(message="[Scan] Scan '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
                 type="DELETE", severity="DEBUG")


class ScanCampaign(models.Model):
    scan_def_list   = models.ManyToManyField(ScanDefinition)
    title           = models.CharField(max_length=256)
    description     = models.CharField(max_length=256)
    enabled         = models.BooleanField(default=False)
    status          = models.CharField(max_length=20)
    owner           = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
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
