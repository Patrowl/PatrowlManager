# -*- coding: utf-8 -*-

from django.db import models
from django.utils import timezone
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import JSONField
from django.db.models import Q
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.forms.models import model_to_dict

# from events.models import Event
# from assets.models import Asset
# from scans.models import Scan
from rules.models import Rule
# from engines.models import EnginePolicyScope
from common.utils.encoding import json_serial

import json
import uuid
import hashlib


FINDING_SEVERITIES = (
    ('info', 'info'),
    ('low', 'low'),
    ('medium', 'medium'),
    ('high', 'high'),
    ('critical', 'critical')
)

FINDING_STATUS = (
    ('new', 'New'),
    ('ack', 'Acknowledged'),
    ('mitigated', 'Mitigated'),
    ('confirmed', 'Confirmed'),
    ('patched', 'Patched'),
    ('closed', 'Closed'),
    ('false-positive', 'False-Positive'),
    ('undone', 'Undone')
    ('duplicate', 'Duplicate')
)


class FindingQuerySet(models.QuerySet):
    def for_user(self, user):
        if settings.PRO_EDITION and not user.is_superuser:
            return self.filter(
                Q(asset__teams__in=user.users_team.all(), asset__teams__is_active=True) |
                Q(owner=user)
            ).distinct()
        return self

    def for_team(self, user, team):
        if settings.PRO_EDITION:
            if user.is_superuser:
                return self.filter(asset__teams__in=[team]).distinct()
            else:
                return self.filter(asset__teams__in=user.users_team.filter(id=team), asset__teams__is_active=True).distinct()
        return self


class FindingManager(models.Manager):
    """Class definition of FindingManager."""

    def get_queryset(self):
        return FindingQuerySet(self.model, using=self._db)  # Important!

    def severity_ordering(self, *args, **kwargs):
        """Sort patterns by preferred order of finding severities."""
        qs = self.get_queryset().filter(*args, **kwargs)
        qs = qs.annotate(severity_order=
            models.Case(
                models.When(severity='info', then=models.Value(0)),
                models.When(severity='low', then=models.Value(1)),
                models.When(severity='medium', then=models.Value(2)),
                models.When(severity='high', then=models.Value(3)),
                models.When(severity='critical', then=models.Value(4)),
                default=models.Value(0),
                output_field=models.IntegerField(), )
            ).order_by('-severity_order', 'asset_name', 'title')
        return qs

    def for_user(self, user):
        """Check if user is allowed to manage the object."""
        return self.get_queryset().for_user(user)

    def for_team(self, user, team):
        """Check if user is allowed to manage the object for a team."""
        return self.get_queryset().for_team(user, team)


class RawFinding(models.Model):
    asset       = models.ForeignKey('assets.Asset', on_delete=models.CASCADE)
    asset_name  = models.CharField(max_length=256)
    task_id     = models.UUIDField(default=uuid.uuid4, editable=True)
    scan        = models.ForeignKey('scans.Scan', on_delete=models.CASCADE)
    # owner       = models.ForeignKey(get_user_model(), on_delete=models.DO_NOTHING, null=True, blank=True)
    owner       = models.ForeignKey(get_user_model(), on_delete=models.SET_NULL, null=True, blank=True)
    title       = models.CharField(max_length=256)
    type        = models.CharField(max_length=50)
    hash        = models.CharField(max_length=256, default='')
    confidence  = models.CharField(max_length=10)
    severity    = models.CharField(choices=FINDING_SEVERITIES, default='info', max_length=10)
    severity_num= models.IntegerField(default=1, blank=True, null=True)
    scopes      = models.ManyToManyField('engines.EnginePolicyScope', blank=True)
    description = models.TextField()
    solution    = models.TextField(null=True, blank=True)
    score       = models.IntegerField(default=0, null=True, blank=True)
    raw_data    = JSONField(null=True, blank=True)
    risk_info   = JSONField(null=True, blank=True)
    vuln_refs   = JSONField(null=True, blank=True)
    links       = JSONField(null=True, blank=True)
    tags        = JSONField(null=True, blank=True)
    status      = models.CharField(choices=FINDING_STATUS, max_length=16)
    engine_type = models.CharField(max_length=20)
    found_at    = models.DateTimeField(null=True, blank=True)
    checked_at  = models.DateTimeField(null=True, blank=True)
    comments    = models.TextField(default="n/a", null=True, blank=True)
    created_at  = models.DateTimeField(default=timezone.now)
    updated_at  = models.DateTimeField(default=timezone.now)

    objects = FindingManager()

    class Meta:
        db_table = 'raw_findings'

    def __str__(self):
        return "{}/{}/{}".format(self.id, self.asset.value, self.title)

    def get_risk(self):
        return (self.severity, self.confidence)

    def save(self, *args, **kwargs):
        if self.hash == '':
            self.hash = hashlib.sha1(str(self.asset_name).encode('utf-8')+str(self.title).encode('utf-8')).hexdigest()
        if self.severity == "info":
            self.severity_num = 1
        elif self.severity == "low":
            self.severity_num = 2
        elif self.severity == "medium":
            self.severity_num = 3
        elif self.severity == "high":
            self.severity_num = 4
        elif self.severity == "critical":
            self.severity_num = 5
        else:
            self.severity_num = 0
        # update the 'updated_at' entry on each update except on creation
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(RawFinding, self).save(*args, **kwargs)

    def evaluate_alert_rules(self, trigger='all'):
        if trigger == "all":
            rules = Rule.objects.filter(enabled=True, scope='finding')
        else:
            rules = Rule.objects.filter(enabled=True, scope='finding', trigger=trigger)
        nb_matches = 0
        for rule in rules:
            rck, rcv = list(rule.condition.items())[0]
            kwargs = {
                "id": self.id,
                # rule.scope_attr + next(iter(rule.condition)): rule.condition.itervalues().next()
                rule.scope_attr + rck: rcv
            }
            if RawFinding.objects.filter(**kwargs):
                nb_matches += 1
                rule.notify(message="[Asset={}] {}".format(self.asset.value, self.title), asset=self.asset, description=self.description)
        return nb_matches


@receiver(post_save, sender=RawFinding)
def rawfinding_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[RawFinding] New raw finding created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
                             type="CREATE", severity="DEBUG")
    else:
        Event.objects.create(message="[RawFinding] Raw finding '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
                             type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=RawFinding)
def rawfinding_delete_log(sender, **kwargs):
    from events.models import Event
    message = "[RawFinding] Raw finding '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)[:250]
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")


class Finding(models.Model):
    raw_finding = models.ForeignKey(RawFinding, models.SET_NULL, blank=True, null=True)
    asset       = models.ForeignKey('assets.Asset', on_delete=models.CASCADE)
    asset_name  = models.CharField(max_length=256) #todo: delete this
    task_id     = models.UUIDField(default=uuid.uuid4, editable=True)
    scan        = models.ForeignKey('scans.Scan', on_delete=models.CASCADE, blank=True, null=True)
    # owner       = models.ForeignKey(get_user_model(), on_delete=models.DO_NOTHING, null=True, blank=True)
    owner       = models.ForeignKey(get_user_model(), on_delete=models.SET_NULL, null=True, blank=True)
    title       = models.CharField(max_length=256, default='title')
    type        = models.CharField(max_length=50)
    hash        = models.CharField(max_length=256)
    confidence  = models.CharField(max_length=10)
    severity    = models.CharField(choices=FINDING_SEVERITIES, default='info', max_length=10)  # info, low, medium, high, critical
    severity_num= models.IntegerField(default=1, blank=True, null=True)  # info, low, medium, high, critical
    scopes      = models.ManyToManyField('engines.EnginePolicyScope', blank=True, related_name='finding_scopes')
    description = models.TextField()
    solution    = models.TextField(null=True, blank=True)
    score       = models.IntegerField(default=0, null=True, blank=True)
    raw_data    = JSONField(null=True, blank=True)
    risk_info   = JSONField(null=True, blank=True)
    vuln_refs   = JSONField(null=True, blank=True)
    links       = JSONField(null=True, blank=True)
    tags        = JSONField(null=True, blank=True)
    status      = models.CharField(choices=FINDING_STATUS, max_length=16, default='new')
    engine_type = models.CharField(max_length=20)
    found_at    = models.DateTimeField(default=timezone.now)
    comments    = models.TextField(default="n/a", null=True, blank=True)
    checked_at  = models.DateTimeField(default=timezone.now)
    created_at  = models.DateTimeField(default=timezone.now)
    updated_at  = models.DateTimeField(default=timezone.now)

    objects = FindingManager()

    class Meta:
        db_table = 'findings'

    def __str__(self):
        return "{}/{}".format(self.id, self.title)

    def to_dict(self):
        """Return JSONified class summary."""
        data = model_to_dict(self, exclude=["scopes"])
        data.update({"scopes": [model_to_dict(s, fields=["name", "id"]) for s in self.scopes.all()]})
        return json.loads(json.dumps(data, default=json_serial))

    def get_risk(self):
        return (self.severity, self.confidence)

    def save(self, *args, **kwargs):
        self.hash = hashlib.sha1(str(self.asset_name).encode('utf-8')+str(self.title).encode('utf-8')).hexdigest()
        if self.severity == "info":
            self.severity_num = 1
        elif self.severity == "low":
            self.severity_num = 2
        elif self.severity == "medium":
            self.severity_num = 3
        elif self.severity == "high":
            self.severity_num = 4
        elif self.severity == "critical":
            self.severity_num = 5
        else:
            self.severity_num = 0

        # update the 'updated_at' entry on each update except on creation
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(Finding, self).save(*args, **kwargs)

    def evaluate_alert_rules(self, trigger='all'):
        if trigger == "all":
            rules = Rule.objects.filter(enabled=True, scope='finding')
        else:
            rules = Rule.objects.filter(enabled=True, scope='finding', trigger=trigger)
        nb_matches = 0
        for rule in rules:
            kwargs = {
                "id": self.id,
                # rule.scope_attr+next(iter(rule.condition)): rule.condition.itervalues().next()
                rule.scope_attr+next(iter(rule.condition)): next(iter(rule.condition.values()))
            }
            if Finding.objects.filter(**kwargs):
                nb_matches += 1
                rule.notify(message="[Asset={}] {}".format(self.asset.value, self.title), asset=self.asset, description=self.description)
        return nb_matches


@receiver(post_save, sender=Finding)
def finding_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[Finding] New finding created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
                             type="CREATE", severity="DEBUG")
    else:
        kwargs['instance'].asset.calc_risk_grade()
        Event.objects.create(message="[Finding] Finding '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
                             type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=Finding)
def finding_delete_log(sender, **kwargs):
    from assets.models import Asset
    from events.models import Event
    asset = Asset.objects.get(id=kwargs['instance'].asset_id)
    asset.calc_risk_grade()

    Event.objects.create(message="[Finding] Finding '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
                 type="DELETE", severity="DEBUG")
