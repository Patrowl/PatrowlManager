# -*- coding: utf-8 -*-

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.postgres.fields import JSONField
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.core.mail import send_mail
from events.models import Event, AuditLog, Alert
from settings.models import Setting
from django_celery_beat.models import PeriodicTask

import json
import requests
import uuid
import inspect
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert as THAlert
from thehive4py.models import AlertArtifact as THAlertArtifact

RULE_SCOPES = (
    ('asset', 'Asset'),
    ('finding', 'Finding'),
    ('scan', 'Scan'),
    ('alert', 'Alert'),
)

RULE_SCOPE_ATTRIBUTES = {
    "asset": {
        # 'value':        {"type": "numeric"},
        'value':        {"type": "text"},
        'name':         {"type": "text"},
        'type':         {"type": "list", "values": ['ip', 'domain', 'url']},
        'description':  {"type": "text"},
        'criticity':    {"type": "list", "values": ['low', 'medium', 'high']}
        },
    "finding": {
        'title':        {"type": "text"},
        'description':  {"type": "text"},
        'type':         {"type": "text"},
        'hash':         {"type": "text"},
        'solution':     {"type": "text"},
        'severity':     {"type": "list", "values": ['info', 'low', 'medium', 'high', 'critical']},
        'status':       {"type": "list", "values": ['new', 'ack']},
        # 'tags':         {"type": "in_list"},
        },
    "scan": {
        'status': {"type": "text"},
    },
    "alert": {
        'title': {"type": "text"},
        'severity': {"type": "list", "values": ['info', 'low', 'medium', 'high', 'critical']},
        'status': {"type": "list", "values": ['new', 'read', 'archived']},
    },
}

RULE_TARGETS = (
    # ('event',   'Patrowl event'),
    # ('logfile', 'To logfile'),
    ('email',   'Send email'),
    ('thehive', 'TheHive Event'),
    # ('splunk',  'To Splunk'),
    ('slack',   'Slack'),
    ('alert',   'Alert'),
)

RULE_TRIGGERS = (
    ('ondemand', 'On-demand'),
    ('auto',     'Auto'),
    ('periodic', 'Periodic'),  # frequency ?
)

RULE_CONDITIONS = {
    'text': {
        "__iexact":      "is exactly",
        "__icontains":   "contains",
        "__istartswith": "starts with",
        "__iendswith":   "ends with",
    },
    'numeric': {
        "__gt":  "greater than",
        "__gte": "greater than/equal to",
        "__lt":  "less than",
        "__lte": "less than/equal to",
    },
    'list': None,  # see values
}

RULE_SEVERITIES = (
    ('Info', 'Info'),
    ('Low', 'Low'),
    ('Medium', 'Medium'),
    ('High', 'High'),
    ('Critical', 'Critical'),
)


class Rule(models.Model):
    title            = models.CharField(max_length=256)
    comments         = models.CharField(max_length=256, default='n/a')
    scope            = models.CharField(choices=RULE_SCOPES, default='finding', max_length=10)
    scope_attr       = models.CharField(max_length=20, null=True, blank=True)
    condition        = JSONField(null=True, blank=True)
    target           = models.CharField(choices=RULE_TARGETS, default='event', max_length=10)
    severity         = models.CharField(choices=RULE_SEVERITIES, default='Low', max_length=10)
    trigger          = models.CharField(choices=RULE_TRIGGERS, default='auto', max_length=10)
    trigger_attr     = models.CharField(max_length=20, null=True, blank=True)
    summary          = JSONField(null=True, blank=True)
    periodic_task    = models.ForeignKey(PeriodicTask, null=True, blank=True, on_delete=models.CASCADE)
    enabled          = models.BooleanField(default=False)
    nb_matches       = models.IntegerField(default=0)
    owner            = models.ForeignKey(get_user_model(), on_delete=models.SET_NULL, null=True, blank=True)
    created_at       = models.DateTimeField(default=timezone.now)
    updated_at       = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'rules'

    def __str__(self):
        return "{}/{}".format(self.id, self.title)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(Rule, self).save(*args, **kwargs)

    def notify(self, message="", asset=None, description="", finding=None):
        # print('into Rule.notify()')
        if self.target == 'email':
            send_email_message(self, message, description)
        elif self.target == 'slack':
            send_slack_message(self, message)
        elif self.target == 'thehive':
            send_thehive_message(self, message, asset, description)
        elif self.target == 'alert':
            send_alert_message(self, message, description, finding)
        elif self.target == 'event':
            Event.objects.create(
                message="[Alert][Rule={}]{}".format(self.title, message),
                type="ALERT", severity="INFO")

        self.nb_matches += 1
        self.save()


@receiver(post_save, sender=Rule)
def rule_create_update_log(sender, **kwargs):
    message = ""
    if kwargs['created']:
        message = "[Rule] New rule created (id={}): {}".format(kwargs['instance'].id, kwargs['instance'])
        Event.objects.create(message=message, type="CREATE", severity="DEBUG")
    else:
        message = "[Rule] Rule '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id)
        Event.objects.create(message=message, type="UPDATE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='rule', type='rule_create_update',
        request_context=inspect.stack())


@receiver(post_delete, sender=Rule)
def rule_delete_log(sender, **kwargs):
    message = "[Rule] Rule '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='rule', type='rule_delete',
        request_context=inspect.stack())


def send_alert_message(rule, message, description, finding):
    severity = rule.severity.lower()
    # Set default severity
    if severity not in ['info', 'low', 'medium', 'high', 'critical']:
        severity = 'info'

    if finding is None:
        AuditLog.objects.create(
            message='Failed alert: {}'.format(message),
            scope='rule', type='rule_send_alert',
            request_context=inspect.stack())
        return

    # asset_id = None
    # asset = Asset.objects.filter(value=finding.asset_name).first()
    # if asset is not None:
    #     asset_id = asset.id

    alert = Alert.objects.create(
        message=message,
        status='new',
        severity=severity,
        metadata={
            "finding_id": finding.id,
            "finding_title": finding.title,
            "scan_id": finding.scan.id,
            "asset_name": finding.asset_name,
            "asset_id": finding.asset.id
        },
        owner=finding.owner
    )
    if finding.asset is not None and finding.asset.teams.count() > 0:
        for team in finding.asset.teams.all():
            alert.teams.add(team)
        alert.save()

    AuditLog.objects.create(
        message=message,
        scope='rule', type='rule_send_alert',
        request_context=inspect.stack())

    return True


def send_email_message(rule, message, description):
    contact_mail = Setting.objects.get(key="alerts.endpoint.email").value
    log_message = "[Rule] Rule '{}' email sent to {} (message={}, description={})".format(rule, contact_mail, message, description).replace("\n", "")
    Event.objects.create(message=log_message[:250], type="CREATE", severity="DEBUG")
    AuditLog.objects.create(
        message=log_message[:250],
        scope='rule', type='rule_send_email',
        request_context=inspect.stack())
    send_mail(
        '[Patrowl] New alert: '+message,
        'Message: {}\nDescription: {}'.format(message, description),
        'alerts@patrowl.io',
        [contact_mail],
        fail_silently=False,
    )


def send_slack_message(rule, message):
    mess = "[Rule] Rule '{}' Slack alert creation (message={})".format(rule, message)[:250]
    Event.objects.create(message=mess, type="CREATE", severity="DEBUG")
    AuditLog.objects.create(
        message=mess,
        scope='rule', type='rule_send_slack',
        request_context=inspect.stack())
    slack_url = Setting.objects.get(key="alerts.endpoint.slack.webhook")
    try:
        slack_channel = Setting.objects.get(key="alerts.endpoint.slack.channel")
    except Exception:
        slack_channel = None
    alert_message = "[Alert][Rule={}]{}".format(rule.title, message)
    data_payload = {'text': alert_message}
    if slack_channel:
        data_payload["channel"] = slack_channel.value
    try:
        requests.post(
            slack_url.value,
            data=json.dumps(data_payload),
            headers={'content-type': 'application/json'})
    except Exception as e:
        Event.objects.create(message="err:{} [Rule] Send slack message failed (id={})".format(e, rule.id)[:250],
                     type="ERROR", severity="ERROR", description=alert_message)


def send_thehive_message(rule, message, asset, description):
    mess = "[Rule] Rule '{}' TheHive alert creation (asset={})".format(rule, asset)
    Event.objects.create(message=mess, type="CREATE", severity="DEBUG")
    AuditLog.objects.create(
        message=mess,
        scope='rule', type='rule_send_thehive',
        request_context=inspect.stack())

    thehive_apikey = Setting.objects.get(key="alerts.endpoint.thehive.apikey")
    thehive_url = Setting.objects.get(key="alerts.endpoint.thehive.url")
    thehive_user = Setting.objects.get(key="alerts.endpoint.thehive.user")
    alert_message = "[Alert][Rule={}]{}".format(rule.title, message)

    api = TheHiveApi(thehive_url.value, thehive_apikey.value)
    sourceRef = str(uuid.uuid4())[0:6]
    # Severity 1 is the lower severity for TheHive
    rule_severity = 1
    if rule.severity == "Medium":
        rule_severity = 2
    elif rule.severity in ["High", "Critical"]:
        rule_severity = 3

    tlp = 0
    if asset.criticity == "low":
        tlp = 1
    elif asset.criticity == "medium":
        tlp = 2
    elif asset.criticity == "high":
        tlp = 3

    if asset:
        artifacts = [THAlertArtifact(dataType=asset.type, data=asset.value)]
        try:
            alert = THAlert(
                        title=alert_message,
                        tlp=tlp,
                        severity=rule_severity,
                        tags=['src:PatrOwl'],
                        description=description,
                        type='external',
                        source=thehive_user.value,
                        sourceRef=sourceRef,
                        artifacts=artifacts)

            response = api.create_alert(alert)

            if response.status_code == 201:
                alert_id = response.json()['id']
                # todo: track theHive alerts
                Event.objects.create(
                    message="[Rule][send_thehive_message()] "
                    "Alert sent to TheHive with message '{}' (alert id: {})".format(message, alert_id),
                    type="DEBUG", severity="DEBUG"
                )
            else:
                return_value = ""
                if "errors" in json.loads(response.text):
                    # Limit length to 40 characters
                    return_value = json.loads(response.text)["errors"][0]["message"][:40]
                Event.objects.create(
                    message="[Rule][send_thehive_message()] Unable to send "
                    "alert to TheHive (status_code={}, return_value='{}')".format(response.status_code, return_value),
                    type="ERROR", severity="ERROR"
                )
        except Exception as e:
            Event.objects.create(
                message="[Rule][send_thehive_message()] Unable to send alert "
                "to TheHive with (error={}, message ='{}')".format(e, message),
                type="ERROR", severity="ERROR")
