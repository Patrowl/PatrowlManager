from django.db import models
from django.utils import timezone
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
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'events'

    def __str__(self):
        return "[{}] {} - {} - {}".format(self.severity, self.message, self.code, self.created_at)

    def save(self, *args, **kwargs):
        if self.severity in LOGGING_LEVEL.split(','):
            return super(Event, self).save(*args, **kwargs)
