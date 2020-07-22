from django.db import models
from django.utils import timezone
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
import inspect


class Setting(models.Model):
    key        = models.CharField(max_length=256, unique=True)
    value      = models.CharField(max_length=256, default='n/a')
    comments   = models.CharField(max_length=256, default='n/a')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = 'settings'

    def __str__(self):
        return "{}: {}".format(self.key, self.value)

    def save(self, *args, **kwargs):
        # update the 'updated_at' entry on each update except on creation
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(Setting, self).save(*args, **kwargs)


@receiver(post_save, sender=Setting)
def setting_create_update_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = ""
    if kwargs['created']:
        message = "[Setting] New setting created (id={}): {}".format(kwargs['instance'].id, kwargs['instance'])
        Event.objects.create(message=message, type="CREATE", severity="DEBUG")
    else:
        message = "[Setting] Setting '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id)
        Event.objects.create(message=message, type="UPDATE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='setting', type='rsetting_create_update',
        request_context=inspect.stack())


@receiver(post_delete, sender=Setting)
def setting_delete_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = "[Setting] Setting '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='setting', type='setting_delete',
        request_context=inspect.stack())
