from django.db import models
from django.utils import timezone


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
