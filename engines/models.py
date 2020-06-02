# -*- coding: utf-8 -*-

from django.db import models
from django.utils import timezone
from django.contrib.auth.models import User
from django.contrib.postgres.fields import JSONField
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
# from events.models import Event
from app.settings import MEDIA_ROOT
import os
import base64

ENGINE_INSTANCE_STATUS = ['STOPPED', 'READY', 'WORKING', 'ERROR']
API_AUTH_METHODS = (
    ('None', 'None'),
    ('HTTPBasic', 'HTTPBasic'),
    ('APIKEY', 'APIKEY')
)


class Engine(models.Model):
    name = models.CharField(max_length=200, unique=True)
    description = models.TextField()
    allowed_asset_types = models.TextField(null=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    # class Meta:
    #     db_table = 'engines'

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):

        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(Engine, self).save(*args, **kwargs)


@receiver(post_save, sender=Engine)
def engine_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[Engine] New engine created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
                             type="CREATE", severity="DEBUG")
    else:
        Event.objects.create(message="[Engine] Engine '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
                             type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=Engine)
def engine_delete_log(sender, **kwargs):
    from events.models import Event
    Event.objects.create(message="[Engine] Engine '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
        type="DELETE", severity="DEBUG")


class EngineInstance(models.Model):
    engine = models.ForeignKey(Engine, on_delete=models.CASCADE)
    # engine = models.ForeignKey(Engine, on_delete=models.CASCADE)
    name = models.CharField(max_length=200, unique=True)
    version = models.CharField(max_length=20)
    api_url = models.CharField(max_length=256)
    enabled = models.BooleanField(default=True)
    status = models.CharField(max_length=20, default='idle')
    authentication_method = models.CharField(
        choices=API_AUTH_METHODS, default='None', max_length=10)
    api_key = models.CharField(max_length=100, null=True, blank=True)
    username = models.CharField(max_length=100, null=True, blank=True)
    password = models.CharField(max_length=100, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    # class Meta:
    #     db_table = 'engineinstances'

    def set_status(self, status):
        # Check allowed status values
        if status in ENGINE_INSTANCE_STATUS:
            self.status = status
        else:
            return -1

    def save(self, *args, **kwargs):
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(EngineInstance, self).save(*args, **kwargs)

    def __str__(self):
        return "{}@{}".format(self.name, self.api_url)


@receiver(post_save, sender=EngineInstance)
def engineinstance_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[EngineInstance] New engine instance created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
            type="CREATE", severity="DEBUG")
    else:
        Event.objects.create(message="[EngineInstance] Engine instance '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
            type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=EngineInstance)
def engineinstance_delete_log(sender, **kwargs):
    from events.models import Event
    Event.objects.create(message="[EngineInstance] Engine instance '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
        type="DELETE", severity="DEBUG")

# def user_directory_path(instance, filename):
#     # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
#     return 'user_{0}/{1}'.format(instance.user.id, filename)


class EnginePolicyScope(models.Model):
    name        = models.CharField(max_length=250)
    priority    = models.IntegerField(null=True, blank=True)
    created_at  = models.DateTimeField(default=timezone.now)
    updated_at  = models.DateTimeField(default=timezone.now)

    # class Meta:
    #     db_table = 'engine_policy_scopes'

    def save(self, *args, **kwargs):
        if not self._state.adding:
            self.updated_at = timezone.now()
        return super(EnginePolicyScope, self).save(*args, **kwargs)

    def __str__(self):
        return self.name

    def __unicode__(self):
        return self.name


@receiver(post_save, sender=EnginePolicyScope)
def enginepolicyscope_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[EnginePolicyScope] New engine policy scope created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
                             type="CREATE", severity="DEBUG")
    else:
        Event.objects.create(message="[EnginePolicyScope] Engine policy scope '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
                             type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=EnginePolicyScope)
def enginepolicyscope_delete_log(sender, **kwargs):
    from events.models import Event
    Event.objects.create(message="[EnginePolicyScope] Engine policy scope '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
                 type="DELETE", severity="DEBUG")


class EnginePolicy(models.Model):
    engine      = models.ForeignKey(Engine, on_delete=models.CASCADE)
    owner       = models.ForeignKey(User, null=True, on_delete=models.SET_NULL)
    name        = models.CharField(max_length=200)
    default     = models.BooleanField(default=False)
    description = models.CharField(max_length=200)
    options     = JSONField(null=True, blank=True, default=dict)
    file        = models.FileField(upload_to='./policies/', null=True, blank=True)
    status      = models.CharField(max_length=50)    #active / trashed
    is_default  = models.BooleanField(default=False)
    scopes      = models.ManyToManyField(EnginePolicyScope)
    created_at  = models.DateTimeField(default=timezone.now)
    updated_at  = models.DateTimeField(default=timezone.now)

    class Meta:
        #db_table = 'engine_policies'
        verbose_name_plural = 'Engine policies'

    def save(self, *args, **kwargs):
        if not self._state.adding:
            self.updated_at = timezone.now()

        super(EnginePolicy, self).save(*args, **kwargs)

        if self.file.name:
            initial_path = self.file.path

            # ex: /media/policies/NESSUS/2/nessuspolicy.nessus
            new_name = '/'.join(['policies', self.engine.name, str(self.owner.id), os.path.basename(initial_path)])
            new_path = os.path.join(MEDIA_ROOT, 'policies',
                self.engine.name, str(self.owner.id), os.path.basename(initial_path))

            # create /media/policies/<engine_name>/ if not exists
            if not os.path.exists(MEDIA_ROOT+"/policies/"+self.engine.name):
                    os.mkdir(MEDIA_ROOT+"/policies/"+self.engine.name)

            # create /media/policies/<engine_name>/<owner_id> if not exists
            if not os.path.exists(os.path.dirname(new_path)):
                    os.mkdir(os.path.dirname(new_path))
            os.rename(initial_path, new_path)

            self.file.name = new_name

        return super(EnginePolicy, self).save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        if self.file.name and os.path.exists(self.file.path):
            os.remove(self.file.path)
        return super(EnginePolicy, self).delete(*args, **kwargs)

    def __str__(self):
        return "{}@{}".format(self.engine.name, self.name)

    def as_dict(self):
        file_b64 = None
        if self.file:
            file_b64_name = self.file.name.split("/")[-1:][0]
            file_b64_content = ""
            self.file.open(mode='rb')
            file_b64_content += base64.b64encode(self.file.read())
            self.file.close()
            file_b64 = {"filename": file_b64_name, "content": file_b64_content}

        scopes = self.scopes.all().only("id", "name")

        return {
            'id': self.id,
            'name': self.name,
            'engine': self.engine.id,
            'engine_name': self.engine.name,
            'owner': self.owner.id,
            'default': self.default,
            'description': self.description,
            'options': self.options,
            'file': file_b64,
            'status': self.status,
            'scopes': list(scopes.values_list("id", flat=True)),
            'scope_names': list(scopes.values_list("name", flat=True))
        }


@receiver(post_save, sender=EnginePolicy)
def enginepolicy_create_update_log(sender, **kwargs):
    from events.models import Event
    if kwargs['created']:
        Event.objects.create(message="[EnginePolicy] New engine policy created (id={}): {}".format(kwargs['instance'].id, kwargs['instance']),
            type="CREATE", severity="DEBUG")
    else:
        Event.objects.create(message="[EnginePolicy] Engine policy '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id),
            type="UPDATE", severity="DEBUG")


@receiver(post_delete, sender=EnginePolicy)
def enginepolicy_delete_log(sender, **kwargs):
    from events.models import Event
    Event.objects.create(message="[EnginePolicy] Engine policy '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
        type="DELETE", severity="DEBUG")
