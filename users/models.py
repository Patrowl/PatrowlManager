# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from organizations.abstract import (AbstractOrganization,
                                    AbstractOrganizationUser,
                                    AbstractOrganizationOwner)

import inspect
import logging
logger = logging.getLogger(__name__)


USER_STATUS = (
    ('ACTIVE', 'ACTIVE'),
    ('DISABLED', 'DISABLED'),
)


class Profile(models.Model):
    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE)
    status = models.CharField(choices=USER_STATUS, default='ACTIVE', max_length=10)
    is_delegated = models.BooleanField(default=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return "profile_{}".format(self.user.username)

    def save(self, *args, **kwargs):
        if not self._state.adding:
            self.updated_at = timezone.now()
        super(Profile, self).save(*args, **kwargs)

    def get_group(self):
        return self


@receiver(post_save, sender=get_user_model())
def create_user_profile(sender, instance, created, **kwargs):
    from events.models import Event, AuditLog
    if created:
        Profile.objects.create(user=instance, status='ACTIVE')

        message = "[User] New user created (id={}): {}".format(instance.id, instance)
        Event.objects.create(message=message, type="CREATE", severity="DEBUG")
        AuditLog.objects.create(
            message=message,
            scope='user', type='user_create',
            request_context=inspect.stack())


@receiver(post_save, sender=get_user_model())
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()


@receiver(post_delete, sender=get_user_model())
def delete_user_profile(sender, **kwargs):
    from events.models import Event, AuditLog
    message = "[User] User '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")
    AuditLog.objects.create(
        message=message,
        scope='user', type='user_delete',
        request_context=inspect.stack())


@receiver(user_logged_in)
def user_logged_in_callback(sender, request, user, **kwargs):
    from events.models import AuditLog
    ip = request.META.get('REMOTE_ADDR')
    message = 'login user: {user} via ip: {ip}'.format(user=user, ip=ip)
    logger.debug(message)
    AuditLog.objects.create(
        message=message,
        scope='user', type='user_login',
        request_context=inspect.stack())


@receiver(user_logged_out)
def user_logged_out_callback(sender, request, user, **kwargs):
    from events.models import AuditLog
    ip = request.META.get('REMOTE_ADDR')

    message = 'logout user: {user} via ip: {ip}'.format(user=user, ip=ip)
    logger.debug(message)
    AuditLog.objects.create(
        message=message,
        scope='user', type='user_logout',
        request_context=inspect.stack())


@receiver(user_login_failed)
def user_login_failed_callback(sender, credentials, **kwargs):
    from events.models import AuditLog

    logger.warning('login failed for: {credentials}'.format(
        credentials=credentials,
    ))
    message = 'login failed for: {credentials}'.format(credentials=credentials,)
    logger.debug(message)
    AuditLog.objects.create(
        message=message,
        scope='user', type='user_login_failed',
        request_context=inspect.stack())


class Team(AbstractOrganization):
    class Meta:
        db_table = 'teams'

    # def __str__(self):
    #     return "{}/{}".format(self.id, self.name)
    def __str__(self):
        return self.name


@receiver(post_save, sender=Team)
def team_create_update_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = ""
    if kwargs['created']:
        message = "[Team] New team created (id={}): {}".format(kwargs['instance'].id, kwargs['instance'])
        Event.objects.create(message=message, type="CREATE", severity="DEBUG")
    else:
        message = "[Team] Team '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id)
        Event.objects.create(message=message, type="UPDATE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='engine', type='team_create_update',
        request_context=inspect.stack())


@receiver(post_delete, sender=Team)
def team_delete_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = "[Team] Team '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")
    AuditLog.objects.create(
        message=message,
        scope='user', type='team_delete',
        request_context=inspect.stack())


class TeamUser(AbstractOrganizationUser):
    class Meta:
        db_table = 'team_users'


@receiver(post_save, sender=TeamUser)
def teamuser_create_update_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = ""
    if kwargs['created']:
        message = "[TeamUser] New team user created (id={}): {}".format(kwargs['instance'].id, kwargs['instance'])
        Event.objects.create(message=message, type="CREATE", severity="DEBUG")
    else:
        message = "[TeamUser] Team user '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id)
        Event.objects.create(message=message, type="UPDATE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='engine', type='teamuser_create_update',
        request_context=inspect.stack())


@receiver(post_delete, sender=TeamUser)
def teamuser_delete_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = "[TeamUser] Team user '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")
    AuditLog.objects.create(
        message=message,
        scope='user', type='teamuser_delete',
        request_context=inspect.stack())


class TeamOwner(AbstractOrganizationOwner):
    class Meta:
        db_table = 'team_owners'


@receiver(post_save, sender=TeamOwner)
def teamowner_create_update_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = ""
    if kwargs['created']:
        message = "[TeamOwner] New team owner created (id={}): {}".format(kwargs['instance'].id, kwargs['instance'])
        Event.objects.create(message=message, type="CREATE", severity="DEBUG")
    else:
        message = "[TeamOwner] Team owner '{}' modified (id={})".format(kwargs['instance'], kwargs['instance'].id)
        Event.objects.create(message=message, type="UPDATE", severity="DEBUG")

    AuditLog.objects.create(
        message=message,
        scope='engine', type='teamowner_create_update',
        request_context=inspect.stack())


@receiver(post_delete, sender=TeamOwner)
def teamowner_delete_log(sender, **kwargs):
    from events.models import Event, AuditLog
    message = "[TeamOwner] Team owner '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id)
    Event.objects.create(message=message, type="DELETE", severity="DEBUG")
    AuditLog.objects.create(
        message=message,
        scope='user', type='teamowner_delete',
        request_context=inspect.stack())
