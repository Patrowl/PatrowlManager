# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from django.db import models
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from organizations.abstract import (AbstractOrganization,
                                    AbstractOrganizationUser,
                                    AbstractOrganizationOwner)


USER_STATUS = (
    ('ACTIVE', 'ACTIVE'),
    ('DISABLED', 'DISABLED'),
)


class Profile(models.Model):
    # MANAGER = 1
    # ANALYST = 2
    # AUDITOR = 3
    #
    # ROLE_CHOICES = (
    #     (MANAGER, 'Manager'),
    #     (ANALYST, 'Analyst'),
    #     (AUDITOR, 'Auditor'),
    # )
    #
    # role = models.PositiveSmallIntegerField(choices=ROLE_CHOICES, default=ANALYST, blank=True, null=True)

    user = models.OneToOneField(get_user_model(), on_delete=models.CASCADE)
    status = models.CharField(choices=USER_STATUS, default='ACTIVE', max_length=10)
    # bio = models.TextField(max_length=500, blank=True)
    # department = models.CharField(max_length=100, blank=True)
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
    from events.models import Event
    if created:
        Profile.objects.create(user=instance, status='ACTIVE', bio="n/a", department="n/a")
        Event.objects.create(message="[User] New user created (id={}): {}".format(instance.id, instance),
                             type="CREATE", severity="DEBUG")


@receiver(post_save, sender=get_user_model())
def save_user_profile(sender, instance, **kwargs):
    instance.profile.save()


@receiver(post_delete, sender=get_user_model())
def delete_user_profile(sender, **kwargs):
    from events.models import Event
    Event.objects.create(message="[User] User '{}' deleted (id={})".format(kwargs['instance'], kwargs['instance'].id),
                 type="DELETE", severity="DEBUG")


class Team(AbstractOrganization):
    class Meta:
        db_table = 'teams'

    def __str__(self):
        return "{}/{}".format(self.id, self.name)


class TeamUser(AbstractOrganizationUser):
    class Meta:
        db_table = 'team_users'


class TeamOwner(AbstractOrganizationOwner):
    class Meta:
        db_table = 'team_owners'
