from users.models import Team, TeamUser, TeamOwner
from django.contrib.auth import get_user_model
admin_user = get_user_model().objects.get(username='admin')
if admin_user.users_team.count() == 0:
    admin_org = Team.objects.create(name='default', is_active=True)
    admin_org.save()
    org_user = TeamUser.objects.create(user=admin_user, organization=admin_org, is_admin=True)
    org_user.save()
    org_owner = TeamOwner.objects.create(organization=admin_org, organization_user=org_user)
    org_owner.save()
