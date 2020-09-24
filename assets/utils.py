from users.models import Team


def _get_allowed_team(team_name, user):
    team = None
    if user.is_superuser:
        team = Team.objects.filter(name__iexact=team_name).first()
    else:
        team = user.users_team.filter(name__iexact=team_name).first()

    return team
