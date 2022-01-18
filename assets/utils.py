from users.models import Team
from assets.models import Asset, AssetGroup


def _get_allowed_team(team_name, user):
    team = None
    if user.is_superuser:
        team = Team.objects.filter(name__iexact=team_name).first()
    else:
        team = user.users_team.filter(name__iexact=team_name).first()

    return team


def _add_new_asset(metadata):
    """
    Add new asset.

    {
        "datatype": rule['datatype'],
        "rule_name": rule['name'],
        "group_name": rule['group_name'],
        "asset_value": asset_value,
        "original_asset_value": self.asset.value,
        "asset_teams": self.asset.teams.all(),
    }
    """

    try:
        # Create the asset
        asset = Asset.objects.create(
            value=metadata["asset_value"],
            name=f"{metadata['asset_value']} (Auto-created)",
            type=metadata["datatype"],
            owner=metadata["owner"],
            description=f"Auto-created by finding evaluation rule ({metadata['rule_name']}) from asset {metadata['original_asset_value']}",
        )

        # Add related Teams
        for team in metadata["asset_teams"]:
            asset.teams.add(team)

        # Add it to a group
        asset_group = AssetGroup.objects.filter(name=metadata['group_name']).first()
        if asset_group is None:
            # Create it first
            asset_group = AssetGroup.objects.create(
                name=metadata['group_name'],
                owner=metadata["owner"],
                description=f"Auto-created by finding evaluation rule ({metadata['rule_name']})"
            )

            for team in metadata["asset_teams"]:
                asset_group.teams.add(team)

        # Add this asset to the group
        asset_group.assets.add(asset)

        # print(asset)
    except Exception:
        return None

    return asset.id
