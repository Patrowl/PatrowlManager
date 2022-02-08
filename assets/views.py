# -*- coding: utf-8 -*-

import csv
import copy

from django.http import JsonResponse
from django.forms.models import model_to_dict
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Value, CharField, Case, When, Q, F, Count
from django.db.models.functions import Lower
from django.conf import settings

from django.contrib import messages
from django.contrib.postgres.aggregates import ArrayAgg
from django.shortcuts import render, redirect, get_object_or_404
from findings.models import Finding
from engines.models import EnginePolicyScope, Engine
from scans.models import Scan, ScanDefinition
from users.models import Team, TeamUser
from common.utils import encoding, pro_group_required
from .forms import AssetForm, AssetGroupForm, DynamicAssetGroupForm, AssetBulkForm, AssetOwnerForm
from .models import Asset, AssetGroup, AssetOwner, AssetCategory, DynamicAssetGroup
from .models import ASSET_INVESTIGATION_LINKS
from .apis import _add_asset_tags
from .utils import _get_allowed_team


@pro_group_required('AssetsViewer', 'AssetsManager')
def list_assets_view(request):
    """List assets."""
    # Check team
    teamid_selected = -1
    if settings.PRO_EDITION is True and request.GET.get('team', '').isnumeric() and int(request.GET.get('team', -1)) >= 0:
        teamid = int(request.GET.get('team'))
        # @Todo: ensure the team is allowed for this user
        teamid_selected = teamid

    teams = []
    if settings.PRO_EDITION and request.user.is_superuser:
        teams = Team.objects.all().order_by('name')
    elif settings.PRO_EDITION and not request.user.is_superuser:
        for tu in TeamUser.objects.filter(user=request.user):
            teams.append({
                'id': tu.organization.id,
                'name': tu.organization.name
            })

    # Check sorting options
    allowed_sort_options = [
        "id", "name", "criticity_num", "score", "type",
        "updated_at", "risk_level", "risk_level__grade",
        "-id", "-name", "-criticity_num", "-score",
        "-type", "-updated_at", "-risk_level",
        "-risk_level__grade"
    ]
    sort_options = request.GET.get("sort", "-updated_at")
    sort_options_valid = ["-updated_at"]
    for s in sort_options.split(","):
        if s in allowed_sort_options and s not in sort_options_valid:
            sort_options_valid.append(str(s))

    # Check Filtering options
    # filter_options = request.GET.get("filter", "")
    filter_name = request.GET.get("filter_name", "")
    filter_type = request.GET.get("filter_type", "")
    filter_criticity = request.GET.get("filter_criticity", "")
    filter_tag = request.GET.get("filter_tag", "")

    # filter_fields = {}

    if teamid_selected >= 0:
        assets_list = Asset.objects.for_team(request.user, teamid_selected).prefetch_related('teams', 'categories').all()
    else:
        assets_list = Asset.objects.for_user(request.user).prefetch_related('teams', 'categories').all()
    filters = Q()
    if filter_name and filter_name != 'null':
        filter_name = filter_name.split(',')
        for term in filter_name:
            filters |= (Q(name__icontains=term) | Q(description__icontains=term))
    if filter_type and filter_type != 'null':
        filters &= Q(type=filter_type)
    if filter_criticity and filter_criticity != 'null':
        filters &= Q(criticity=filter_criticity)
    if filter_tag and filter_tag != 'null':
        filter_tag = filter_tag.split(',')
        # https://stackoverflow.com/questions/25831081/django-orm-dynamically-add-multiple-conditions-for-manytomanyfield
        for tag in filter_tag:
            assets_list = assets_list.filter(categories__value=tag)

    # Query
    if teamid_selected >= 0:
        assets_list = assets_list.filter(filters).annotate(
            criticity_num=Case(
                When(criticity="high", then=Value("1")),
                When(criticity="medium", then=Value("2")),
                When(criticity="low", then=Value("3")),
                default=Value("1"),
                output_field=CharField())
            ).annotate(cat_list=ArrayAgg('categories__value')).order_by(*sort_options_valid)
    else:
        assets_list = assets_list.filter(filters).annotate(
            criticity_num=Case(
                When(criticity="high", then=Value("1")),
                When(criticity="medium", then=Value("2")),
                When(criticity="low", then=Value("3")),
                default=Value("1"),
                output_field=CharField())
            ).annotate(cat_list=ArrayAgg('categories__value')).order_by(*sort_options_valid)

    # Pagination assets
    nb_rows_assets = request.GET.get('n_a', 20)
    nb_rows_assetgroups = request.GET.get('n_ag', 20)
    nb_rows_dynamicassetgroups = request.GET.get('n_dag', 20)
    if str(nb_rows_assets).isnumeric() is False:
        nb_rows_assets = 20
    if str(nb_rows_assetgroups).isnumeric() is False:
        nb_rows_assetgroups = 20
    if str(nb_rows_dynamicassetgroups).isnumeric() is False:
        nb_rows_dynamicassetgroups = 20

    assets_paginator = Paginator(assets_list, nb_rows_assets)
    page = request.GET.get('p_a')
    try:
        assets = assets_paginator.page(page)
    except PageNotAnInteger:
        assets = assets_paginator.page(1)
    except EmptyPage:
        assets = assets_paginator.page(assets_paginator.num_pages)

    # List asset groups
    asset_groups_list = []
    if teamid_selected >= 0:
        ags = AssetGroup.objects.for_team(request.user, teamid_selected).prefetch_related('teams', 'categories').all().annotate(
            asset_list=ArrayAgg('assets__value')
        ).only(
            "id", "name", "assets", "criticity",
            "updated_at", "risk_level", "teams"
        )
    else:
        ags = AssetGroup.objects.for_user(request.user).prefetch_related('teams', 'categories').all().annotate(
            asset_list=ArrayAgg('assets__value')
        ).only(
            "id", "name", "assets", "criticity",
            "updated_at", "risk_level", "teams"
        )

    for asset_group in ags.order_by(Lower("name")):
        assets_names = ""
        if asset_group.asset_list != [None]:
            assets_names = ", ".join(asset_group.asset_list)
        ag = {
            "id": asset_group.id,
            "name": asset_group.name,
            "criticity": asset_group.criticity,
            "updated_at": asset_group.updated_at,
            "assets_names": assets_names,
            "risk_grade": asset_group.risk_level['grade'],
            "teams": asset_group.teams
        }
        asset_groups_list.append(ag)

    asset_groups_paginator = Paginator(asset_groups_list, nb_rows_assetgroups)
    page_ag = request.GET.get('p_ag')
    try:
        asset_groups = asset_groups_paginator.page(page_ag)
    except PageNotAnInteger:
        asset_groups = asset_groups_paginator.page(1)
    except EmptyPage:
        asset_groups = asset_groups_paginator.page(asset_groups_paginator.num_pages)

    # List dynamic asset groups
    dynamic_asset_groups_list = []
    if teamid_selected >= 0:
        dags = DynamicAssetGroup.objects.for_team(request.user, teamid_selected).prefetch_related('teams', 'tags').all().annotate(tag_list=ArrayAgg('tags__value')).only(
            "id", "name", "criticity", "updated_at", "risk_level", "teams"
        )
    else:
        dags = DynamicAssetGroup.objects.for_user(request.user).prefetch_related('teams', 'tags').all().annotate(tag_list=ArrayAgg('tags__value')).only(
            "id", "name", "criticity", "updated_at", "risk_level", "teams"
        )

    for dynamic_asset_group in dags.order_by(Lower("name")):
        # assets_names = ""
        # if len(dynamic_asset_group.get_assets()) > 1:
        #     assets_names = ", ".join(dynamic_asset_group.get_assets())
        dag = {
            "id": dynamic_asset_group.id,
            "name": dynamic_asset_group.name,
            "criticity": dynamic_asset_group.criticity,
            "tags": dynamic_asset_group.tag_list,
            "assets": dynamic_asset_group.get_assets(),
            "updated_at": dynamic_asset_group.updated_at,
            "teams": dynamic_asset_group.teams
        }
        dynamic_asset_groups_list.append(dag)

    dynamic_asset_groups_paginator = Paginator(dynamic_asset_groups_list, nb_rows_dynamicassetgroups)
    page_dag = request.GET.get('p_dag')
    try:
        dynamic_asset_groups = dynamic_asset_groups_paginator.page(page_dag)
    except PageNotAnInteger:
        dynamic_asset_groups = dynamic_asset_groups_paginator.page(1)
    except EmptyPage:
        dynamic_asset_groups = dynamic_asset_groups_paginator.page(dynamic_asset_groups_paginator.num_pages)

    tags = assets_list.values_list('categories__value', flat=True).order_by('categories__value').distinct()
    owners = AssetOwner.objects.all()

    return render(request, 'list-assets.html', {
        'assets': assets,
        'asset_groups': asset_groups,
        'dynamic_asset_groups': dynamic_asset_groups,
        'teams': teams,
        'tags': tags,
        'owners': owners
    })


@pro_group_required('AssetsManager')
def add_asset_view(request):
    """Add a new asset."""
    form = None

    if request.method == 'GET':
        form = AssetForm(user=request.user)
    elif request.method == 'POST':
        form = AssetForm(request.POST, user=request.user)

        if not Asset.is_savable():
            messages.error(request, 'MAX_ASSETS reached. Contact Support team ;)')
            return render(request, 'add-asset.html', {'form': form})

        if form.is_valid():
            asset_args = {
                'value': encoding.unicode_escape(form.cleaned_data['value']),
                'name': form.cleaned_data['name'],
                'type': form.cleaned_data['type'],
                'criticity': form.cleaned_data['criticity'],
                'exposure': form.cleaned_data['exposure'],
                'description': form.cleaned_data['description'],
                'owner': request.user,
            }
            asset = Asset(**asset_args)
            asset.save()

            # Add categories (M2M)
            if len(form.cleaned_data['categories']) == 0:
                asset.categories.add(AssetCategory.objects.get(id=1))
            else:
                for cat in form.cleaned_data['categories']:
                    asset.categories.add(cat)

            # Add teams (M2M)
            if 'teams' in form.cleaned_data.keys():
                for team in form.cleaned_data['teams']:
                    asset.teams.add(team)

            # Save categories and teams
            asset.save()

            if asset.type in ['ip-range', 'ip-subnet']:
                # Create an asset group dynamically
                assetgroup_args = {
                    'name': "{} assets".format(asset.name),
                    'criticity': asset.criticity,
                    'description': "Asset dynamically created. Imported desc: {}".format(asset.description),
                    'owner': request.user
                }
                asset_group = AssetGroup(**assetgroup_args)
                asset_group.save()

                # Add the asset to the new group
                asset_group.assets.add(asset)

                # Add the teams to the new group
                for team in form.cleaned_data['teams']:
                    asset_group.teams.add(team)
                asset_group.save()

                # Caculate the risk grade
                asset_group.calc_risk_grade()
                asset_group.save()

            messages.success(request, 'New asset created')
            return redirect('detail_asset_view', asset_id=asset.id)

    return render(request, 'add-asset.html', {'form': form})


@pro_group_required('AssetsManager')
def edit_asset_view(request, asset_id):
    """Edit an asset."""
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)

    form = AssetForm(user=request.user)
    if request.method == 'GET':
        form = AssetForm(instance=asset, user=request.user)
    elif request.method == 'POST':
        form = AssetForm(request.POST, instance=asset, user=request.user)
        if form.is_valid():
            # asset.value = form.cleaned_data['value']
            asset.name = form.cleaned_data['name']
            asset.type = form.cleaned_data['type']
            asset.description = form.cleaned_data['description']
            asset.criticity = form.cleaned_data['criticity']
            asset.exposure = form.cleaned_data['exposure']
            asset.evaluate_risk()

            # Update categories (M2M)
            asset.categories.clear()
            if len(form.cleaned_data['categories']) == 0:
                # Add a default category
                asset.categories.add(AssetCategory.objects.get(id=1))
            else:
                for cat_id in form.data.getlist('categories'):
                    asset.categories.add(AssetCategory.objects.get(id=cat_id))

            # Update teams (M2M)
            if 'teams' in form.cleaned_data.keys():
                asset.teams.clear()
                for team in form.cleaned_data['teams']:
                    asset.teams.add(team)

            # Save categories and teams
            asset.save()

            messages.success(request, 'Update submission successful')
            return redirect('detail_asset_view', asset_id=asset_id)

    return render(request, 'edit-asset.html', {'form': form, 'asset': asset})


@pro_group_required('AssetsManager')
def add_asset_group_view(request):
    """Add an asset group."""
    form = None

    if request.method == 'GET':
        form = AssetGroupForm(user=request.user)
        teams_list = request.user.users_team.values('id', 'name').order_by('name')
    elif request.method == 'POST':
        form = AssetGroupForm(request.POST, user=request.user)
        if form.is_valid():
            asset_args = {
                'name': form.cleaned_data['name'],
                'criticity': form.cleaned_data['criticity'],
                'description': form.cleaned_data['description'],
                'owner': request.user
            }
            asset_group = AssetGroup(**asset_args)
            asset_group.save()

            for asset_id in form.data.getlist('assets'):
                asset_group.assets.add(Asset.objects.for_user(request.user).get(id=asset_id))
            asset_group.save()

            # Add categories
            #for cat in form.data['categories']:
            #    asset_group.categories.add(cat)

            # Add the teams to the new group
            if 'teams' in form.cleaned_data.keys():
                for team in form.cleaned_data['teams']:
                    asset_group.teams.add(team)

            asset_group.save()

            asset_group.calc_risk_grade()
            asset_group.save()
            messages.success(request, 'Creation submission successful')

            return redirect('detail_asset_group_view', assetgroup_id=asset_group.id)
    return render(request, 'add-asset-group.html', {'form': form, 'teams_list': teams_list})


@pro_group_required('AssetsManager')
def add_dyn_asset_group_view(request):
    """Add a dynamic asset group."""
    form = None

    if request.method == 'GET':
        form = DynamicAssetGroupForm(user=request.user)
        teams_list = request.user.users_team.values('id', 'name').order_by('name')
        tags_list = AssetCategory.objects.all()
    elif request.method == 'POST':
        form = DynamicAssetGroupForm(request.POST, user=request.user)
        if form.is_valid():
            asset_args = {
                'name': form.cleaned_data['name'],
                'criticity': form.cleaned_data['criticity'],
                'description': form.cleaned_data['description'],
                'owner': request.user
            }
            asset_group = DynamicAssetGroup(**asset_args)
            asset_group.save()

            # Add tags
            if 'tags' in form.cleaned_data.keys():
                for tag in form.cleaned_data['tags']:
                    asset_group.tags.add(tag)

            # Add the teams to the new group
            if 'teams' in form.cleaned_data.keys():
                for team in form.cleaned_data['teams']:
                    asset_group.teams.add(team)

            # asset_group.save()

            asset_group.calc_risk_grade()
            asset_group.save()
            messages.success(request, 'Creation submission successful')

            return redirect('detail_dynamic_asset_group_view', assetgroup_id=asset_group.id)
    return render(request, 'add-dyn-asset-group.html', {
        'form': form, 'teams_list': teams_list, 'tags_list': tags_list
    })


@pro_group_required('AssetsManager')
def edit_asset_group_view(request, assetgroup_id):
    """Edit an asset group."""
    asset_group = get_object_or_404(AssetGroup.objects.for_user(request.user).prefetch_related('teams', 'assets', 'categories'), id=assetgroup_id)

    form = AssetGroupForm(user=request.user)
    if request.method == 'GET':
        form = AssetGroupForm(instance=asset_group, user=request.user)
        teams_list = request.user.users_team.values('id', 'name').order_by('name')
    elif request.method == 'POST':
        form = AssetGroupForm(request.POST, instance=asset_group, user=request.user)
        if form.is_valid():
            if asset_group.name != form.cleaned_data['name']:
                asset_group.name = form.cleaned_data['name']
            asset_group.description = form.cleaned_data['description']
            #asset_group.criticity = form.cleaned_data['criticity']

            # Update assets
            asset_group.assets.clear()
            
            for asset_id in form.data.getlist('assets'):
                asset_group.assets.add(Asset.objects.for_user(request.user).get(id=asset_id))

            # Update the teams
            if 'teams' in form.cleaned_data.keys():
                asset_group.teams.clear()
                for team in form.cleaned_data['teams']:
                    asset_group.teams.add(team)

            asset_group.evaluate_risk()
            asset_group.save()

            asset_group.calc_risk_grade()
            asset_group.save()

            messages.success(request, 'Update submission successful')
            return redirect('detail_asset_group_view', assetgroup_id=assetgroup_id)

    return render(request, 'edit-asset-group.html', {
        'form': form,
        'assetgroup_id': assetgroup_id,
        'asset_group': asset_group,
        'teams_list': teams_list
    })


@pro_group_required('AssetsManager')
def edit_dyn_asset_group_view(request, assetgroup_id):
    """Edit a dynamic asset group."""
    asset_group = get_object_or_404(DynamicAssetGroup.objects.for_user(request.user).prefetch_related('teams', 'tags'), id=assetgroup_id)

    form = DynamicAssetGroupForm(user=request.user)
    if request.method == 'GET':
        form = DynamicAssetGroupForm(instance=asset_group, user=request.user)
        teams_list = request.user.users_team.values('id', 'name').order_by('name')
        tags_list = AssetCategory.objects.all()
    elif request.method == 'POST':
        form = DynamicAssetGroupForm(request.POST, instance=asset_group, user=request.user)
        if form.is_valid():
            if asset_group.name != form.cleaned_data['name']:
                asset_group.name = form.cleaned_data['name']
            asset_group.description = form.cleaned_data['description']
            asset_group.criticity = form.cleaned_data['criticity']

            # Add tags
            if 'tags' in form.cleaned_data.keys():
                asset_group.tags.clear()
                for tag in form.cleaned_data['tags']:
                    asset_group.tags.add(tag)

            # Update the teams
            if 'teams' in form.cleaned_data.keys():
                asset_group.teams.clear()
                for team in form.cleaned_data['teams']:
                    asset_group.teams.add(team)
            #
            # asset_group.evaluate_risk()
            # asset_group.save()

            asset_group.calc_risk_grade()
            asset_group.save()

            messages.success(request, 'Update submission successful')
            return redirect('detail_dynamic_asset_group_view', assetgroup_id=assetgroup_id)

    return render(request, 'edit-dyn-asset-group.html', {
        'form': form,
        'assetgroup_id': assetgroup_id,
        'asset_group': asset_group,
        'teams_list': teams_list,
        'tags_list': tags_list
    })


def _import_asset_from_csv(request, line, m):
    """Import asset from a CSV file (bulk import)."""
    asset = None
    if Asset.objects.for_user(request.user).filter(value=line['asset_value']).count() > 0:
        asset = Asset.objects.for_user(request.user).filter(value=line['asset_value']).first()
        # continue
        m.warning(request, "Asset '{}' already created. Updates are not applied.".format(asset))
    else:
        # Set default criticity/criticality
        asset_criticity = 'low'
        if 'asset_criticality' in line.keys() and str(line['asset_criticality']).lower() in ['low', 'medium', 'high']:
            asset_criticity = str(line['asset_criticality']).lower()
        if 'asset_criticity' in line.keys() and str(line['asset_criticity']).lower() in ['low', 'medium', 'high']:
            asset_criticity = str(line['asset_criticity']).lower()

        # Set default exposure
        if 'asset_exposure' not in line.keys():
            line['asset_exposure'] = 'unknown'
        asset_exposure = str(line['asset_exposure']).lower()
        if asset_exposure not in ['unknown', 'external', 'internal', 'restricted']:
            asset_exposure = 'unknown'

        asset_args = {
            'value': line['asset_value'],
            'name': line['asset_name'],
            'type': line['asset_type'],
            'description': line['asset_description'],
            'criticity': asset_criticity,
            'exposure': asset_exposure,
            'owner': request.user,
            'status': "new",
        }
        asset = Asset(**asset_args)
        asset.save()

    # Add groups
    if 'asset_groupname' in line and line['asset_groupname'] != "":
        # ag = AssetGroup.objects.for_user(request.user).filter(name=str(line['asset_groupname'])).first()
        ag = AssetGroup.objects.filter(name=str(line['asset_groupname'])).first()
        if ag is None:  # Create new asset group
            asset_args = {
                'name': str(line['asset_groupname']),
                'criticity': "low",
                'description': "Created automatically on asset upload.",
                'owner': request.user
            }
            ag = AssetGroup(**asset_args)
            ag.save()
        # add the asset to the group
        ag.assets.add(asset)

    # Manage tags (categories)
    if 'asset_tags' in line and line['asset_tags'] != "":
        for tag in line['asset_tags'].split(","):
            new_tag = _add_asset_tags(asset, tag)
            asset.categories.add(new_tag)
        asset.save()

    # Manage teams
    if 'asset_teams' in line and line['asset_teams'] != "":
        for team in line['asset_teams'].split(","):
            new_team = _get_allowed_team(team.lower(), request.user)
            if new_team is not None:
                asset.teams.add(new_team)
        asset.save()
    return asset


@pro_group_required('AssetsManager')
def bulkadd_asset_view(request):
    """Import assets from a CSV file (bulk import)."""
    form = None

    if request.method == 'GET' or request.method != 'POST' or request.FILES is False:
        form = AssetBulkForm()
        return render(request, 'add-assets-bulk.html', {'form': form})

    form = AssetBulkForm(request.POST, request.FILES)
    # if request.FILES:
    csv_file = request.FILES['file']
    try:
        decoded_file = csv_file.read().decode('utf-8-sig').splitlines()
        records = csv.DictReader(decoded_file, delimiter=';')
    except Exception:
        messages.error(request, "Unable to process CSV file '{}'. Check weird chars. No assets imported.".format(asset))
        return redirect('list_assets_view')

    # Note: Header is skiped automatically
    for line in records:
        # Add assets
        asset = None
        try:
            asset = _import_asset_from_csv(request, line, messages)
            messages.success(request, "Asset '{}' successfully imported".format(asset))
        except Exception:
            messages.error(request, "Error importing asset '{}' from CSV file. Updates are not applied.".format(asset))
    return redirect('list_assets_view')


# todo: change to asset_id
@pro_group_required('AssetsManager')
def evaluate_asset_risk_view(request, asset_name):
    """Evaluate asset risk metrics."""
    asset = get_object_or_404(Asset.objects.for_user(request.user), value=asset_name)
    data = asset.evaluate_risk()
    return JsonResponse(data, safe=False)


@pro_group_required('AssetsManager', 'AssetsViewer')
def detail_asset_view(request, asset_id):
    """Return asset details."""
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
    findings = Finding.objects.filter(asset=asset).annotate(
        severity_numm=Case(
            When(severity="critical", then=Value("0")),
            When(severity="high", then=Value("1")),
            When(severity="medium", then=Value("2")),
            When(severity="low", then=Value("3")),
            When(severity="info", then=Value("4")),
            default=Value("1"),
            output_field=CharField())
        ).annotate(
            scope_list=ArrayAgg('scopes__name')
        ).order_by(
            'severity_numm', 'type', 'updated_at'
        ).only(
            "severity", "status", "engine_type", "risk_info", "vuln_refs",
            "title", "id", "solution", "updated_at", "type"
        )

    findings_stats = {
        'total': 0, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
        'new': 0, 'ack': 0, 'false-positive': 0, 'duplicate': 0, 'closed': 0,
        'mitigated': 0, 'reopened': 0,
        'cvss_gte_7': 0
    }
    engines_stats = {}
    references = {}

    engine_scopes = {}
    for engine_scope in EnginePolicyScope.objects.all():
        engine_scopes.update({
            engine_scope.name: {
                'priority': engine_scope.priority,
                'id': engine_scope.id,
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        })

    for finding in findings:
        findings_stats['total'] = findings_stats.get('total', 0) + 1
        if finding.status not in ["false-positive", "duplicate", "closed", "mitigated", "undone", "patched"]:
            findings_stats[finding.severity] = findings_stats.get(finding.severity, 0) + 1
        if finding.status == 'new':
            findings_stats['new'] = findings_stats.get('new', 0) + 1
        elif finding.status == 'ack':
            findings_stats['ack'] = findings_stats.get('ack', 0) + 1
        elif finding.status == 'duplicate':
            findings_stats['duplicate'] = findings_stats.get('duplicate', 0) + 1
        elif finding.status == 'false-positive':
            findings_stats['false-positive'] = findings_stats.get('false-positive', 0) + 1
        elif finding.status == 'closed':
            findings_stats['closed'] = findings_stats.get('closed', 0) + 1
        elif finding.status == 'mitigated':
            findings_stats['mitigated'] = findings_stats.get('mitigated', 0) + 1
        elif finding.status == 'reopened':
            findings_stats['reopened'] = findings_stats.get('reopened', 0) + 1

        for fs in finding.scope_list:
            if fs is not None:
                c = engine_scopes[fs]
                engine_scopes[fs].update({
                    'total': c['total'] + 1,
                    finding.severity: c[finding.severity] + 1
                })
        if finding.engine_type not in engines_stats.keys():
            engines_stats.update({finding.engine_type: 0})
        engines_stats[finding.engine_type] = engines_stats.get(finding.engine_type, 0) + 1
        if finding.risk_info["cvss_base_score"] > 7.0:
            findings_stats['cvss_gte_7'] = findings_stats.get('cvss_gte_7', 0) + 1

        if bool(finding.vuln_refs):
            for ref in finding.vuln_refs.keys():
                if ref not in references.keys():
                    references.update({ref: []})
                tref = references[ref]
                if type(finding.vuln_refs[ref]) is list:
                    tref = tref + finding.vuln_refs[ref]
                else:
                    tref.append(finding.vuln_refs[ref])

                references.update({ref: tref})

    # Show only unique references
    references_cleaned = {}
    for ref in references:
        references_cleaned.update({ref: sorted(list(set(references[ref])))})

    # Related scans
    scans_stats = {
        'performed': Scan.objects.filter(assets__in=[asset]).count(),
        'defined': ScanDefinition.objects.filter(assets_list__in=[asset]).count(),
        'periodic': ScanDefinition.objects.filter(assets_list__in=[asset], scan_type='periodic').count(),
        'ondemand': ScanDefinition.objects.filter(assets_list__in=[asset], scan_type='single').count(),
        'running': Scan.objects.filter(assets__in=[asset], status='started').count(),  # bug: a regrouper par assets
        'lasts': Scan.objects.filter(assets__in=[asset]).order_by('-updated_at')[:3]
    }

    asset_groups = list(AssetGroup.objects.for_user(request.user).filter(assets__in=[asset]).only("id"))
    # dyn_asset_groups = list(DynamicAssetGroup.objects.for_user(request.user).filter(tags__in=asset.categories.all()).only("id"))
    # print(dyn_asset_groups)
    scan_defs = ScanDefinition.objects.filter(Q(assets_list__in=[asset]) | Q(assetgroups_list__in=asset_groups)).annotate(engine_type_name=F('engine_type__name')).annotate(scan_set_count=Count('scan')).order_by('-updated_at')
    scans = Scan.objects.filter(assets__in=[asset]).values("id", "title", "status", "summary", "updated_at").annotate(engine_type_name=F('engine_type__name')).order_by('-updated_at')

    # Investigation links
    investigation_links = []
    DEFAULT_LINKS = copy.deepcopy(ASSET_INVESTIGATION_LINKS)
    for i in DEFAULT_LINKS:
        if asset.type in i["datatypes"]:
            if "link" in i.keys():
                i["link"] = i["link"].replace("%asset%", asset.value)
                investigation_links.append(i)

    # Calculate automatically risk grade
    asset.calc_risk_grade()
    asset_risk_grade = {
        'now': asset.get_risk_grade(),
        'day_ago': asset.get_risk_grade(history=1),
        'week_ago': asset.get_risk_grade(history=7),
        'month_ago': asset.get_risk_grade(history=30),
        'year_ago': asset.get_risk_grade(history=365)
    }

    return render(request, 'details-asset.html', {
        'asset': asset,
        'asset_risk_grade': asset_risk_grade,
        'findings': findings,
        'findings_stats': findings_stats,
        'references': references_cleaned,
        'scans_stats': scans_stats,
        'scans': scans,
        'scan_defs': scan_defs,
        'investigation_links': investigation_links,
        'engines_stats': engines_stats,
        'asset_scopes': list(engine_scopes.items())
    })


@pro_group_required('AssetsManager', 'AssetsViewer')
def detail_asset_group_view(request, assetgroup_id):
    """Return asset group details."""
    asset_group = get_object_or_404(AssetGroup.objects.for_user(request.user).prefetch_related('categories', 'assets'), id=assetgroup_id)

    assets_list = asset_group.assets.all().order_by("-risk_level__grade", "criticity", "type")

    findings = Finding.objects.severity_ordering().filter(
        asset__in=asset_group.assets.all()
    ).order_by(
        '-severity_order', 'asset', 'type', 'updated_at'
    ).only(
        "severity", "status", "engine_type", "risk_info", "vuln_refs",
        "title", "id", "solution", "updated_at", "type", "asset_id",
        "asset_name")

    asset_scopes = {}
    for scope in EnginePolicyScope.objects.all():
        asset_scopes.update({
            scope.name: {
                'priority': scope.priority,
                'id': scope.id,
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        })

    findings_stats = {
        'total': 0,
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
        'new': 0, 'ack': 0
    }
    engines_stats = {}

    # for finding in findings:
    #     for fs in finding.scope_list:
    #         if fs is not None:
    #             c = asset_scopes[fs]
    #             asset_scopes[fs].update({'total': c['total']+1, finding.severity: c[finding.severity]+1})
    #     if finding.engine_type not in engines_stats.keys():
    #         engines_stats.update({finding.engine_type: 0})
    #     engines_stats[finding.engine_type] = engines_stats.get(finding.engine_type, 0) + 1

    engines_stats_filter_agg = {}
    for engine in Engine.objects.values_list('name', flat=True):
        engines_stats_filter_agg.update({
            f"engine_{engine}": Count('id', filter=Q(engine_type=engine))
        })

    engines_scopes_filter_agg = {}
    # scope_names = EnginePolicyScope.objects.values_list('name', flat=True)
    # for scope in scope_names:
    #     engines_scopes_filter_agg.update({
    #         f"scope_{scope}_total": Count('id', filter=Q(scopes__name=scope)),
    #         f"scope_{scope}_info": Count('id', filter=Q(scopes__name=scope, severity='info')),
    #         f"scope_{scope}_low": Count('id', filter=Q(scopes__name=scope, severity='low')),
    #         f"scope_{scope}_medium": Count('id', filter=Q(scopes__name=scope, severity='medium')),
    #         f"scope_{scope}_high": Count('id', filter=Q(scopes__name=scope, severity='high')),
    #         f"scope_{scope}_critical": Count('id', filter=Q(scopes__name=scope, severity='critical')),
    #     })

    # Sorry...
    findings_stats = findings.aggregate(
        nb_new=Count('id', filter=Q(status='new')),
        nb_ack=Count('id', filter=Q(status='ack')),
        nb_critical=Count('id', filter=Q(severity='critical')),
        nb_high=Count('id', filter=Q(severity='high')),
        nb_medium=Count('id', filter=Q(severity='medium')),
        nb_low=Count('id', filter=Q(severity='low')),
        nb_info=Count('id', filter=Q(severity='info')),
        total=Count('id'),
        **engines_stats_filter_agg,
        **engines_scopes_filter_agg
    )

    # Sorry again...
    # for scope in scope_names:
    #     asset_scopes[scope].update({
    #         'total': findings_stats['scope_'+scope+'_total'],
    #         'info': findings_stats['scope_'+scope+'_info'],
    #         'low': findings_stats['scope_'+scope+'_low'],
    #         'medium': findings_stats['scope_'+scope+'_medium'],
    #         'high': findings_stats['scope_'+scope+'_high'],
    #         'critical': findings_stats['scope_'+scope+'_critical'],
    #     })

    # Scans
    scan_defs = ScanDefinition.objects.filter(
        Q(assetgroups_list__in=[asset_group])
    ).annotate(
        engine_type_name=F('engine_type__name'),
        nb_scans=Count('scan')
    )

    scan_defs_stats = scan_defs.aggregate(
        nb_periodic=Count('id', filter=Q(scan_type='periodic')),
        nb_ondemand=Count('id', filter=Q(scan_type='single')),
        nb_running=Count('id', filter=Q(scan_type='started')),
    )

    scans = Scan.objects.filter(scan_definition__in=scan_defs)

    scans_stats = {
        'performed': len(scans),
        'defined': len(scan_defs),
        'periodic': scan_defs_stats['nb_periodic'],
        'ondemand': scan_defs_stats['nb_ondemand'],
        'running': scan_defs_stats['nb_running']
    }

    # calculate automatically risk grade
    # asset_group.calc_risk_grade()
    asset_group_risk_grade = {
        'now': asset_group.get_risk_grade(),
        # 'day_ago': asset_group.get_risk_grade(history = 1),
        # 'week_ago': asset_group.get_risk_grade(history = 7),
        # 'month_ago': asset_group.get_risk_grade(history = 30),
        # 'year_ago': asset_group.get_risk_grade(history = 365)
    }

    # Paginations
    # Pagination assets
    nb_rows = int(request.GET.get('n_assets', 25))
    assets_paginator = Paginator(assets_list, nb_rows)
    page = request.GET.get('p_assets', 1)
    try:
        assets = assets_paginator.page(page)
    except PageNotAnInteger:
        assets = assets_paginator.page(1)
    except EmptyPage:
        assets = assets_paginator.page(assets_paginator.num_pages)

    # Pagination findings
    nb_rows = int(request.GET.get('n_findings', 50))
    findings_paginator = Paginator(findings, nb_rows)
    page = request.GET.get('p_findings', 1)
    try:
        ag_findings = findings_paginator.page(page)
    except PageNotAnInteger:
        ag_findings = findings_paginator.page(1)
    except EmptyPage:
        ag_findings = findings_paginator.page(findings_paginator.num_pages)

    return render(request, 'details-asset-group.html', {
        'asset_group': asset_group,
        'asset_group_risk_grade': asset_group_risk_grade,
        'assets': assets,
        'findings': ag_findings,
        'findings_stats': findings_stats,
        'scans_stats': scans_stats,
        'scans': scans,
        'scan_defs': scan_defs,
        'engines_stats': engines_stats,
        'asset_scopes': list(asset_scopes.items())
    })


@pro_group_required('AssetsManager', 'AssetsViewer')
def detail_dynamic_asset_group_view(request, assetgroup_id):
    """Return dynamic asset group details."""
    asset_group = get_object_or_404(DynamicAssetGroup.objects.for_user(request.user).prefetch_related('tags'), id=assetgroup_id)

    # assets_list = asset_group.assets.all().order_by("-risk_level__grade", "criticity", "type")
    assets_list = asset_group.get_assets().order_by("-risk_level__grade", "criticity", "type")

    findings = Finding.objects.severity_ordering().filter(
        asset__in=asset_group.get_assets()
    ).order_by(
        '-severity_order', 'asset', 'type', 'updated_at'
    ).only(
        "severity", "status", "engine_type", "risk_info", "vuln_refs",
        "title", "id", "solution", "updated_at", "type", "asset_id",
        "asset_name")

    asset_scopes = {}
    for scope in EnginePolicyScope.objects.all():
        asset_scopes.update({
            scope.name: {
                'priority': scope.priority,
                'id': scope.id,
                'total': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        })

    findings_stats = {
        'total': 0,
        'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
        'new': 0, 'ack': 0
    }
    engines_stats = {}

    # for finding in findings:
    #     for fs in finding.scope_list:
    #         if fs is not None:
    #             c = asset_scopes[fs]
    #             asset_scopes[fs].update({'total': c['total']+1, finding.severity: c[finding.severity]+1})
    #     if finding.engine_type not in engines_stats.keys():
    #         engines_stats.update({finding.engine_type: 0})
    #     engines_stats[finding.engine_type] = engines_stats.get(finding.engine_type, 0) + 1

    engines_stats_filter_agg = {}
    for engine in Engine.objects.values_list('name', flat=True):
        engines_stats_filter_agg.update({
            f"engine_{engine}": Count('id', filter=Q(engine_type=engine))
        })

    engines_scopes_filter_agg = {}

    # Sorry...
    findings_stats = findings.aggregate(
        nb_new=Count('id', filter=Q(status='new')),
        nb_ack=Count('id', filter=Q(status='ack')),
        nb_critical=Count('id', filter=Q(severity='critical')),
        nb_high=Count('id', filter=Q(severity='high')),
        nb_medium=Count('id', filter=Q(severity='medium')),
        nb_low=Count('id', filter=Q(severity='low')),
        nb_info=Count('id', filter=Q(severity='info')),
        total=Count('id'),
        **engines_stats_filter_agg,
        **engines_scopes_filter_agg
    )

    # Sorry again...
    # for scope in scope_names:
    #     asset_scopes[scope].update({
    #         'total': findings_stats['scope_'+scope+'_total'],
    #         'info': findings_stats['scope_'+scope+'_info'],
    #         'low': findings_stats['scope_'+scope+'_low'],
    #         'medium': findings_stats['scope_'+scope+'_medium'],
    #         'high': findings_stats['scope_'+scope+'_high'],
    #         'critical': findings_stats['scope_'+scope+'_critical'],
    #     })

    # Scans
    scan_defs = ScanDefinition.objects.filter(
        Q(dynassetgroups_list__in=[asset_group])
    ).annotate(
        engine_type_name=F('engine_type__name'),
        nb_scans=Count('scan')
    )
    # scan_defs = ScanDefinition.objects.filter(id=0)

    scan_defs_stats = scan_defs.aggregate(
        nb_periodic=Count('id', filter=Q(scan_type='periodic')),
        nb_ondemand=Count('id', filter=Q(scan_type='single')),
        nb_running=Count('id', filter=Q(scan_type='started')),
    )

    scans = Scan.objects.filter(scan_definition__in=scan_defs)

    scans_stats = {
        'performed': len(scans),
        'defined': len(scan_defs),
        'periodic': scan_defs_stats['nb_periodic'],
        'ondemand': scan_defs_stats['nb_ondemand'],
        'running': scan_defs_stats['nb_running']
    }

    # calculate automatically risk grade
    asset_group_risk_grade = {
        'now': asset_group.get_risk_grade(),
        # 'day_ago': asset_group.get_risk_grade(history = 1),
        # 'week_ago': asset_group.get_risk_grade(history = 7),
        # 'month_ago': asset_group.get_risk_grade(history = 30),
        # 'year_ago': asset_group.get_risk_grade(history = 365)
    }

    # Paginations
    # Pagination assets
    nb_rows = int(request.GET.get('n_assets', 25))
    assets_paginator = Paginator(assets_list, nb_rows)
    page = request.GET.get('p_assets', 1)
    try:
        assets = assets_paginator.page(page)
    except PageNotAnInteger:
        assets = assets_paginator.page(1)
    except EmptyPage:
        assets = assets_paginator.page(assets_paginator.num_pages)

    # Pagination findings
    nb_rows = int(request.GET.get('n_findings', 50))
    findings_paginator = Paginator(findings, nb_rows)
    page = request.GET.get('p_findings', 1)
    try:
        ag_findings = findings_paginator.page(page)
    except PageNotAnInteger:
        ag_findings = findings_paginator.page(1)
    except EmptyPage:
        ag_findings = findings_paginator.page(findings_paginator.num_pages)

    return render(request, 'details-dyn-asset-group.html', {
        'asset_group': asset_group,
        'asset_group_risk_grade': asset_group_risk_grade,
        'assets': assets,
        'findings': ag_findings,
        'findings_stats': findings_stats,
        'scans_stats': scans_stats,
        'scans': scans,
        'scan_defs': scan_defs,
        'engines_stats': engines_stats,
        'asset_scopes': list(asset_scopes.items())
    })


# Asset Owners
@pro_group_required('AssetsManager', 'AssetsViewer')
def list_asset_owners_view(request):
    """List asset owners."""
    owners = []
    for owner in AssetOwner.objects.all():
        tmp_owner = model_to_dict(owner)
        tmp_owner["nb_assets"] = owner.assets.all().count()
        tmp_owner["nb_contacts"] = owner.contacts.all().count()
        tmp_owner["nb_documents"] = owner.documents.all().count()
        owners.append(tmp_owner)

    return render(request, 'list-asset-owners.html', {'owners': owners})


@pro_group_required('AssetsManager')
def add_asset_owner_view(request):
    """Add new asset owner."""
    form = None
    if request.method == 'GET':
        form = AssetOwnerForm(user=request.user)
    elif request.method == 'POST':
        form = AssetOwnerForm(request.POST, user=request.user)

        if form.is_valid():
            owner_args = {
                'name': form.cleaned_data['name'],
                'url': form.cleaned_data['url'],
                'comments': form.cleaned_data['comments'],
                'owner': request.user,
            }
            owner = AssetOwner(**owner_args)
            owner.save()
            for asset_id in form.data.getlist('assets'):
                owner.assets.add(Asset.objects.for_user(request.user).get(id=asset_id))
            owner.save()
            messages.success(request, 'Creation submission successful')

            return redirect('list_asset_owners_view')
    return render(request, 'add-asset-owner.html', {'form': form})


@pro_group_required('AssetsManager')
def delete_asset_owner_view(request, asset_owner_id):
    """Delete asset owner."""
    owner = {}
    if request.method == 'POST':
        owner = get_object_or_404(AssetOwner, id=asset_owner_id)
        owner.delete()
        messages.success(request, 'Asset owner successfully deleted!')
        return redirect('list_asset_owners_view')
    return render(request, 'delete-asset-owner.html', {'owner': owner})


@pro_group_required('AssetsManager', 'AssetsViewer')
def details_asset_owner_view(request, asset_owner_id):
    """Return asset owner details."""
    owner = model_to_dict(get_object_or_404(AssetOwner, id=asset_owner_id))
    return render(request, 'details-asset-owner.html', {'owner': owner})
