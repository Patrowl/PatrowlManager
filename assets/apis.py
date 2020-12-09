# -*- coding: utf-8 -*-

from django.http import JsonResponse, HttpResponse, QueryDict
from django.forms.models import model_to_dict
from django.utils.encoding import smart_str
from django.db.models import Value, CharField, Q, F
from django.shortcuts import render, redirect, get_object_or_404
from django.core.files.storage import FileSystemStorage

from wsgiref.util import FileWrapper
from rest_framework.decorators import api_view
from common.utils import pro_group_required

from .models import Asset, AssetGroup, AssetCategory
from .models import AssetOwner, AssetOwnerContact, AssetOwnerDocument
from .models import ASSET_CRITICITIES
from .forms import AssetOwnerContactForm, AssetOwnerDocumentForm, AssetGroupForm
from app.settings import MEDIA_ROOT
from findings.models import Finding
from events.models import Event, AuditLog

import csv
import os
import mimetypes
import datetime
import urllib


# Assets
@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_api(request, asset_id):
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
    return JsonResponse(asset.to_dict(), safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager')
def ack_asset_api(request, asset_id):
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
    asset.set_status('ack')
    return JsonResponse({'status': 'success'})


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_group_api(request, assetgroup_id):
    assetgroup = get_object_or_404(AssetGroup.objects.for_user(request.user), id=assetgroup_id)
    return JsonResponse(assetgroup.to_dict(), safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_findings_api(request, asset_id):
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
    findings = [f.to_dict() for f in asset.finding_set.all()]
    return JsonResponse(findings, safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_assets_stats_api(request):
    assets = Asset.objects.for_user(request.user).all()
    data = {
        "nb_assets": assets.count(),
        "nb_assets_high": assets.filter(criticity="high").count(),
        "nb_assets_medium": assets.filter(criticity="medium").count(),
        "nb_assets_low": assets.filter(criticity="low").count()
    }
    return JsonResponse(data)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_details_api(request, asset_name):
    asset = get_object_or_404(Asset.objects.for_user(request.user), value=asset_name)

    # Asset details
    response = model_to_dict(asset, fields=[field.name for field in asset._meta.fields])

    # Related asset groups
    asset_groups = []
    for asset_group in asset.assetgroup_set.all():
        asset_group_dict = model_to_dict(asset_group, fields=[field.name for field in asset_group._meta.fields])
        asset_groups.append(asset_group_dict)
    response.update({
        "asset_groups": asset_groups
    })

    # Related findings
    findings = []
    for finding in asset.finding_set.all():
        finding_dict = model_to_dict(finding, fields=[field.name for field in finding._meta.fields])
        findings.append(finding_dict)
    response.update({
        "findings": findings
    })

    # Last 10 scans
    scans = []
    for scan in asset.scan_set.all()[:10]:
        scan_dict = model_to_dict(scan, fields=[field.name for field in scan._meta.fields])
        scans.append(scan_dict)

    response.update({
        "last10scans": scans
    })

    return JsonResponse(response, json_dumps_params={'indent': 2}, safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_trends_api(request, asset_id):
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
    data = []
    ticks_by_period = {'week': 7, 'month': 30, 'trimester': 120, 'year': 365}
    grade_levels = {'A': 6, 'B': 5, 'C': 4, 'D': 3, 'E': 2, 'F': 1, 'n/a': 0}

    # period = x-axis
    period = request.GET.get('period_by', None)
    if period not in ticks_by_period.keys():
        period = 7
    else:
        period = ticks_by_period[period]

    nb_ticks = int(request.GET.get('max_ticks', 15))
    if nb_ticks < period:
        delta = period // nb_ticks
    else:
        delta = 1

    startdate = datetime.datetime.today()
    for i in range(0, nb_ticks):
        enddate = startdate - datetime.timedelta(days=i*delta)
        findings_stats = {
            'total': 0,
            'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
            'new': 0,
            'risk_grade': 'n/a',
            'date': str(enddate.date())}

        for f in asset.finding_set.filter(created_at__lte=enddate).exclude(Q(status='false-positive') | Q(status='duplicate')).values("severity", "status"):
            findings_stats['total'] = findings_stats.get('total') + 1
            findings_stats[f["severity"]] = findings_stats.get(f["severity"]) + 1
            if f["status"] == 'new':
                findings_stats['new'] = findings_stats.get('new') + 1

        if findings_stats['total'] != 0:
            findings_stats['risk_grade'] = grade_levels[asset.get_risk_grade(history=i)]
        else:
            findings_stats['risk_grade'] = 0
        data.append(findings_stats)

    return JsonResponse(data[::-1], json_dumps_params={'indent': 2}, safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def list_assets_api(request):
    q = request.GET.get("q", None)
    team = request.GET.get("team", None)

    if q:
        assets = Asset.objects.for_user(request.user).filter(
                Q(value__icontains=q) | Q(name__icontains=q)
            ).annotate(
                format=Value("asset", output_field=CharField())
            ).values('id', 'value', 'format', 'name','type','exposure','categories__value','assetowner__name')
        assetgroups = AssetGroup.objects.for_user(request.user).filter(
                name__icontains=q
            ).annotate(
                value=F("name")
            ).annotate(
                format=Value("assetgroup", output_field=CharField())
            ).values('id', 'value', 'format', 'name')
        # vtasio added tags
        taggroups = AssetCategory.objects.filter(value__icontains = q ).annotate(name = F("value") ).annotate(format = Value("taggroup",
                                                                                                       output_field=CharField())).values(
            'id', 'value', 'format', 'name')
    else:
        assets = Asset.objects.for_user(request.user).annotate(
                format=Value("asset", output_field=CharField())
            ).values('id', 'value', 'format', 'name','type','exposure','categories__value','assetowner__name')
        assetgroups = AssetGroup.objects.for_user(request.user).annotate(
                value=F("name")
            ).annotate(
                format=Value("assetgroup", output_field=CharField())
            ).values('id', 'value', 'format', 'name')
        #vtasio added tags
        taggroups = AssetCategory.objects.annotate(             name = F("value")          ).annotate(
                     format = Value("taggroup", output_field=CharField())          ).values('id', 'value', 'format',
                                                                                            'name')

    # Filter by team
    if team is not None and len(team) > 0:
        assets = assets.filter(teams__in=team)
        assetgroups = assetgroups.filter(teams__in=team)
        taggroups = taggroups.filter(teams__in=team)

    assets_list = list(assets)
    assetgroups_list = list(assetgroups)
    taggroups_list = list(taggroups)
    return JsonResponse(assets_list + assetgroups_list + taggroups_list, safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def list_asset_groups_api(request):
    q = request.GET.get("q", None)
    if q:
        assetgroups = list(AssetGroup.objects
            .for_user(request.user)
            .filter(name__icontains=q)
            .extra(select={'value': 'name'})
            # .annotate(value=Value("name", output_field=CharField()))
            .annotate(format=Value("assetgroup", output_field=CharField()))
            .values('id', 'value', 'format', 'name'))
    else:
        assetgroups = list(AssetGroup.objects
            .for_user(request.user)
            .extra(select={'value': 'name'})
            .annotate(format=Value("assetgroup", output_field=CharField()))
            .values('id', 'value', 'format', 'name'))
    return JsonResponse(assetgroups, safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager')
def refresh_all_asset_grade_api(request):
    for asset in Asset.objects.for_user(request.user).all():
        asset.calc_risk_grade()
    for assetgroup in AssetGroup.objects.for_user(request.user).all():
        assetgroup.calc_risk_grade()
    return redirect('list_assets_view')


@api_view(['GET'])
@pro_group_required('AssetsManager')
def refresh_asset_grade_api(request, asset_id=None):
    if asset_id:
        asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
        asset.calc_risk_grade()
    else:
        # update all
        for asset in Asset.objects.for_user(request.user).all():
            asset.calc_risk_grade()
    return redirect('list_assets_view')


@api_view(['GET'])
@pro_group_required('AssetsManager')
def refresh_assetgroup_grade_api(request, assetgroup_id=None):
    if assetgroup_id:
        assetgroup = get_object_or_404(AssetGroup.objects.for_user(request.user), id=assetgroup_id)
        assetgroup_id.calc_risk_grade()
    else:
        # update all
        for assetgroup in AssetGroup.objects.for_user(request.user).all():
            assetgroup.calc_risk_grade()
    return JsonResponse({"status": "success"}, safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def export_assets_api(request, assetgroup_id=None):
    AuditLog.objects.create(
        message="Export assets as CSV file".format(request.user),
        scope='asset', type='assets_export_csv', owner=request.user, context=request)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="patrowl_assets.csv"'
    writer = csv.writer(response, delimiter=';')

    assets = []
    if assetgroup_id:
        asset_group = AssetGroup.objects.for_user(request.user).get(id=assetgroup_id)
        for asset in asset_group.assets.all():
            assets.append(asset)
    else:
        assets = Asset.objects.for_user(request.user).all()

    writer.writerow([
        'asset_value', 'asset_name', 'asset_type', 'asset_description',
        'asset_criticity', 'asset_tags', 'owner', 'team', 'asset_exposure', 'created_at'])
    for asset in assets:
        try:
            asset_owner = asset.owner.username
        except Exception:
            asset_owner = ""
        writer.writerow([
            smart_str(asset.value),
            asset.name,
            asset.type,
            smart_str(asset.description),
            asset.criticity,
            ",".join([a.value for a in asset.categories.all()]),
            asset_owner,
            ",".join([t.name for t in asset.teams.all()]),
            asset.exposure,
            asset.created_at
        ])
    return response


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def export_assetgroups_api(request):
    AuditLog.objects.create(
        message="Export asset groups as CSV file".format(request.user),
        scope='asset', type='assetgroups_export_csv', owner=request.user, context=request)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="patrowl_assets.csv"'
    writer = csv.writer(response, delimiter=';')

    writer.writerow([
        'assetgroup_name',
        'asset_value', 'asset_name', 'asset_type', 'asset_description',
        'asset_criticity', 'asset_tags', 'owner', 'team', 'asset_exposure',
        'created_at'])

    for assetgroup in AssetGroup.objects.for_user(request.user).all().order_by('name'):
        for asset in assetgroup.assets.all():
            try:
                asset_owner = asset.owner.username
            except Exception:
                asset_owner = ""

            writer.writerow([
                smart_str(assetgroup.name),
                smart_str(asset.value),
                asset.name,
                asset.type,
                smart_str(asset.description),
                asset.criticity,
                ",".join([a.value for a in asset.categories.all()]),
                asset_owner,
                ",".join([t.name for t in asset.teams.all()]),
                asset.exposure,
                asset.created_at
            ])
    return response


@api_view(['PUT', 'POST'])
@pro_group_required('AssetsManager')
def add_asset_api(request):
    new_asset_args = QueryDict(request.body)
    tags = new_asset_args.getlist('tags')
    new_asset_args_dict = QueryDict(request.body).dict()
    new_asset_args_dict.update({"owner": request.user})
    new_asset_args_dict.pop("tags", None)
    try:
        asset = Asset(**new_asset_args_dict)
        asset.save()

        # Add categories
        for cat in tags:
            c = AssetCategory.objects.filter(value=cat).first()
            if c:
                asset.categories.add(c)
        asset.save()

        return JsonResponse(asset.to_dict())
    except Exception:
        return JsonResponse({
            'status': 'error',
            'reason': 'Unable to create asset with provided args.'
        })


@api_view(['PUT', 'POST'])
@pro_group_required('AssetsManager')
def add_asset_group_api(request):
    new_assetgroup_args = QueryDict(request.body)
    tags = new_assetgroup_args.getlist('tags')
    assets = new_assetgroup_args.getlist('assets')
    new_assetgroup_args_dict = QueryDict(request.body).dict()
    new_assetgroup_args_dict.update({"owner": request.user})
    new_assetgroup_args_dict.pop("tags", None)
    new_assetgroup_args_dict.pop("assets", None)

    assetgroup = AssetGroup(**new_assetgroup_args_dict)
    assetgroup.save()

    # Add assets
    for asset in assets:
        a = Asset.objects.for_user(request.user).filter(id=asset).first()
        if a:
            assetgroup.assets.add(a)
    assetgroup.save()

    # Add categories
    for cat in tags:
        c = AssetCategory.objects.filter(value=cat).first()
        if c:
            assetgroup.categories.add(c)
    assetgroup.save()

    return JsonResponse(assetgroup.to_dict())


@api_view(['POST'])
@pro_group_required('AssetsManager')
def update_criticity_assets_api(request):
    data = request.data
    assets = data['assets']
    criticity = data['criticity']

    for asset_id in assets:
        a = Asset.objects.for_user(request.user).get(id=asset_id)
        if any(criticity in d for d in ASSET_CRITICITIES):
            a.set_criticity(criticity)

    return JsonResponse({'status': 'success'})


@api_view(['POST', 'DELETE'])
@pro_group_required('AssetsManager')
def delete_assets_api(request):
    assets = request.data
    for asset_id in assets:
        a = Asset.objects.for_user(request.user).get(id=asset_id)
        a.delete()

    return JsonResponse({'status': 'success'})


@api_view(['POST', 'DELETE'])
@pro_group_required('AssetsManager')
def delete_asset_api(request, asset_id):
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
    asset.delete()

    return JsonResponse({'status': 'success'})


@api_view(['POST', 'DELETE'])
@pro_group_required('AssetsManager')
def delete_assetgroup_api(request, assetgroup_id):
    assetgroup = get_object_or_404(AssetGroup.objects.for_user(request.user), id=assetgroup_id)
    assetgroup.delete()

    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


@api_view(['POST'])
@pro_group_required('AssetsManager')
def edit_assetgroup_api(request, assetgroup_id):
    asset_group = get_object_or_404(AssetGroup.objects.for_user(request.user), id=assetgroup_id)
    form = AssetGroupForm(request.POST, instance=asset_group)
    if asset_group.name != form.data['name']:
        asset_group.name = form.data['name']
    asset_group.description = form.data['description']
    asset_group.criticity = form.data['criticity']
    asset_group.assets.clear()
    for asset_id in form.data.getlist('assets'):
        asset_group.assets.add(Asset.objects.for_user(request.user).get(id=asset_id))
    asset_group.evaluate_risk()
    asset_group.save()

    asset_group.calc_risk_grade()
    asset_group.save()

    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_tags_api(request):
    tags = AssetCategory.objects.values_list('value', flat=True)
    return JsonResponse(list(tags), safe=False)


def _add_asset_tags(asset, new_value):
    new_tag = AssetCategory.objects.filter(value__iexact=new_value).first()
    if not new_tag:
        if not AssetCategory.objects.filter(value="Custom").first():
            AssetCategory.objects.create(value="Custom", comments="custom tags")
        custom_tags = AssetCategory.objects.get(value="Custom")
        new_tag = custom_tags.add_child(value=new_value)

        Event.objects.create(message="[AssetCategory/add_asset_tags()] New AssetCategory created: '{}' with id: {}.".format(new_value, new_tag.id),
                     type="INFO", severity="INFO")

    if new_tag not in asset.categories.all():  # Not already set
        # Check if futures parents has been already selected. If True: delete them
        cats = list(asset.categories.all().values_list('value', flat=True))
        if new_tag.get_all_parents():
            pars = [t.value for t in new_tag.get_all_parents()]
        else:
            pars = []
        intersec_par = set(pars).intersection(cats)
        if intersec_par:
            asset.categories.remove(AssetCategory.objects.get(value=list(intersec_par)[0]))

        # Check if current tags are not children of the new tag.
        # If True: delete them
        chis = [t.value for t in new_tag.get_children()]
        for c in set(chis).intersection(cats):
            asset.categories.remove(AssetCategory.objects.get(value=c))

    return new_tag


@api_view(['POST'])
@pro_group_required('AssetsManager')
def add_asset_tags_api(request, asset_id):
    if request.method == 'POST':
        asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
        new_tag = _add_asset_tags(asset, request.POST.getlist('input-search-tags')[0])
        asset.categories.add(new_tag)
        asset.save()

    return redirect('detail_asset_view', asset_id=asset_id)


@api_view(['POST'])
@pro_group_required('AssetsManager')
def add_asset_group_tags_api(request, assetgroup_id):
    if request.method == 'POST':
        asset_group = get_object_or_404(AssetGroup.objects.for_user(request.user), id=assetgroup_id)
        new_tag = _add_asset_tags(asset_group, request.POST.getlist('input-search-tags')[0])
        asset_group.categories.add(new_tag)

    return redirect('detail_asset_group_view', assetgroup_id=assetgroup_id)


@api_view(['POST'])
@pro_group_required('AssetsManager')
def delete_asset_tags_api(request, asset_id):
    tag_id = request.POST.get('tag_id', None)
    try:
        tag = AssetCategory.objects.get(id=tag_id)
    except AssetCategory.DoesNotExist:
        Event.objects.create(message="[AssetCategory/delete_asset_tags_api()] Asset with id '{}' was not found.".format(asset_id),
                     type="ERROR", severity="ERROR")
        return redirect('detail_asset_view', asset_id=asset_id)

    if request.method == 'POST':
        asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
        asset.categories.remove(tag)  # @todo: check error cases

    return redirect('detail_asset_view', asset_id=asset_id)


@api_view(['POST'])
@pro_group_required('AssetsManager')
def delete_asset_group_tags_api(request, assetgroup_id):
    tag_id = request.POST.get('tag_id', None)
    try:
        tag = AssetCategory.objects.get(id=tag_id)
    except AssetCategory.DoesNotExist:
        Event.objects.create(message="[AssetCategory/delete_asset_group_tags_api()] AssetGroup with id '{}' was not found.".format(assetgroup_id),
                     type="ERROR", severity="ERROR")
        return redirect('detail_asset_group_view', assetgroup_id=assetgroup_id)

    if request.method == 'POST':
        assetgroup = get_object_or_404(AssetGroup.objects.for_user(request.user), id=assetgroup_id)
        assetgroup.categories.remove(tag)  # @todo: check error cases

    return redirect('detail_asset_group_view', assetgroup_id=assetgroup_id)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_report_html_api(request, asset_id):
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)

    findings_tmp = list()
    findings_stats = {}

    # @todo: invert loops
    for sev in ["critical", "high", "medium", "low", "info"]:
        tmp = Finding.objects.filter(asset=asset.id, severity=sev).order_by('type')
        if tmp.count() > 0:
            findings_tmp += tmp
        findings_stats.update({sev: tmp.count()})
    findings_stats.update({"total": len(findings_tmp)})

    return render(request, 'report-asset-findings.html', {
        'asset': asset,
        'findings': findings_tmp,
        'findings_stats': findings_stats})


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_report_json_api(request, asset_id):
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)

    findings_tmp = list()
    findings_stats = {}

    # @todo: invert loops
    for sev in ["critical", "high", "medium", "low", "info"]:
        tmp = Finding.objects.filter(asset=asset.id, severity=sev).order_by('type')
        findings_stats.update({sev: tmp.count()})
        if tmp.count() > 0:
            for f in tmp:
                tmp_f = model_to_dict(f, exclude=["scopes"])
                tmp_f.update({"scopes": [ff.name for ff in f.scopes.all()]})
                findings_tmp.append(tmp_f)

    asset_dict = model_to_dict(asset, exclude=["categories", "teams"])
    asset_dict.update({"categories": [tag.value for tag in asset.categories.all()]})

    return JsonResponse({
        'asset': asset_dict,
        'findings': findings_tmp,
        'findings_stats': findings_stats
        }, safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_report_csv_api(request, asset_id):
    asset = get_object_or_404(Asset.objects.for_user(request.user), id=asset_id)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="patrowl_asset_{}.csv"'.format(asset_id)
    writer = csv.writer(response, delimiter=';')
    writer.writerow([
        'asset_value',
        'id', 'title', 'description', 'solution',
        'type', 'severity', 'score',
        'status', 'comments',
        'scopes',
        'tags',
        'links',
        'engine_type', 'engine_name',
        'scan_title', 'scan_policy',
        'owner', 'teams',
        'found_at', 'updated_at'
    ])

    for f in Finding.objects.filter(asset=asset.id).order_by('severity_num'):
        writer.writerow([
            smart_str(asset.value),
            f.id, smart_str(f.title), smart_str(f.description), smart_str(f.solution),
            f.type, f.severity, f.score,
            f.status, smart_str(f.comments),
            ", ".join([ff.name for ff in f.scopes.all()]),
            ", ".join(f.tags),
            ", ".join(f.links),
            f.engine_type, f.scan.engine.name,
            smart_str(f.scan.title), smart_str(f.scan.engine_policy.name),
            f.owner.username,
            ", ".join([t.name for t in asset.teams.all()]),
            f.found_at, f.updated_at
        ])

    return response


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_group_report_html_api(request, asset_group_id):
    asset_group = get_object_or_404(AssetGroup.objects.for_user(request.user).prefetch_related("assets"), id=asset_group_id)
    assets = asset_group.assets.all().only(
        "value", "name", "type", "criticity", "risk_level", "description",
        "created_at")

    # OPTIMIZE: findings

    return render(request, 'report-assetgroup-findings.html', {
        'asset_group': asset_group,
        'assets': assets})


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_group_report_json_api(request, asset_group_id):
    asset_group = get_object_or_404(AssetGroup.objects.for_user(request.user).prefetch_related("assets"), id=asset_group_id)

    assets = list()
    for asset in asset_group.assets.all():

        findings_tmp = list()
        findings_stats = {}

        # @todo: invert loops
        for sev in ["critical", "high", "medium", "low", "info"]:
            tmp = Finding.objects.filter(asset=asset.id, severity=sev).order_by('type')
            tmp_count = tmp.count()
            findings_stats.update({sev: tmp_count})
            if tmp_count > 0:
                for f in tmp:
                    tmp_f = model_to_dict(f, exclude=["scopes"])
                    tmp_f.update({"scopes": [ff.name for ff in f.scopes.all()]})
                    findings_tmp.append(tmp_f)

        asset_dict = model_to_dict(asset, exclude=["categories", "teams"])
        asset_tags = [tag.value for tag in asset.categories.all()]
        asset_dict.update({"categories": asset_tags})
        assets.append({
            'asset': asset_dict,
            'findings': findings_tmp,
            'findings_stats': findings_stats
            })

    return JsonResponse(assets, safe=False)


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_group_report_csv_api(request, asset_group_id):
    asset_group = get_object_or_404(AssetGroup.objects.for_user(request.user).prefetch_related("assets"), id=asset_group_id)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="patrowl_assetgroup_{}.csv"'.format(asset_group_id)
    writer = csv.writer(response, delimiter=';')
    writer.writerow([
        'asset_value',
        'id', 'title', 'description', 'solution',
        'type', 'severity', 'score',
        'status', 'comments',
        'scopes',
        'tags',
        'links',
        'engine_type', 'engine_name',
        'scan_title', 'scan_policy',
        'found_at', 'updated_at'
    ])

    for asset in asset_group.assets.all():
        for f in Finding.objects.filter(asset=asset.id).order_by('severity_num'):
            links = ""
            try:
                links = ", ".join(f.links)
            except Exception:
                pass
            writer.writerow([
                smart_str(asset.value),
                f.id, smart_str(f.title), smart_str(f.description), smart_str(f.solution),
                f.type, f.severity, f.score,
                f.status, smart_str(f.comments),
                ", ".join([ff.name for ff in f.scopes.all()]),
                ", ".join(f.tags),
                links,
                f.engine_type, f.scan.engine.name,
                smart_str(f.scan.title), smart_str(f.scan.engine_policy.name),
                f.found_at, f.updated_at
            ])

    return response


@api_view(['GET'])
@pro_group_required('AssetsManager', 'AssetsViewer')
def get_asset_owner_doc_api(request, asset_owner_doc_id):
    doc = get_object_or_404(AssetOwnerDocument, id=asset_owner_doc_id)
    fp = urllib.unquote(doc.filepath)
    fn = urllib.unquote(doc.filename)

    file_wrapper = FileWrapper(file(fp, 'rb'))
    file_mimetype = mimetypes.guess_type(fp)
    response = HttpResponse(file_wrapper, content_type=file_mimetype)
    response['X-Sendfile'] = fp
    response['Content-Length'] = os.stat(fp).st_size
    response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(fn)
    return response


@api_view(['POST'])
@pro_group_required('AssetsManager')
def edit_asset_owner_comments_api(request, asset_owner_id):
    if request.method != "POST" or not request.POST.get('new_comments', None):
        return HttpResponse(status=400)

    owner = get_object_or_404(AssetOwner, id=asset_owner_id)
    owner.comments = request.POST.get('new_comments')
    owner.save()
    return HttpResponse(status=200)


@api_view(['POST'])
@pro_group_required('AssetsManager')
def delete_asset_owner_contact_api(request, asset_owner_id):
    # if request.method != 'POST':
    #     return HttpResponse(status=400)

    contact = get_object_or_404(AssetOwnerContact, id=asset_owner_id)
    contact.delete()
    return redirect('details_asset_owner_view', asset_owner_id=asset_owner_id)


@api_view(['POST'])
@pro_group_required('AssetsManager')
def delete_asset_owner_document_api(request, asset_owner_id):
    if request.method != 'POST' or not request.POST.get('doc_id', None):
        return HttpResponse(status=400)

    doc_id = request.POST.get('doc_id')
    document = get_object_or_404(AssetOwnerDocument, id=doc_id)
    document.delete()
    return redirect('details_asset_owner_view', asset_owner_id=asset_owner_id)


@api_view(['POST'])
@pro_group_required('AssetsManager')
def add_asset_owner_document_api(request, asset_owner_id):
    owner = get_object_or_404(AssetOwner, id=asset_owner_id)
    form = AssetOwnerDocumentForm(request.POST, request.FILES)
    if form.is_valid():
        doc_args = {
            'doctitle': form.cleaned_data['doctitle'],
            'tlp_color': form.cleaned_data['tlp_color'],
            'comments': form.cleaned_data['comments'],
            'owner': request.user,
        }
        if request.FILES:
            # Create /media/ folders if not exists
            if not os.path.exists(MEDIA_ROOT+"/owners_docs"):
                os.makedirs(MEDIA_ROOT+"/owners_docs")
            if not os.path.exists(MEDIA_ROOT+"/owners_docs/"+str(request.user.id)):
                os.makedirs(MEDIA_ROOT+"/owners_docs/"+str(request.user.id))

            myfile = request.FILES['file']
            fs = FileSystemStorage(location=MEDIA_ROOT+"/owners_docs/"+str(request.user.id), base_url=MEDIA_ROOT+"/owners_docs/"+str(request.user.id))
            filename = fs.save(myfile.name, myfile)
            uploaded_file_url = fs.url(filename)
            doc_args.update({
                'filename': filename,
                'filepath': uploaded_file_url
            })

        doc = AssetOwnerDocument(**doc_args)
        doc.save()

        # Add this document to the asset owner
        owner.documents.add(doc)
        owner.save()

    return redirect('details_asset_owner_view', asset_owner_id=asset_owner_id)


@api_view(['POST'])
@pro_group_required('AssetsManager')
def add_asset_owner_contact_api(request, asset_owner_id):
    owner = get_object_or_404(AssetOwner, id=asset_owner_id)

    form = AssetOwnerContactForm(request.POST)
    if form.is_valid():
        contact_args = {
            'name': form.cleaned_data['name'],
            'title': form.cleaned_data['title'],
            'email': form.cleaned_data['email'],
            'phone': form.cleaned_data['phone'],
            'address': form.cleaned_data['address'],
            'url': form.cleaned_data['url'],
            'comments': form.cleaned_data['comments'],
            'owner': request.user,
        }

        contact = AssetOwnerContact(**contact_args)
        contact.save()

        # Add this contact to the asset owner
        owner.contacts.add(contact)
        owner.save()

    return redirect('details_asset_owner_view', asset_owner_id=asset_owner_id)
