# -*- coding: utf-8 -*-

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Count, F
from django_celery_beat.models import PeriodicTask, IntervalSchedule

from app.settings import TIME_ZONE
from .forms import ScanDefinitionForm
from .models import Scan, ScanDefinition
from .utils import _update_celerybeat, _run_scan
from engines.models import Engine, EnginePolicy, EngineInstance, EnginePolicyScope
from findings.models import RawFinding
from assets.models import Asset, AssetGroup

from datetime import timedelta, datetime
from pytz import timezone
import shlex
import json


def detail_scan_view(request, scan_id):
    # todo: optimize that shit
    scan = get_object_or_404(Scan, id=scan_id)
    scan.update_sumary()
    scan.save()
    scan_def = ScanDefinition.objects.get(id=scan.scan_definition.id)

    # Check search filters
    search_filters = request.GET.get("search", None)
    parsed_filters = ""
    assets_filters = {}
    findings_filters = {}

    if search_filters:
        parsed_filters = shlex.shlex(search_filters)
        parsed_filters.whitespace_split = True
        parsed_filters.quotes = '"'
        parsed_filters.wordchars += '\''

        for fil in parsed_filters:
            if fil.startswith("\""):
                fil = fil.lstrip('"')
                fil = fil.rstrip('"')
            if fil.startswith("assets:") or fil.startswith("a:") or fil.startswith("assets.value:") or fil.startswith("a.value:"):
                assets_filters.update({"value__icontains": fil.split(':')[1]})
            elif fil.startswith("asset.criticity:") or fil.startswith("a.criticity:"):
                assets_filters.update({"criticity__icontains": fil.split(':')[1]})
            elif fil.startswith("asset.type:") or fil.startswith("a.type:"):
                assets_filters.update({"type__icontains": fil.split(':')[1]})
            elif fil.startswith("finding:") or fil.startswith("f:") or fil.startswith("finding.title:") or fil.startswith("f.title:"):
                findings_filters.update({"title__icontains": fil.split(':')[1]})
            elif fil.startswith("finding.status:") or fil.startswith("f.status:"):
                findings_filters.update({"status__icontains": fil.split(':')[1]})
            elif fil.startswith("finding.severity:") or fil.startswith("f.severity:"):
                findings_filters.update({"severity__icontains": fil.split(':')[1]})
            else:
                assets_filters.update({"value__icontains": fil})
                findings_filters.update({"title__icontains": fil})

    # Search assets related to the scan
    if assets_filters == {}:
        assets = scan.assets.all()
    else:
        assets = scan.assets.filter(**assets_filters)
        findings_filters.update({"asset__in": assets})

    # Search asset groups related to the scan
    assetgroups = scan_def.assetgroups_list.all()

    # Add the assets from the asset group to the existing list of assets
    if len(assetgroups) == 0:
        other_assets = assets
    else:
        other_assets = []
        for asset in assets:
            for ag in assetgroups:
                if asset not in ag.assets.all():
                    other_assets.append(asset)

    # Search raw findings related to the asset
    if findings_filters == {}:
        raw_findings = RawFinding.objects.filter(scan=scan).order_by('asset', 'severity', 'type', 'title')
    else:
        findings_filters.update({"scan": scan})
        raw_findings = RawFinding.objects.filter(**findings_filters).order_by('asset', 'severity', 'type', 'title')

    # Generate summary info on assets (for progress bars)
    summary_assets = {}
    for a in assets:
        summary_assets.update({a.value: {"info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0, "total": 0}})
    for f in raw_findings.filter(asset__in=assets):
        summary_assets[f.asset_name].update({
            f.severity: summary_assets[f.asset_name][f.severity] + 1,
            "total": summary_assets[f.asset_name]["total"] + 1
           })

    # Generate summary info on asset groups (for progress bars)
    summary_assetgroups = {}
    for ag in assetgroups:
        summary_assetgroups.update({
            ag.id: {
                "info": 0, "low": 0, "medium": 0,
                "high": 0, "critical": 0, "total": 0
            }
        })
        for f in raw_findings:
            if f.asset.value in ag.assets.all().values_list('value', flat=True):
                summary_assetgroups[ag.id].update({
                    f.severity: summary_assetgroups[ag.id][f.severity] + 1,
                    "total": summary_assetgroups[ag.id]["total"] + 1
                })

    # Generate findings stats
    month_ago = datetime.today()-timedelta(days=30)
    findings_stats = {
        "count": raw_findings.count(),
        "cvss_gte_70": raw_findings.filter(risk_info__cvss_base_score__gte=7.0).count(),
        "pubdate_30d": raw_findings.filter(risk_info__vuln_publication_date__lte=month_ago.strftime('%Y/%m/%d')).count(),
        "cvss_gte_70_pubdate_30d": raw_findings.filter(risk_info__cvss_base_score__gte=7.0, risk_info__vuln_publication_date__lte=month_ago.strftime('%Y/%m/%d')).count()
    }

    # Pagination of findings
    scan_findings = raw_findings
    paginator_findings = Paginator(raw_findings, 50)
    page_finding = request.GET.get('p_findings')
    try:
        scan_findings = paginator_findings.page(page_finding)
    except PageNotAnInteger:
        scan_findings = paginator_findings.page(1)
    except EmptyPage:
        scan_findings = paginator_findings.page(paginator_findings.num_pages)

    # Pagination of events
    scan_events = scan.event_set.all().order_by('-id')
    paginator_events = Paginator(scan_events, 50)
    page_event = request.GET.get('p_events')
    try:
        scan_events = paginator_events.page(page_event)
    except PageNotAnInteger:
        scan_events = paginator_events.page(1)
    except EmptyPage:
        scan_events = paginator_events.page(paginator_events.num_pages)

    return render(request, 'details-scan.html', {
        'scan': scan,
        'summary_assets': summary_assets,
        'summary_assetgroups': summary_assetgroups,
        'assets': assets,
        'assetgroups': assetgroups,
        'other_assets': other_assets,
        'findings': scan_findings,
        'findings_stats': findings_stats,
        'scan_events': scan_events})


def list_scans_view(request):
    """List performed scans."""
    scan_list = Scan.objects.all().order_by('-finished_at')

    paginator = Paginator(scan_list, 10)
    page = request.GET.get('page')
    try:
        scans = paginator.page(page)
    except PageNotAnInteger:
        scans = paginator.page(1)
    except EmptyPage:
        scans = paginator.page(paginator.num_pages)
    return render(request, 'list-scans-performed.html', {'scans': scans})


def delete_scan_view(request, scan_id):
    """Delete scan."""
    scan = get_object_or_404(Scan, id=scan_id)
    if request.method == 'POST':
        scan.delete()
        messages.success(request, 'Scan successfully deleted!')
        return redirect('list_scan_def_view')
    return render(request, 'delete-scan.html', {'scan': scan})


# Scan Definitions
def list_scan_def_view(request):
    scans = Scan.objects.all()
    scan_defs = ScanDefinition.objects.all().order_by('-updated_at').annotate(scan_count=Count('scan')).annotate(engine_type_name=F('engine_type__name'))
    return render(request, 'list-scan-definitions.html', {
        'scan_defs': scan_defs, 'scans': scans})


def delete_scan_def_view(request, scan_def_id):
    scan_definition = get_object_or_404(ScanDefinition, id=scan_def_id)

    if request.method == 'POST':
        if scan_definition.scan_type == "periodic":
            try:
                periodic_task = scan_definition.periodic_task
                if periodic_task:
                    periodic_task.enabled = False   # maybe useless
                    periodic_task.save()            # maybe useless
                    periodic_task.delete()
                    _update_celerybeat()
            except PeriodicTask.DoesNotExist:
                pass
        if scan_definition.scheduled_at is not None:
            # todo: search the scheduled tasks and revoke them
            pass

        scan_definition.delete()

        messages.success(request, 'Scan definition successfully deleted!')
        return redirect('list_scan_def_view')
    return render(request, 'delete-scan-definition.html', {'scan_def': scan_definition})


def add_scan_def_view(request):
    form = None
    scan_cats = EnginePolicyScope.objects.all().values()
    scan_policies = list(EnginePolicy.objects.all())
    scan_engines = Engine.objects.all().values()
    scan_engines_json = json.dumps(list(EngineInstance.objects.all().values('id', 'name', 'engine__name', 'engine__id')))

    scan_policies_json = []
    for p in scan_policies:
        scan_policies_json.append(p.as_dict())

    if request.method == 'GET' or ScanDefinitionForm(request.POST).errors:
        if ScanDefinitionForm(request.POST).errors:
            print (ScanDefinitionForm(request.POST).errors)
        form = ScanDefinitionForm()

    elif request.method == 'POST':
        form = ScanDefinitionForm(request.POST)

        if form.is_valid():
            scan_definition = ScanDefinition()
            scan_definition.engine_policy = form.cleaned_data['engine_policy']
            scan_definition.engine_type = scan_definition.engine_policy.engine
            scan_definition.scan_type = form.cleaned_data['scan_type']
            scan_definition.title = form.cleaned_data['title']
            scan_definition.description = form.cleaned_data['description']
            scan_definition.owner = User.objects.get(id=request.user.id)
            scan_definition.status = "created"
            scan_definition.enabled = form.data['start_scan'] == "now"
            if form.cleaned_data['scan_type'] == 'periodic':
                scan_definition.every = int(form.cleaned_data['every'])
                scan_definition.period = form.cleaned_data['period']

            if form.data['start_scan'] == "scheduled":
                try:
                    # check if it's future or not
                    if form.cleaned_data['scheduled_at'] > datetime.now():
                        # @todo: validate datetime format
                        scan_definition.scheduled_at = timezone(TIME_ZONE).localize(form.cleaned_data['scheduled_at'])
                        scan_definition.enabled = True
                except Exception:
                    scan_definition.scheduled_at = None
                    scan_definition.enabled = False

            if int(form.data['engine_id']) > 0:
                # todo: check if the engine is compliant with the scan policy
                scan_definition.engine = EngineInstance.objects.get(id=form.data['engine_id'])

            scan_definition.save()

            assets_list = []
            for asset_id in form.data.getlist('assets_list'):
                asset = Asset.objects.get(id=asset_id)
                scan_definition.assets_list.add(asset)
                assets_list.append({
                    "id": asset.id,
                    "value": asset.value.strip(),
                    "criticity": asset.criticity,
                    "datatype": asset.type
                })

            # assetgroups_list = []
            for assetgroup_id in form.data.getlist('assetgroups_list'):
                assetgroup = AssetGroup.objects.get(id=assetgroup_id)
                scan_definition.assetgroups_list.add(assetgroup)
                # assetgroups_list.append(assetgroup.name)
                for a in assetgroup.assets.all():
                    scan_definition.assets_list.add(a)
                    assets_list.append({
                        "id": a.id,
                        "value": a.value.strip(),
                        "criticity": a.criticity,
                        "datatype": a.type
                    })

            scan_definition.save()

            # Todo: check if no asset or asset group is defined
            messages.success(request, 'Creation submission successful')

            # Todo: check if the engine instance id is set (dedicated scanner)
            parameters = {
                "scan_params": {
                    "assets": assets_list,
                    # "assetgroups": assetgroups_list,
                    "options": scan_definition.engine_policy.options,
                },
                "scan_definition_id": scan_definition.id,
                "engine_name": str(scan_definition.engine_type.name).lower(),
                "owner_id": request.user.id,
            }
            if form.data['engine_id'] != '' and int(form.data['engine_id']) > 0:
                # todo: check if the engine is compliant with the scan policy
                parameters.update({
                    "engine_id": EngineInstance.objects.get(id=form.data['engine_id']).id
                })
                parameters.update({
                    "scan_params": {
                        "engine_id": EngineInstance.objects.get(id=form.data['engine_id']).id
                    }
                })

            # todo: check if its a direct, a scheduled or a periodic task
            if form.cleaned_data['scan_type'] == 'periodic':
                schedule, created = IntervalSchedule.objects.get_or_create(
                    every=int(scan_definition.every),
                    period=scan_definition.period,
                )

                periodic_task = PeriodicTask.objects.create(
                    interval=schedule,
                    name='[PO] {}@{}'.format(scan_definition.title, scan_definition.id),
                    task='engines.tasks.start_periodic_scan_task',
                    args=json.dumps([parameters]),
                    queue='scan-'+scan_definition.engine_type.name.lower(),
                    routing_key='scan.'+scan_definition.engine_type.name.lower(),
                    last_run_at=None,
                )

                periodic_task.enabled = True
                periodic_task.save()

                scan_definition.periodic_task = periodic_task
                _update_celerybeat()
            else:  # Single later/now/scheduled
                if form.data['start_scan'] == "now":
                    # start the single scan now
                    _run_scan(scan_definition.id, request.user.id)
                elif form.data['start_scan'] == "scheduled" and scan_definition.scheduled_at is not None:
                    _run_scan(scan_definition.id, request.user.id, eta=scan_definition.scheduled_at)

            scan_definition.save()

            return redirect('list_scan_def_view')

    return render(request, 'add-scan-definition.html', {
        'form': form,
        'scan_engines': scan_engines,
        'scan_engines_json': scan_engines_json,
        'scan_cats': scan_cats,
        'scan_policies_json': json.dumps(scan_policies_json),
        'scan_policies': scan_policies})


def edit_scan_def_view(request, scan_def_id):
    scan_definition = get_object_or_404(ScanDefinition, id=scan_def_id)

    form = None
    if request.method == 'GET':
        form = ScanDefinitionForm(instance=scan_definition)
        scan_cats = EnginePolicyScope.objects.all().values()
        scan_policies = list(EnginePolicy.objects.all())
        scan_engines = Engine.objects.all().values()
        scan_engines_json = json.dumps(list(EngineInstance.objects.all().values('id', 'name', 'engine__name', 'engine__id')))

        scan_policies_json = []
        for p in scan_policies:
            scan_policies_json.append(p.as_dict())
    elif request.method == 'POST':
        form = ScanDefinitionForm(request.POST)

        if form.is_valid():
            scan_definition.title = form.cleaned_data['title']
            scan_definition.status = "edited"
            scan_definition.description = form.cleaned_data['description']
            scan_definition.enabled = form.cleaned_data['enabled'] is True
            scan_definition.engine_policy = form.cleaned_data['engine_policy']
            scan_definition.engine_type = scan_definition.engine_policy.engine
            if len(form.data['engine']) > 0:
                # todo: check if the engine is compliant with the scan policy
                scan_definition.engine = EngineInstance.objects.get(id=form.data['engine'])
            else:
                scan_definition.engine = None

            scan_definition.assets_list.clear()
            scan_definition.assetgroups_list.clear()
            assets_list = []
            for asset_id in form.data.getlist('assets_list'):
                asset = Asset.objects.get(id=asset_id)
                scan_definition.assets_list.add(asset)
                assets_list.append({
                    "id": asset.id,
                    "value": asset.value.strip(),
                    "criticity": asset.criticity,
                    "datatype": asset.type
                })
            for assetgroup_id in form.data.getlist('assetgroups_list'):
                assetgroup = AssetGroup.objects.get(id=assetgroup_id)
                scan_definition.assetgroups_list.add(assetgroup)
                for a in assetgroup.assets.all():
                    scan_definition.assets_list.add(a)
                    assets_list.append({
                        "id": a.id,
                        "value": a.value.strip(),
                        "criticity": a.criticity,
                        "datatype": a.type
                    })

            if form.cleaned_data['scan_type'] == 'single':
                scan_definition.every = None
                scan_definition.period = None

            if form.cleaned_data['scan_type'] == 'periodic':
                scan_definition.every = int(form.cleaned_data['every'])
                scan_definition.period = form.cleaned_data['period']

                schedule, created = IntervalSchedule.objects.get_or_create(
                    every=int(scan_definition.every),
                    period=scan_definition.period,
                )

                parameters = {
                    "scan_params": {
                        "assets": assets_list,
                        # "assetgroups": assetgroups_list,
                        "options": scan_definition.engine_policy.options,
                    },
                    # "scan_definition_id": str(scan_definition.id),
                    "scan_definition_id": scan_definition.id,
                    "engine_name": str(scan_definition.engine_type.name).lower(),
                    "owner_id": request.user.id,
                }
                if form.data['engine'] != '' and int(form.data['engine']) > 0:
                    parameters.update({
                        "engine_id": EngineInstance.objects.get(id=form.data['engine']).id,
                        "scan_params": {
                            "engine_id": EngineInstance.objects.get(id=form.data['engine']).id
                        }
                    })

                # Remove the old PeriodicTask if exists
                task_title = '[PO] {}@{}'.format(scan_definition.title, scan_definition.id)
                PeriodicTask.objects.filter(name=task_title).delete()

                # Create new one
                periodic_task = PeriodicTask.objects.create(
                    interval=schedule,
                    name=task_title,
                    task='engines.tasks.start_periodic_scan_task',
                    args=json.dumps([parameters]),
                    #expires=datetime.utcnow() + timedelta(seconds=30),
                    queue='scan-'+scan_definition.engine_type.name.lower(),
                    routing_key='scan.'+scan_definition.engine_type.name.lower(),
                    last_run_at=None,
                )

                periodic_task.enabled = True
                periodic_task.save()

                scan_definition.periodic_task = periodic_task
                _update_celerybeat()

            scan_definition.save()
            messages.success(request, 'Update submission successful')
            return redirect('list_scan_def_view')

    return render(request, 'edit-scan-definition.html', {
        'form': form,
        'scan_def': scan_definition,
        'scan_engines': scan_engines,
        'scan_engines_json': scan_engines_json,
        'scan_cats': scan_cats,
        'scan_policies_json': json.dumps(scan_policies_json),
        'scan_policies': scan_policies})


def detail_scan_def_view(request, scan_definition_id):
    """Details of a scan definition."""
    scan_def = get_object_or_404(ScanDefinition, id=scan_definition_id)
    scan_list = scan_def.scan_set.order_by('-finished_at')

    paginator = Paginator(scan_list, 20)
    page = request.GET.get('page')
    try:
        scans = paginator.page(page)
    except PageNotAnInteger:
        scans = paginator.page(1)
    except EmptyPage:
        scans = paginator.page(paginator.num_pages)
    return render(request, 'details-scan-def.html', {
        'scan_def': scan_def, 'scans': scans})


def compare_scans_view(request):
    scan_a_id = request.GET.get("scan_a_id", None)
    scan_b_id = request.GET.get("scan_b_id", None)
    scan_a = get_object_or_404(Scan, id=scan_a_id)
    scan_b = get_object_or_404(Scan, id=scan_b_id)

    scan_a_missing_findings = scan_b.rawfinding_set.all().exclude(
        hash__in=scan_a.rawfinding_set.values_list('hash'))
    scan_b_missing_findings = scan_a.rawfinding_set.all().exclude(
        hash__in=scan_b.rawfinding_set.values_list('hash'))

    return render(request, 'compare-scans.html', {
        'scan_a': scan_a,
        'scan_b': scan_b,
        'scan_a_missing_findings': scan_a_missing_findings,
        'scan_b_missing_findings': scan_b_missing_findings
    })
