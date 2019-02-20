# -*- coding: utf-8 -*-

from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from .models import Finding, RawFinding
from .forms import ImportFindingsForm, FindingForm
from assets.models import Asset
from events.models import Event
from engines.tasks import importfindings_task
import json
import os
import time
import collections


def list_findings_view(request):
    filter_by_asset = request.GET.get('_asset_value', None)
    filter_by_asset_cond = request.GET.get('_asset_value_cond', None)
    filter_by_title = request.GET.get('_title', None)
    filter_by_title_cond = request.GET.get('_title_cond', None)
    filter_by_type = request.GET.get('_type', None)
    filter_by_type_cond = request.GET.get('_type_cond', None)
    filter_by_severity = request.GET.get('_severity', None)
    filter_by_severity_cond = request.GET.get('_severity_cond', None)
    # filter_by_startdate = request.GET.get('_startdate', None)
    # filter_by_enddate = request.GET.get('_enddate', None)
    filter_by_status = request.GET.get('_status', None)
    filter_by_status_cond = request.GET.get('_status_cond', None)
    filter_by_asset_id = request.GET.get('_asset_id', None)
    filter_by_asset_group_id = request.GET.get('_asset_group_id', None)
    filter_by_asset_group_name = request.GET.get('_asset_group_name', None)
    filter_by_engine = request.GET.get('_engine', None)
    filter_by_type = request.GET.get('_type', None)
    # filter_by_asset_tags = request.GET.get('_tags', None)
    filter_by_scope = request.GET.get('_scope', None)
    filter_by_reference = request.GET.get('_reference', None)
    # filter_by_reference_cond = request.GET.get('_reference_cond', None)

    filters = {}
    excludes = {}
    # Filter by asset value
    if filter_by_asset and filter_by_asset_cond:
        if filter_by_asset_cond in ["exact", "icontains", "istartwith", "iendwith"]:
            filters.update({"asset_name__{}".format(filter_by_asset_cond): filter_by_asset})
        elif filter_by_asset_cond in ["not_exact", "not_icontains", "not_istartwith", "not_iendwith"]:
            excludes.update({"asset_name__{}".format(filter_by_asset_cond[4:]): filter_by_asset})

    # Filter by finding type
    if filter_by_type:
        if filter_by_type_cond in ["exact", "icontains", "istartwith", "iendwith"]:
            filters.update({"type__{}".format(filter_by_type_cond): filter_by_type})
        elif filter_by_asset_cond in ["not_exact", "not_icontains", "not_istartwith", "not_iendwith"]:
            excludes.update({"type__{}".format(filter_by_type_cond[4:]): filter_by_type})

    # Filter by finding title
    if filter_by_title:
        if filter_by_title_cond in ["exact", "icontains", "istartwith", "iendwith"]:
            filters.update({"title__{}".format(filter_by_title_cond): filter_by_title})
        elif filter_by_asset_cond in ["not_exact", "not_icontains", "not_istartwith", "not_iendwith"]:
            excludes.update({"title__{}".format(filter_by_title_cond[4:]): filter_by_title})

    # Filter by finding severity
    if filter_by_severity and filter_by_severity in ["info", "low", "medium", "high", "critical"]:
        if filter_by_severity_cond == "exact":
            filters.update({"severity__{}".format(filter_by_severity_cond): filter_by_severity})
        elif filter_by_asset_cond == "not_exact":
            excludes.update({"severity__{}".format(filter_by_severity_cond[4:]): filter_by_severity})

    # Filter by finding status
    if filter_by_status and filter_by_status in ["ack", "new", "mitigated", "patched", "closed", "false-positive"]:
        if filter_by_status_cond == "exact":
            filters.update({"status__{}".format(filter_by_status_cond): filter_by_status})
        elif filter_by_asset_cond == "not_exact":
            excludes.update({"status__{}".format(filter_by_status_cond[4:]): filter_by_status})

    if filter_by_status and filter_by_status in ["new", "ack"]:
        filters.update({"status": filter_by_status})
    if filter_by_asset_id:
        filters.update({"asset_id": filter_by_asset_id})
    if filter_by_asset_group_id:
        filters.update({"asset__assetgroup": filter_by_asset_group_id})
    if filter_by_asset_group_name:
        filters.update({"asset__assetgroup__name__icontains": filter_by_asset_group_name})

    if filter_by_engine:
        filters.update({"engine_type": filter_by_engine})
    if filter_by_scope:
        filters.update({"scan__engine_policy__scopes__in": filter_by_scope})
    if filter_by_reference:
        filters.update({"vuln_refs__icontains": filter_by_reference})

    findings = Finding.objects.filter(**filters).exclude(**excludes).order_by(
             'asset_name', 'severity', 'status', 'type')

    nb_findings = findings.count()

    # Pagination findings
    nb_rows = request.GET.get('n', 50)
    findings_paginator = Paginator(findings, nb_rows)
    page = request.GET.get('page')
    try:
        findings_p = findings_paginator.page(page)
    except PageNotAnInteger:
        findings_p = findings_paginator.page(1)
    except EmptyPage:
        findings_p = findings_paginator.page(findings_paginator.num_pages)

    return render(request, 'list-findings.html', {
        'findings': findings_p, 'nb_findings': nb_findings})


def list_asset_findings_view(request, asset_name):
    findings = None
    filter_by_status = request.GET.get('_status', None)

    filters = {
        "asset_name": asset_name
    }
    if filter_by_status and filter_by_status in ["new", "ack"]:
        filters.update({"status": filter_by_status})

    findings = Finding.objects.filter(**filters).order_by(
             'asset_name', 'severity', 'status', 'type')

    return render(request, 'list-findings.html', {'findings': findings})


def delete_finding_view(request, finding_id):
    finding = get_object_or_404(Finding, id=finding_id)
    asset_id = finding.asset.id
    finding.delete()

    # reevaluate related asset critity
    # Asset.objects.get(owner_id=request.user.id, asset_id=finding.asset_id).evaluate_risk()
    Asset.objects.get(id=asset_id).evaluate_risk()
    messages.success(request, 'Finding successfully deleted!')
    return redirect('list_findings_view')


def import_findings_view(request):
    if request.method == 'POST':
        form = ImportFindingsForm(request.POST, request.FILES)

        if form.is_valid():
            # store the file in /media/imports/<owner_id>/<tmp_file>
            user_report_dir = settings.MEDIA_ROOT + "/imports/"+str(request.user.id)+"/"
            if not os.path.exists(user_report_dir):
                os.makedirs(user_report_dir)
            filename = user_report_dir+"import_" + str(request.user.id) + "_" + str(int(time.time() * 1000)) + "." + form.cleaned_data['engine']
            with open(filename, 'wb+') as destination:
                for chunk in request.FILES['file'].chunks():
                    destination.write(chunk)
            # enqueue the import processing
            importfindings_task.apply_async(
                args=[filename, request.user.id, form.cleaned_data['engine'], form.cleaned_data['min_level']],
                queue='default',
                routing_key='default',
                retry=False
            )

            messages.success(request, 'Findings successfully imported!')
        return redirect('list_findings_view')
    else:
        form = ImportFindingsForm()
    return render(request, 'import-findings.html', {'form': form})


def details_finding_view(request, finding_id):
    finding = None

    if request.GET.get("raw", None) and request.GET.get("raw") == "true":
        finding = get_object_or_404(RawFinding, id=finding_id)
        return render(request, 'details-finding.html', {'finding': finding, 'raw': True})

    finding = get_object_or_404(Finding, id=finding_id)

    # Inject tracking data
    tracking_timeline = {}
    tracking_timeline.update({finding.created_at: {"level": "info", "message": "First identification in scan <a href='/scans/details/{}'>'{}'</a> ({}). Definition <a href='/scans/defs/details/{}'>here</a>".format(finding.scan.id, finding.scan, finding.scan.engine_type, finding.scan.scan_definition.id)}})

    # Identify changes
    for event in Event.objects.filter(finding=finding):
        tracking_timeline.update({event.created_at: {"level": "info", "message": event.message}})

    # Identify finding occurrences in related scan results (excluding the 1st)
    for scan in finding.scan.scan_definition.scan_set.filter(status="finished").exclude(id=finding.scan.id):
        finding_notfound = True
        for f in scan.rawfinding_set.all():
            if f.hash == finding.hash:
                finding_notfound = False
                tracking_timeline.update({f.created_at: {
                    "level": "info",
                    "message": "Identified in scan <a href='/scans/details/{}'>{}</a>".format(scan.id, scan)}})
            break
        if finding_notfound:
            tracking_timeline.update({scan.created_at: {
                "level": "warning",
                "message": "Not in scan <a href='/scans/details/{}'>{}</a>".format(scan.id, scan)}})

    return render(request, 'details-finding.html', {
        'finding': finding,
        'raw': False,
        'tracking_timeline': collections.OrderedDict(sorted(tracking_timeline.items(), key=lambda t: t[0]))})


def edit_finding_view(request, finding_id):
    form = None
    is_raw_finding = request.GET.get("raw", None) and request.GET.get("raw") == "true"
    if is_raw_finding:
        finding = get_object_or_404(RawFinding, id=finding_id)
    else:
        finding = get_object_or_404(Finding, id=finding_id)

    form = FindingForm()
    if request.method == 'GET':
        form = FindingForm(instance=finding)
    elif request.method == 'POST':
        form = FindingForm(request.POST, instance=finding)

        if form.is_valid():
            finding.title = form.cleaned_data['title']
            finding.description = form.cleaned_data['description']
            finding.type = form.cleaned_data['type']
            finding.severity = form.cleaned_data['severity']
            finding.solution = form.cleaned_data['solution']
            finding.risk_info = form.cleaned_data['risk_info']
            finding.vuln_refs = form.cleaned_data['vuln_refs']
            finding.links = form.cleaned_data['links']
            finding.tags = form.cleaned_data['tags']
            finding.status = form.cleaned_data['status']
            finding.comments = form.cleaned_data['comments']

            finding.save()
            messages.success(request, 'Update submission successful')
            return redirect('list_findings_view')

    return render(request, 'edit-finding.html',
        {'form': form, 'finding': finding, 'raw': is_raw_finding})


def add_finding_view(request):
    form = None

    form = FindingForm()
    if request.method == 'GET':
        form = FindingForm()
    elif request.method == 'POST':
        form = FindingForm(request.POST)

        if form.is_valid():
            finding_args = {
                'title': form.cleaned_data['title'],
                'description': form.cleaned_data['description'],
                'confidence': form.cleaned_data['confidence'],
                'type': form.cleaned_data['type'],
                'severity': form.cleaned_data['severity'],
                'solution': form.cleaned_data['solution'],
                'risk_info': form.cleaned_data['risk_info'],
                'vuln_refs': form.cleaned_data['vuln_refs'],
                'links': form.cleaned_data['links'],
                'tags': str(json.dumps(form.cleaned_data['tags'].split(','))),
                'status': form.cleaned_data['status'],
                # 'owner': form.cleaned_data['owner'],
                'asset': form.cleaned_data['asset'],
                'asset_name': form.cleaned_data['asset'].value,
                'scan': form.cleaned_data['scan']
            }

            finding = Finding(**finding_args)
            finding.save()
            messages.success(request, 'Creation submission successful')
            return redirect('list_findings_view')

    return render(request, 'add-finding.html', {'form': form})


def compare_findings_view(request):
    finding_a_id = request.GET.get("finding_a_id", None)
    finding_b_id = request.GET.get("finding_b_id", None)
    raw_finding = request.GET.get("raw", None)
    if raw_finding:
        finding_a = get_object_or_404(RawFinding, id=finding_a_id)
        finding_b = get_object_or_404(RawFinding, id=finding_b_id)
    else:
        finding_a = get_object_or_404(Finding, id=finding_a_id)
        finding_b = get_object_or_404(Finding, id=finding_b_id)

    return render(request, 'compare-findings.html', {
        'finding_a': finding_a,
        'finding_b': finding_b})
