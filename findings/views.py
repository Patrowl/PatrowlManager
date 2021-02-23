# -*- coding: utf-8 -*-

from django.conf import settings
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import F
from common.utils import pro_group_required
from .models import Finding, RawFinding
from .forms import ImportFindingsForm, FindingForm
from .utils import _search_findings
from assets.models import Asset
from users.models import Team, TeamUser
from engines.tasks import importfindings_task
from assets.models import AssetOwner
import os
import time
import collections
import datetime


@pro_group_required('FindingsManager', 'FindingsViewer')
def list_findings_view(request):

    teams = []
    if settings.PRO_EDITION and request.user.is_superuser:
        teams = Team.objects.all().order_by('name')
    elif settings.PRO_EDITION and not request.user.is_superuser:
        for tu in TeamUser.objects.filter(user=request.user):
            teams.append({
                'id': tu.organization.id,
                'name': tu.organization.name
            })

    findings = _search_findings(request)
    nb_findings = findings.count()

    # Pagination findings
    nb_rows = request.GET.get('n', 50)
    findings_paginator = Paginator(findings, nb_rows)
    page = request.GET.get('page')
    owners = AssetOwner.objects.all()
    try:
        findings_p = findings_paginator.page(page)
    except PageNotAnInteger:
        findings_p = findings_paginator.page(1)
    except EmptyPage:
        findings_p = findings_paginator.page(findings_paginator.num_pages)

    return render(request, 'list-findings.html', {
        'findings': findings_p,
        'nb_findings': nb_findings,
        'teams': teams,
        'owners': owners
    })


@pro_group_required('FindingsManager', 'FindingsViewer')
def list_asset_findings_view(request, asset_name):
    findings = None
    filter_by_status = request.GET.get('_status', None)

    filters = {
        "asset_name": asset_name
    }
    if filter_by_status and filter_by_status in ["new", "ack"]:
        filters.update({"status": filter_by_status})

    findings = Finding.objects.for_user(request.user).filter(**filters).order_by(
             'asset_name', 'severity', 'status', 'type')

    return render(request, 'list-findings.html', {'findings': findings})


@pro_group_required('FindingsManager')
def delete_finding_view(request, finding_id):
    finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)
    asset_id = finding.asset.id
    finding.delete()

    # Reevaluate related asset critity
    Asset.objects.for_user(request.user).get(id=asset_id).evaluate_risk()
    messages.success(request, 'Finding successfully deleted!')
    return redirect('list_findings_view')


@pro_group_required('FindingsManager')
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


@pro_group_required('FindingsManager', 'FindingsViewer')
def details_finding_view(request, finding_id):
    from events.models import Event
    finding = None

    if request.GET.get("raw", None) and request.GET.get("raw") == "true":
        finding = get_object_or_404(RawFinding, id=finding_id)
        return render(request, 'details-finding.html', {'finding': finding, 'raw': True})

    finding = get_object_or_404(Finding, id=finding_id)

    # Inject tracking data
    tracking_timeline = {}
    if finding.engine_type not in ["", "MANUAL"]:
        tracking_timeline.update({
            finding.created_at: {
                "level": "info",
                "message": "First identification in scan \
                <a href='/scans/details/{}'>'{}'</a> ({}). \
                Definition <a href='/scans/defs/details/{}'>here</a>"
                .format(
                    finding.scan.id, finding.scan, finding.scan.engine_type,
                    finding.scan.scan_definition.id
                )
            }
        })

    # Identify finding occurrences in related scan results (excluding the 1st)
    for f in RawFinding.objects.for_user(request.user).filter(hash=finding.hash).annotate(scan_title=F('scan__title')):
        tracking_timeline.update({f.created_at: {
            "level": "info",
            "message": "Identified in scan <a href='/scans/details/{}'>{}</a>".format(f.scan_id, f.scan_title)}})

    # Identify changes
    for event in Event.objects.filter(finding=finding):
        tracking_timeline.update({
            event.created_at: {"level": "info", "message": event.message}
        })

    return render(request, 'details-finding.html', {
        'finding': finding,
        'raw': False,
        'tracking_timeline': collections.OrderedDict(sorted(tracking_timeline.items(), key=lambda t: t[0]))})


@pro_group_required('FindingsManager')
def edit_finding_view(request, finding_id):
    form = None
    is_raw_finding = request.GET.get("raw", None) and request.GET.get("raw") == "true"
    if is_raw_finding:
        finding = get_object_or_404(RawFinding.objects.for_user(request.user), id=finding_id)
    else:
        finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)

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

            # Update Finding status if
            if type(finding) == RawFinding:
                for f in Finding.objects.for_user(request.user).filter(title=finding.title, asset_name=finding.asset_name, hash=finding.hash).only('id', 'status'):
                    f.status = form.cleaned_data['status']
                    f.save()
            return redirect('list_findings_view')

    return render(request, 'edit-finding.html',
        {'form': form, 'finding': finding, 'raw': is_raw_finding})


@pro_group_required('FindingsManager')
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
                'confidence': 'certain',
                'type': form.cleaned_data['type'],
                'severity': form.cleaned_data['severity'],
                'solution': form.cleaned_data['solution'],
                'risk_info': form.cleaned_data['risk_info'],
                'vuln_refs': form.cleaned_data['vuln_refs'],
                'links': form.cleaned_data['links'],
                'tags': form.cleaned_data['tags'],
                # 'tags': [].append(form.cleaned_data['tags'].split(',')),
                'status': form.cleaned_data['status'],
                'owner': request.user,
                'asset': form.cleaned_data['asset'],
                'asset_name': form.cleaned_data['asset'].value,
                'raw_data': {},
                'engine_type': 'MANUAL'
                # 'scan': form.cleaned_data['scan']
            }

            if not finding_args["risk_info"]:
                finding_args.update({
                    'risk_info': {
                        "cvss_base_score": 0.0,
                        "vuln_publication_date": datetime.datetime.today().strftime('%Y/%m/%d')
                    }
                })
            finding = Finding(**finding_args)
            finding.save()
            return redirect('list_findings_view')

    return render(request, 'add-finding.html', {'form': form})


@pro_group_required('FindingsManager', 'FindingsViewer')
def compare_findings_view(request):
    finding_a_id = request.GET.get("finding_a_id", None)
    finding_b_id = request.GET.get("finding_b_id", None)
    raw_finding = request.GET.get("raw", None)
    if raw_finding:
        finding_a = get_object_or_404(RawFinding.objects.for_user(request.user), id=finding_a_id)
        finding_b = get_object_or_404(RawFinding.objects.for_user(request.user), id=finding_b_id)
    else:
        finding_a = get_object_or_404(Finding.objects.for_user(request.user), id=finding_a_id)
        finding_b = get_object_or_404(Finding.objects.for_user(request.user), id=finding_b_id)

    return render(request, 'compare-findings.html', {
        'finding_a': finding_a,
        'finding_b': finding_b})
