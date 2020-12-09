# -*- coding: utf-8 -*-

from django.conf import settings
from .models import Finding
from .forms import FindingForm

import datetime


def _search_findings(request):
    # Check team
    teamid_selected = -1
    if settings.PRO_EDITION is True and request.GET.get('team', '').isnumeric() and int(request.GET.get('team', -1)) >= 0:
        teamid = int(request.GET.get('team'))
        # @Todo: ensure the team is allowed for this user
        teamid_selected = teamid

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
    filter_by_reference_id = request.GET.get('_reference_cond', None)
    # filter_by_reference_cond = request.GET.get('_reference_cond', None)

    filter_limit = request.GET.get('limit', None)

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
        elif filter_by_type_cond in ["not_exact", "not_icontains", "not_istartwith", "not_iendwith"]:
            excludes.update({"type__{}".format(filter_by_type_cond[4:]): filter_by_type})

    # Filter by finding title
    if filter_by_title:
        if filter_by_title_cond in ["exact", "icontains", "istartwith", "iendwith"]:
            filters.update({"title__{}".format(filter_by_title_cond): filter_by_title})
        elif filter_by_title_cond in ["not_exact", "not_icontains", "not_istartwith", "not_iendwith"]:
            excludes.update({"title__{}".format(filter_by_title_cond[4:]): filter_by_title})

    # Filter by finding severity
    if filter_by_severity and filter_by_severity in ["info", "low", "medium", "high", "critical"]:
        if filter_by_severity_cond == "exact":
            filters.update({"severity__{}".format(filter_by_severity_cond): filter_by_severity})
        elif filter_by_severity_cond == "not_exact":
            excludes.update({"severity__{}".format(filter_by_severity_cond[4:]): filter_by_severity})

    # Filter by finding status
    if filter_by_status and filter_by_status in ["ack", "new", "mitigated", "patched", "closed", "false-positive", "undone", "duplicate"]:
        if filter_by_status_cond == "exact" or filter_by_status_cond is None:
            filter_by_status_cond = "exact"
            filters.update({"status__{}".format(filter_by_status_cond): filter_by_status})
        elif filter_by_status_cond == "not_exact":
            excludes.update({"status__{}".format(filter_by_status_cond[4:]): filter_by_status})

    # Filter by references
    if filter_by_reference_id in ['CVE', 'CWE', 'CPE', 'MS', 'NESSUS', 'OSVDB', 'DIB']:
        if filter_by_reference:
            filters.update({"vuln_refs__{}__icontains".format(filter_by_reference_id): filter_by_reference})

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

    if teamid_selected >= 0:
        if str(filter_limit).isdigit():
            # findings = Finding.objects.severity_ordering().filter(**filters).exclude(**excludes)[:int(filter_limit)]
            findings = Finding.objects.severity_ordering().for_team(request.user, teamid_selected).filter(**filters).exclude(**excludes)[:int(filter_limit)]
        else:
            # findings = Finding.objects.severity_ordering().filter(**filters).exclude(**excludes).order_by(
            findings = Finding.objects.severity_ordering().for_team(request.user, teamid_selected).filter(**filters).exclude(**excludes).order_by(
                     '-severity_order', 'asset_name', 'status', 'type', 'engine_type')
    else:
        if str(filter_limit).isdigit():
            # findings = Finding.objects.severity_ordering().filter(**filters).exclude(**excludes)[:int(filter_limit)]
            findings = Finding.objects.severity_ordering().for_user(request.user).filter(**filters).exclude(**excludes)[:int(filter_limit)]
        else:
            # findings = Finding.objects.severity_ordering().filter(**filters).exclude(**excludes).order_by(
            findings = Finding.objects.severity_ordering().for_user(request.user).filter(**filters).exclude(**excludes).order_by(
                     '-severity_order', 'asset_name', 'status', 'type', 'engine_type')
    return findings.only("id", "asset_name", "title", "severity", "status", "engine_type", "updated_at")


def _add_finding(request):
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
        if finding_args['risk_info'] is None or not any(finding_args.risk_info):
            finding_args.update({
                'risk_info': {
                    "cvss_base_score": 0.0,
                    "vuln_publication_date": datetime.datetime.today().strftime('%Y/%m/%d')
                }
            })

        finding = Finding(**finding_args)
        finding.save()
        return finding
