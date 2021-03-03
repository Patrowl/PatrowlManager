# -*- coding: utf-8 -*-

from django.http import JsonResponse, HttpResponse
from django.forms.models import model_to_dict
from django.shortcuts import render, get_object_or_404
from .models import Finding, RawFinding
from .utils import _search_findings, _add_finding
from assets.models import Asset
from scans.models import Scan, ScanDefinition
from rules.models import Rule
from rest_framework.decorators import api_view
from common.utils.encoding import json_serial
from common.utils import pro_group_required
from django.db.models import Q
import json
import csv


@api_view(['GET'])
@pro_group_required('FindingsManager', 'FindingsViewer')
def get_raw_finding_api(request, finding_id):
    finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)
    return JsonResponse(finding.raw_data, safe=False)


@api_view(['GET'])
@pro_group_required('FindingsManager', 'FindingsViewer')
def list_findings_api(request):
    findings_list = []
    for f in _search_findings(request):
        findings_list.append(f.to_dict())
    return JsonResponse(findings_list, safe=False)


@api_view(['POST'])
@pro_group_required('FindingsManager')
def add_finding_api(request):
    finding = _add_finding(request)
    return JsonResponse(finding.to_dict())


@api_view(['GET'])
@pro_group_required('FindingsManager', 'FindingsViewer')
def get_finding_api(request, finding_id):
    finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)
    return JsonResponse(finding.to_dict())


@api_view(['POST'])
@pro_group_required('FindingsManager')
def delete_findings_api(request):
    findings = request.data
    for finding_id in findings:
        f = Finding.objects.for_user(request.user).get(id=finding_id)

        # reevaluate related asset critity
        Asset.objects.for_user(request.user).get(id=f.asset.id).evaluate_risk()
        f.delete()

    return JsonResponse({'status': 'success'})


@api_view(['POST'])
@pro_group_required('FindingsManager', 'FindingsViewer')
def export_findings_csv_api(request):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=export_findings.csv'
    writer = csv.writer(response, delimiter=';')
    writer.writerow([
        'asset_value', 'asset_type',
        'engine_type',
        'scan_title', 'scan_policy',
        'finding_id', 'finding_type', 'finding_status', 'finding_tags',
        'finding_severity', 'finding_description', 'finding_solution',
        'finding_hash', 'finding_creation_date', 'finding_risk_info',
        'finding_cvss', 'finding_links'
        ])

    # findings = json.loads(request.body)
    findings = request.data
    for finding_id in findings:
        finding = Finding.objects.for_user(request.user).get(id=finding_id)
        if 'links' in finding.risk_info.keys():
            finding_links = ", ".join(finding.risk_info['links'])
        else:
            finding_links = None

        writer.writerow([
            finding.asset.value, finding.asset.type,
            finding.scan.engine_type.name,
            finding.scan.title, finding.scan.engine_policy.name,
            finding.id, finding.type, finding.status, ','.join(finding.tags),
            finding.severity, finding.description, finding.solution,
            finding.hash, finding.created_at, finding.risk_info,
            finding.risk_info['cvss_base_score'],
            finding_links
        ])

    return response


@api_view(['POST'])
@pro_group_required('FindingsManager')
def delete_rawfindings_api(request):
    findings = request.data
    for finding_id in findings:
        f = RawFinding.objects.for_user(request.user).get(id=finding_id)

        # reevaluate related asset critity
        Asset.objects.for_user(request.user).get(id=f.asset.id).evaluate_risk()
        f.delete()

    return JsonResponse({'status': 'success'})


@api_view(['POST'])
@pro_group_required('FindingsManager')
def change_findings_status_api(request):
    findings = request.data
    for finding in findings:
        f = Finding.objects.for_user(request.user).filter(id=finding['ack']).first()
        f.status = "ack"
        f.save()

    return JsonResponse({'status': 'success'})


@api_view(['GET'])
@pro_group_required('FindingsManager')
def ack_findings_status_api(request, finding_id):
    f = Finding.objects.for_user(request.user).filter(id=finding_id).first()
    f.status = "ack"
    f.save()
    return JsonResponse({'status': 'success'})


@api_view(['POST'])
@pro_group_required('FindingsManager')
def change_rawfindings_status_api(request):
    findings = request.data
    for finding in findings:
        rf = RawFinding.objects.for_user(request.user).filter(id=finding['ack']).first()
        rf.status = "ack"
        rf.save()
        # for f in rf.finding_set.all():
        #     f.status = "ack"
        #     f.save()
        for f in Finding.objects.for_user(request.user).filter(title=rf.title, asset_name=rf.asset_name, hash=rf.hash).only('id', 'status'):
            f.status = rf.status
            f.save()

    return JsonResponse({'status': 'success'})


@api_view(['GET'])
@pro_group_required('FindingsManager', 'FindingsViewer')
def get_findings_stats_api(request):
    scope = request.GET.get('scope', None)
    data = {}
    if not scope:
        findings = Finding.objects.for_user(request.user).all()
    else:
        scan_id = request.GET.get('scan_id', None)
        if not scan_id:
            return JsonResponse({})
        if scope == "scan_def":
            get_object_or_404(ScanDefinition, id=scan_id)
            findings = RawFinding.objects.for_user(request.user).filter(scan__scan_definition_id=scan_id)
        elif scope == "scan":
            scan = get_object_or_404(Scan, id=scan_id)
            findings = RawFinding.objects.for_user(request.user).filter(scan=scan)

    data = {
        "nb_findings": findings.count(),
        "nb_info": findings.filter(severity="info").count(),
        "nb_low": findings.filter(severity="low").exclude(Q(status='falsepositive') | Q(status='duplicate')).count(),
        "nb_medium": findings.filter(severity="medium").exclude(Q(status='falsepositive') | Q(status='duplicate')).count(),
        "nb_high": findings.filter(severity="high").exclude(Q(status='falsepositive') | Q(status='duplicate')).count(),
        "nb_critical": findings.filter(severity="critical").exclude(Q(status='falsepositive') | Q(status='duplicate')).count(),
        "nb_new_findings": findings.filter(status="new").count(),
        "nb_new_info": findings.filter(status="new", severity="info").count(),
        "nb_new_low": findings.filter(status="new", severity="low").count(),
        "nb_new_medium": findings.filter(status="new", severity="medium").count(),
        "nb_new_high": findings.filter(status="new", severity="high").count(),
        "nb_new_critical": findings.filter(status="new", severity="critical").count(),
        "nb_false_positive": findings.filter(status="falsepositive").count(),
        "nb_duplicate": findings.filter(status="duplicate").count(),
    }

    return JsonResponse(data)


@api_view(['GET'])
@pro_group_required('FindingsManager')
def send_finding_alerts_api(request, finding_id):
    if request.GET.get("raw", None) and request.GET.get("raw") == "true":
        finding = get_object_or_404(RawFinding.objects.for_user(request.user), id=finding_id)
    else:
        finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)

    # Create a new rule
    rule = Rule(title="manual", severity=finding.severity.capitalize(), owner_id=request.user.id)
    if request.GET.get("type", None) and request.GET.get("type") == "slack":
        rule.target = "slack"
        rule.notify(finding.title)
    elif request.GET.get("type", None) and request.GET.get("type") == "thehive":
        rule.target = "thehive"
        rule.notify(message=finding.title, asset=finding.asset, description=finding.description)
    elif request.GET.get("type", None) and request.GET.get("type") == "email":
        rule.target = "email"
        rule.notify(message=finding.title, asset=finding.asset, description=finding.description)

    rule.delete()

    return JsonResponse({"status": "success"})


@api_view(['GET'])
@pro_group_required('FindingsManager')
def generate_finding_alerts_api(request, finding_id):
    if request.GET.get("raw", None) and request.GET.get("raw") == "true":
        finding = get_object_or_404(RawFinding.objects.for_user(request.user), id=finding_id)
    else:
        finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)

    nb_matches = finding.evaluate_alert_rules()
    return JsonResponse({"status": "success", "nb_matches": nb_matches})


@api_view(['POST'])
@pro_group_required('FindingsManager')
def update_finding_comments_api(request, finding_id):
    new_comments = request.POST.get("comments", None)
    if new_comments is None:
        return JsonResponse({"status": "error", "reason": "invalid parameter"})

    if request.POST.get("raw", None) and request.POST.get("raw") == "true":
        finding = get_object_or_404(RawFinding.objects.for_user(request.user), id=finding_id)
    else:
        finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)

    finding.comments = new_comments
    finding.save()
    return JsonResponse({"status": "success"})


@api_view(['GET'])
@pro_group_required('FindingsManager')
def update_finding_api(request, finding_id):
    from events.models import Event
    is_raw = False
    if request.GET.get("raw", None) and request.GET.get("raw") == "true":
        finding = get_object_or_404(RawFinding.objects.for_user(request.user), id=finding_id)
        is_raw = True
    else:
        finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)

    allowed_fields = [f.name for f in Finding._meta.get_fields()]
    for field_key in iter(request.GET.keys()):
        if field_key in allowed_fields:
            if is_raw:
                Event.objects.create(message="Finding updated on field {}: from '{}' to '{}'".format(
                    field_key, getattr(finding, field_key), request.GET.get(field_key)
                ), type="UPDATE", severity="INFO", rawfinding=finding)
                setattr(finding, field_key, request.GET.get(field_key))

                # Update the related Finding too
                if field_key != "status":
                    _finding = Finding.objects.for_user(request.user).get(title=finding.title, asset=finding.asset)
                    Event.objects.create(message="Finding updated on field {}: from '{}' to '{}'".format(
                        field_key, getattr(finding, field_key), request.GET.get(field_key)
                    ), type="UPDATE", severity="INFO", finding=_finding)
                    setattr(_finding, field_key, request.GET.get(field_key))
                    _finding.save()

            else:
                field_value = request.GET.get(field_key)
                Event.objects.create(message="Finding updated on field {}: from '{}' to '{}'".format(
                    field_key, getattr(finding, field_key), field_value
                ), type="UPDATE", severity="INFO", finding=finding)
                # scan value need to be a Scan() object, empty value is None
                if not field_value and field_key == 'scan':
                    field_value = None
                    setattr(finding, 'engine_type', 'MANUAL')
                setattr(finding, field_key, field_value)

    finding.save()

    return JsonResponse({"status": "success"})


@api_view(['GET'])
@pro_group_required('FindingsManager', 'FindingsViewer')
def export_finding_api(request, finding_id):
    allowed_formats = ['json', 'html', 'stix', 'pdf', 'csv']
    if request.GET.get("raw", None) and request.GET.get("raw") == "true":
        finding = get_object_or_404(RawFinding.objects.for_user(request.user), id=finding_id)
        prefix = "raw-"
    else:
        finding = get_object_or_404(Finding.objects.for_user(request.user), id=finding_id)
        prefix = ""
    export_format = request.GET.get("output", "csv")

    if not export_format or export_format not in allowed_formats:
        return JsonResponse({"status": "error", "reason": "bad format"})

    res = {}
    if export_format == 'json':
        res = model_to_dict(finding, exclude="scopes")
        res.update({"scopes": list(finding.scopes.values())})
        response = HttpResponse(
            json.dumps(res, default=json_serial),
            content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename=export_finding_{}{}.json'.format(prefix, finding.id)
        return response

    elif export_format == 'stix':
        res = {
            "type": "vulnerability",
            "name": finding.title,
            "description": finding.description,
            "id": "patrowl-{}{}".format(prefix, finding.id)
        }
        response = HttpResponse(
            json.dumps(res, default=json_serial),
            content_type='application/json')
        response['Content-Disposition'] = 'attachment; filename=export_finding_{}{}.stix.json'.format(prefix, finding.id)
        return response

    elif export_format == 'html':
        return render(request, 'report-finding.html', {'finding': finding})

    elif export_format == 'csv':
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=export_finding_{}{}.csv'.format(prefix, finding.id)
        writer = csv.writer(response, delimiter=';')
        writer.writerow([
            'asset_value', 'asset_type',
            'engine_type',
            'scan_title', 'scan_policy',
            'finding_id', 'finding_type', 'finding_status', 'finding_tags',
            'finding_severity', 'finding_description', 'finding_solution',
            'finding_hash', 'finding_creation_date', 'finding_risk_info',
            'finding_cvss', 'finding_links'
            ])
        if 'links' in finding.risk_info.keys():
            finding_links = ", ".join(finding.risk_info['links'])
        else:
            finding_links = None
        writer.writerow([
            finding.asset.value, finding.asset.type,
            finding.scan.engine_type.name,
            finding.scan.title, finding.scan.engine_policy.name,
            finding.id, finding.type, finding.status, ','.join(finding.tags),
            finding.severity, finding.description, finding.solution,
            finding.hash, finding.created_at, finding.risk_info,
            finding.risk_info['cvss_base_score'], finding_links
        ])

        return response
