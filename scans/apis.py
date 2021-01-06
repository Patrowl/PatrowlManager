# -*- coding: utf-8 -*-

from django.http import JsonResponse, HttpResponse
from wsgiref.util import FileWrapper
# from django.utils import timezone as tz

from django.shortcuts import render, get_object_or_404
from django.forms.models import model_to_dict
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives
from django_celery_beat.models import PeriodicTask
from rest_framework.decorators import api_view
from common.utils import pro_group_required

from .models import Scan, ScanDefinition
from .utils import _update_celerybeat, _run_scan, _search_scans, _add_scan_def
from engines.tasks import stopscan_task
from findings.models import RawFinding
from settings.models import Setting
from events.models import AuditLog
from django.db.models import Q

from datetime import timedelta
from pytz import timezone
import datetime
import json
import os
import csv
import tzlocal

import logging
logger = logging.getLogger(__name__)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scan_definitions_api(request):
    """Get scan definitions."""
    scans_list = []
    for scan in ScanDefinition.objects.for_user(request.user).all():
        scans_list.append(scan.to_dict())
    return JsonResponse(scans_list, safe=False)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scan_definition_api(request, scan_id):
    """Get selected scan."""
    scan = get_object_or_404(ScanDefinition.objects.for_user(request.user), id=scan_id)
    return JsonResponse(scan.to_dict(), safe=False)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def export_scan_definition_api(request, scan_id):
    """Get selected scan."""
    scan = get_object_or_404(ScanDefinition.objects.for_user(request.user), id=scan_id)
    response = JsonResponse(scan.to_dict())
    response['Content-Disposition'] = 'attachment; filename=scandef_'+str(scan.id)+'.json'
    return response


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def export_scan_definitions_api(request):
    """Get selected scan."""
    scans_list = []
    for scan in ScanDefinition.objects.for_user(request.user).all():
        scans_list.append(scan.to_dict())
    response = JsonResponse(scans_list, safe=False)
    response['Content-Disposition'] = 'attachment; filename=scandefs'
    return response


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scan_api(request, scan_id):
    """Get selected scan."""
    scan = get_object_or_404(Scan.objects.for_user(request.user), id=scan_id)
    return JsonResponse(scan.to_dict(), safe=False)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scans_api(request):
    """Get scans."""
    scans_list = []
    for scan in _search_scans(request):
        scans_list.append(scan.to_dict())
    return JsonResponse(scans_list, safe=False)


@api_view(['GET', 'DELETE'])
@pro_group_required('ScansManager')
def delete_scan_api(request, scan_id):
    """Delete selected scan."""
    scan = get_object_or_404(Scan.objects.for_user(request.user), id=scan_id)

    if scan.status not in ['finished', 'error']:
        res = stopscan_task.apply_async(args=[scan.id], queue='scanmgt', retry=True, ignore_result=False)
        res.get()
    scan.delete()
    return JsonResponse({'status': 'success'})


@api_view(['POST', 'DELETE'])
@pro_group_required('ScansManager')
def delete_scans_api(request):
    """Delete selected scans."""
    scans = request.data
    for scan_id in scans:
        try:
            scan = Scan.objects.for_user(request.user).get(id=scan_id)
        except Scan.DoesNotExist:
            continue

        # Stop scans if possible
        if scan.status not in ['finished', 'error']:
            res = stopscan_task.apply_async(args=[scan.id], queue='scanmgt', retry=True, ignore_result=False)
            res.get()
        Scan.objects.for_user(request.user).get(id=scan_id).delete()
    return JsonResponse({'status': 'success'})


@api_view(['GET', 'DELETE'])
@pro_group_required('ScansManager')
def delete_scan_def_api(request, scan_id):
    """Delete selected scan defs."""
    scan_def = get_object_or_404(ScanDefinition.objects.for_user(request.user), id=scan_id)

    # Delete periodic_task if any
    try:
        periodic_task = scan_def.periodic_task
        if periodic_task:
            periodic_task.enabled = False   # maybe useless
            periodic_task.save()            # maybe useless
            periodic_task.delete()
            _update_celerybeat()
    except PeriodicTask.DoesNotExist:
        pass

    # Delete scan definition
    scan_def.delete()
    return JsonResponse({'status': 'success'})


@api_view(['POST', 'DELETE'])
@pro_group_required('ScansManager')
def delete_scan_defs_api(request):
    """Delete selected scan defs."""
    scans = request.data
    for scan_id in scans:
        scan_def = ScanDefinition.objects.for_user(request.user).get(id=scan_id)
        # Delete periodic_task if any
        try:
            periodic_task = scan_def.periodic_task
            if periodic_task:
                periodic_task.enabled = False   # maybe useless
                periodic_task.save()            # maybe useless
                periodic_task.delete()
                _update_celerybeat()
        except PeriodicTask.DoesNotExist:
            pass

        # Delete scan definition
        scan_def.delete()
    return JsonResponse({'status': 'success'})


@api_view(['GET'])
@pro_group_required('ScansManager')
def stop_scan_api(request, scan_id):
    """Stop a scan."""
    scan = get_object_or_404(Scan.objects.for_user(request.user), id=scan_id)
    scan.status = "stopping"
    scan.save()
    stopscan_task.apply_async(
        args=[scan.id], queue='scanmgt', retry=True, ignore_result=False)
    # args=[scan.id], queue='scan', retry=False, ignore_result=True)
    AuditLog.objects.create(
        message="Scan '{}' stopped".format(scan),
        scope='engine', type='scan_stop', owner=request.user, context=request)
    return JsonResponse({'status': 'success'})


@api_view(['POST'])
@pro_group_required('ScansManager')
def stop_scans_api(request):
    """Stop selected scans."""
    scans = request.data
    for scan_id in scans:
        try:
            scan = Scan.objects.for_user(request.user).get(id=scan_id)
        except Scan.DoesNotExist:
            continue

        scan.status = "stopping"
        scan.save()
        stopscan_task.apply_async(
            args=[scan.id],
            queue='scanmgt',
            retry=True,
            ignore_result=True
        )
        AuditLog.objects.create(
            message="Scan '{}' stopped".format(scan),
            scope='engine', type='scan_stop', owner=request.user, context=request)

    return JsonResponse({'status': 'success'})


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scans_stats_api(request):
    scope = request.GET.get('scope', None)
    data = {}
    if not scope:
        scan_defs = ScanDefinition.objects.for_user(request.user).all()
        data = {
            "nb_scans_defined": scan_defs.count(),
            "nb_scans_performed": Scan.objects.all().count(),
            "nb_periodic_scans": scan_defs.filter(scan_type="periodic").count(),
            "nb_active_periodic_scans": scan_defs.filter(scan_type="periodic", enabled=True).count()
        }
    elif scope == "scan_def":
        scan_id = request.GET.get('scan_id', None)
        num_records = int(request.GET.get('num_records', 10))
        if not scan_id:
            return JsonResponse({})
        # scan_def = get_object_or_404(ScanDefinition, id=scan_id)
        scans = reversed(Scan.objects.filter(scan_definition=scan_id).values('id', 'created_at', 'summary').order_by('-created_at')[:num_records])
        data = list(scans)
    elif scope == "scans":
        num_records = int(request.GET.get('num_records', 10))
        scans = reversed(Scan.objects.all().values('id', 'created_at', 'summary').order_by('-created_at')[:num_records])
        data = list(scans)

    return JsonResponse(data, json_dumps_params={'indent': 2}, safe=False)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scans_heatmap_api(request):
    data = {}

    # Check team
    teamid = -1
    if settings.PRO_EDITION is True and request.GET.get('team', '').isnumeric() and int(request.GET.get('team', -1)) >= 0:
        teamid = int(request.GET.get('team'))

    if teamid >= 0:
        for scan in Scan.objects.for_team(request.user, teamid).all():
            data.update({scan.updated_at.astimezone(tzlocal.get_localzone()).strftime("%s"): 1})
    else:
        for scan in Scan.objects.for_user(request.user).all():
            data.update({scan.updated_at.astimezone(tzlocal.get_localzone()).strftime("%s"): 1})
    return JsonResponse(data)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scans_by_period_api(request):
    # remove to optimize

    data = {}
    start_date = request.GET.get('start', None)
    stop_date = request.GET.get('stop', None)
    if start_date and datetime.strptime(start_date, '%Y-%m-%dT%H:%M:%fZ'):
        start_date = datetime.strptime(start_date, '%Y-%m-%dT%H:%M:%fZ')
    if stop_date:
        stop_date = datetime.strptime(stop_date, '%Y-%m-%dT%H:%M:%fZ')

    for scan in Scan.objects.filter(updated_at__gte=start_date):
        # expected format: {timestamp: value, timestamp2: value2 ...}
        data.update({scan.updated_at.strftime("%s"): 1})
    return JsonResponse(data)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scans_by_date_api(request):
    scopes = ["year", "month", "week", "day", "hour", "minute"]

    data = []
    date = request.GET.get('date', None)
    stop_date = None
    scope = request.GET.get('scope', None)
    status = request.GET.get('status', None)

    if date and datetime.datetime.strptime(date, '%Y-%m-%dT%H:%M:%fZ'):
        date_wot = datetime.datetime.strptime(date, '%Y-%m-%dT%H:%M:%fZ')
        date = timezone(tzlocal.get_localzone().zone).localize(date_wot)
    else:
        return HttpResponse(status=400)

    if scope not in scopes:
        return HttpResponse(status=400)

    if scope == "hour":
        stop_date = date + timedelta(hours=1)
    elif scope == "day":
        stop_date = date + timedelta(days=1)
    elif scope == "week":
        stop_date = date + timedelta(days=7)
    elif scope == "month":
        stop_date = date + timedelta(days=30)

    scans_filters = {
        'updated_at__gte': date,
        'updated_at__lte': stop_date,
    }

    if status is not None:
        if status in ["running", "enqueued"]:
            scans_filters.update({
                'status': status
            })
        elif status == "finished":
            scans_filters.update({
                'status__in': ["finished", "error", "stopped"]
            })

    scans = Scan.objects.for_user(request.user).filter(**scans_filters)

    for scan in scans:
        updated_at = scan.updated_at.astimezone(tzlocal.get_localzone()).strftime("%Y-%m-%d %H:%M:%S")
        # if scan.updated_at.date() == timezone.now().date():
        #     updated_at = timezone.localtime(scan.updated_at).strftime("%H:%M:%S")
        # else:
        #     updated_at = scan.updated_at.date().isoformat()
        data.append({
            "scan_id": scan.id,
            "status": scan.status,
            "engine_type": scan.engine_type.name,
            "title": scan.title,
            "summary": json.dumps(scan.summary),
            "updated_at": updated_at,
            "scan_definition_id": scan.scan_definition.id
        })
    return JsonResponse(data, safe=False)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scan_report_html_api(request, scan_id):
    scan = get_object_or_404(Scan.objects.for_user(request.user), id=scan_id)
    send_email = request.GET.get('email', None)
    tmp_scan = model_to_dict(scan)
    tmp_scan['assets'] = []
    for asset in scan.assets.all():
        tmp_scan['assets'].append(asset.value)

    tmp_scan['engine_type_name'] = scan.engine_type.name
    tmp_scan['engine_name'] = scan.engine.name
    tmp_scan['engine_policy_name'] = scan.engine_policy.name

    findings = RawFinding.objects.filter(scan=scan.id)

    findings_tmp = list()
    for sev in ["high", "medium", "low", "info", "critical"]:
        tmp = RawFinding.objects.filter(scan=scan, severity=sev).order_by('title', 'type')
        if tmp.count() > 0:
            findings_tmp += tmp

    findings_by_asset = dict()
    for asset in scan.assets.all():
        findings_by_asset_tmp = list()
        for sev in ["critical", "high", "medium", "low", "info"]:
            tmp = RawFinding.objects.filter(scan=scan, asset=asset, severity=sev).order_by('title', 'type')
            if tmp.count() > 0:
                findings_by_asset_tmp += tmp
        findings_by_asset.update({asset.value: findings_by_asset_tmp})

    findings_stats = {
        "total": findings.count(),
        "high": findings.filter(severity='high').exclude(Q(status='false-positive') | Q(status='duplicate')).count(),
        "medium": findings.filter(severity='medium').exclude(Q(status='false-positive') | Q(status='duplicate')).count(),
        "low": findings.filter(severity='low').exclude(Q(status='false-positive') | Q(status='duplicate')).count(),
        "info": findings.filter(severity='info').count(),
        "critical": findings.filter(severity='critical').exclude(Q(status='false-positive') | Q(status='duplicate')).count()
    }

    for asset in scan.assets.all():
        findings_stats.update({
            asset.value: {
                "total": findings.filter(asset=asset).count(),
                "critical": findings.filter(asset=asset, severity='critical').exclude(Q(status='false-positive') | Q(status='duplicate')).count(),
                "high": findings.filter(asset=asset, severity='high').exclude(Q(status='false-positive') | Q(status='duplicate')).count(),
                "medium": findings.filter(asset=asset, severity='medium').exclude(Q(status='false-positive') | Q(status='duplicate')).count(),
                "low": findings.filter(asset=asset, severity='low').exclude(Q(status='false-positive') | Q(status='duplicate')).count(),
                "info": findings.filter(asset=asset, severity='info').count(),
            }
        })

    report_params = {
        'scan': tmp_scan,
        'findings': findings_by_asset,
        'findings_stats': findings_stats
    }

    if send_email is None:
        # Return HTML report as response
        return render(request, 'report-scan.html', report_params)

    else:
        # Send Email and return status as JSON response
        msg_text = render_to_string("email_send_report.txt")
        msg_html = render_to_string("email_send_report.html", report_params)
        html_report = render_to_string('report-scan.html', report_params)

        subject = '[PatrowlManager] Scan Report available - {}'.format(scan)

        try:
            recipients = Setting.objects.get(key="alerts.endpoint.email").value
        except Exception as e:
            logger.error('Unable to send report as email message. "alerts.endpoint.email" setting not configured:')
            return JsonResponse({'status': 'error', 'reason': '"alerts.endpoint.email" setting not configured'}, 400)

        try:
            msg = EmailMultiAlternatives(
                subject=subject,
                body=msg_text,
                from_email=settings.EMAIL_HOST_USER,
                to=[recipients])
            msg.attach_alternative(msg_html, "text/html")
            msg.attach('scan_report.html', html_report, "text/html")
            msg.send()
        except Exception as e:
            logger.error('Unable to send report as email message:', e)
            return JsonResponse({'status': 'error', 'reason': '{}'.format(e)}, 400)

        return JsonResponse({"status": "success"}, safe=False)


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scan_report_json_api(request, scan_id):
    scan = get_object_or_404(Scan.objects.for_user(request.user), id=scan_id)

    filename = str(scan.report_filepath)
    if not os.path.isfile(filename):
        return HttpResponse(status=404)

    wrapper = FileWrapper(open(filename))
    response = HttpResponse(wrapper, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename=report_'+os.path.basename(filename)
    response['Content-Length'] = os.path.getsize(filename)

    return response


@api_view(['GET'])
@pro_group_required('ScansManager', 'ScansViewer')
def get_scan_report_csv_api(request, scan_id):
    scan = get_object_or_404(Scan.objects.for_user(request.user), id=scan_id)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=report_{}.csv'.format(scan_id)

    writer = csv.writer(response, delimiter=';')
    writer.writerow([
        'asset_value', 'asset_type',
        'engine_type', 'engine_name',
        'scan_title', 'scan_policy',
        'finding_id', 'finding_title', 'finding_type', 'finding_status',
        'finding_tags', 'finding_severity', 'finding_description',
        'finding_solution', 'finding_hash', 'finding_creation_date',
        'finding_risk_info', 'finding_cvss', 'finding_links'
        ])

    for finding in RawFinding.objects.filter(scan=scan).order_by('asset__name', 'severity', 'title'):
        engine_policy_name = ""
        if scan.engine_policy is not None:
            engine_policy_name = scan.engine_policy.name
        writer.writerow([
            finding.asset_name, finding.asset.type,
            scan.engine_type.name, scan.engine.name,
            scan.title, engine_policy_name,
            finding.id, finding.title, finding.type, finding.status,
            ', '.join(finding.tags), finding.severity, finding.description,
            finding.solution, finding.hash, finding.created_at,
            finding.risk_info, finding.risk_info['cvss_base_score'],
            ', '.join(finding.links)
        ])

    return response


@csrf_exempt
@api_view(['GET'])
@pro_group_required('ScansManager')
def toggle_scan_def_status_api(request, scan_def_id):
    scan_def = get_object_or_404(ScanDefinition.objects.for_user(request.user), id=scan_def_id)
    scan_def.enabled = not scan_def.enabled
    scan_def.save()

    AuditLog.objects.create(
        message="Scan definition '{}' status toggled to '{}'".format(scan_def, scan_def.enabled),
        scope='engine', type='scan_stop', owner=request.user, context=request)

    if scan_def.scan_type == 'periodic':
        try:
            periodic_task = scan_def.periodic_task
            periodic_task.enabled = scan_def.enabled
            periodic_task.last_run_at = None
            periodic_task.save()
            # Todo: wait celery beat fix
            _update_celerybeat()
        except PeriodicTask.DoesNotExist:
            logger.error("Fuck, PeriodicTask '{}' does not exists".format(periodic_task.id))
            return JsonResponse({'status': 'error'}, 403)

    return JsonResponse({'status': 'success'})


@api_view(['GET'])
@pro_group_required('ScansManager')
def run_scan_def_api(request, scan_def_id):
    scan_def = get_object_or_404(ScanDefinition.objects.for_user(request.user), id=scan_def_id)

    if scan_def.scan_type in ["single", "scheduled", "periodic"]:
        _run_scan(scan_def_id, request.user.id)
        return JsonResponse({'status': 'success'})
    else:
        return JsonResponse({'status': 'failed'}, status=403)


@api_view(['POST', 'PUT'])
@pro_group_required('ScansManager')
def add_scan_def_api(request):
    scan_def = _add_scan_def(request.data, owner=request.user)
    if scan_def:
        return JsonResponse({'status': 'success', 'scan_def_id': scan_def.id})
    else:
        return JsonResponse({'status': 'failed'}, status=403)
