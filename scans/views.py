from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from wsgiref.util import FileWrapper
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.forms.models import model_to_dict
from django.db.models import Count, F, Q#, Min, Sum, Avg
from django.views.decorators.csrf import csrf_exempt
from django_celery_beat.models import PeriodicTask, IntervalSchedule, PeriodicTasks

from app.settings import TIME_ZONE
from .forms import ScanCampaignForm, ScanDefinitionForm
from .models import Scan, ScanCampaign, ScanDefinition
from engines.models import Engine, EnginePolicy, EngineInstance, EnginePolicyScope
from engines.tasks import startscan_task, start_periodic_scan_task, stopscan_task
from findings.models import RawFinding, Finding
from assets.models import Asset, AssetGroup

import uuid, random, datetime, json, copy, os, tempfile, zipfile, time, csv
from datetime import datetime, timedelta
from pytz import timezone
import xmlrpclib, shlex


@csrf_exempt
def delete_scans(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error'})

    scans = json.loads(request.body)
    for scan_id in scans:
        Scan.objects.get(id=scan_id).delete()

    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


@csrf_exempt
def stop_scan(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    scan.status = "stopping"
    scan.save()
    resp = stopscan_task.apply_async(
        args=[scan.id],
        queue='scan-'+str(scan.engine_type).lower(),
        routing_key='scan.'+str(scan.engine_type).lower(),
        retry=False
    )

    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


def _update_celerybeat():
    print("INFO: Updating Celery Beat Scheduler...")
    server = xmlrpclib.Server('http://localhost:9001/RPC2')

    try:
        if server.supervisor.getProcessInfo("celery-beat")['statename'] in ['RUNNING', 'RESTARTING']:
            server.supervisor.stopProcess("celery-beat")
    except:
        print "error ", server.supervisor.getProcessInfo("celery-beat")['statename']

    try:
        if server.supervisor.getProcessInfo("celery-beat")['statename'] in ['FATAL', 'SHUTDOWN', 'STOPPED'] :
            server.supervisor.startProcess("celery-beat", False)
    except:
        print "error:", server.supervisor.getProcessInfo("celery-beat")['statename']

    return server.supervisor.getProcessInfo("celery-beat")['statename']

def _remove_prefix(text, prefix):
    return text[text.startswith(prefix) and len(prefix):]

def detail_scan_view(request, scan_id):
    #todo: optimize that shit
    scan = get_object_or_404(Scan, id=scan_id)
    scan.update_sumary()
    scan.save()
    scan_def = ScanDefinition.objects.get(id=scan.scan_definition.id)

    ## Check search filters
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

    print "findings_filters:", findings_filters

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
        summary_assets.update({a.value: {"info": 0, "low": 0, "medium":0, "high": 0, "total": 0}})
    for f in raw_findings.filter(asset__in=assets):
        summary_assets[f.asset_name].update({
            f.severity: summary_assets[f.asset_name][f.severity] + 1,
            "total": summary_assets[f.asset_name]["total"] + 1
            })

    # Generate summary info on asset groups (for progress bars)
    summary_assetgroups = {}
    for ag in assetgroups:
        summary_assetgroups.update({ag.id: {"info": 0, "low": 0, "medium":0, "high": 0, "total": 0}})
        for f in raw_findings:
            if f.asset.value in ag.assets.all().values_list('value', flat=True):
                summary_assetgroups[ag.id].update({
                    f.severity: summary_assetgroups[ag.id][f.severity] + 1,
                    "total": summary_assetgroups[ag.id]["total"] + 1
                })

    # Generate findings stats
    month_ago =  datetime.today()-timedelta(days=30)
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
        # 'findings': raw_findings,
        'findings': scan_findings,
        'findings_stats': findings_stats,
        'scan_events': scan_events})


def list_scans_view(request):
    scan_list =  Scan.objects.all().order_by('-finished_at')

    paginator = Paginator(scan_list, 10)
    page = request.GET.get('page')
    try:
        scans = paginator.page(page)
    except PageNotAnInteger:
        scans = paginator.page(1)
    except EmptyPage:
        scans = paginator.page(paginator.num_pages)
    return render(request, 'list-scans-performed.html', { 'scans': scans })


def get_scans_stats(request):
    scope = request.GET.get('scope', None)
    data = {}
    if not scope:
        scan_defs = ScanDefinition.objects.all()
        scans = Scan.objects.all()
        data = {
            "nb_scans_defined": scan_defs.count(),
            "nb_scans_performed": scans.count(),
            "nb_periodic_scans": scan_defs.filter(scan_type="periodic").count(),
            "nb_active_periodic_scans": scan_defs.filter(scan_type="periodic", enabled=True).count()
        }
    elif scope == "scan_def":
        scan_id = request.GET.get('scan_id', None)
        num_records = request.GET.get('num_records', 10)
        if not scan_id: return  JsonResponse({})
        scan_def = get_object_or_404(ScanDefinition, id=scan_id)
        scans = reversed(Scan.objects.filter(scan_definition=scan_id).values('id', 'created_at', 'summary').order_by('-created_at')[:num_records])
        data = list(scans)
    elif scope == "scans":
        num_records = request.GET.get('num_records', 10)
        scans = reversed(Scan.objects.all().values('id', 'created_at', 'summary').order_by('-created_at')[:num_records])
        data = list(scans)

    return JsonResponse(data, json_dumps_params={'indent': 2}, safe=False)


def get_scans_heatmap(request):
    data = {}

    for scan in Scan.objects.all():
        # expected format: {timestamp: value, timestamp2: value2 ... }
        data.update({scan.updated_at.strftime("%s"): 1})
    return JsonResponse(data)


def get_scans_by_period(request):
    # remove to optimize

    data = {}
    start_date = request.GET.get('start', None)
    stop_date = request.GET.get('stop', None)
    if start_date and datetime.strptime(start_date, '%Y-%m-%dT%H:%M:%fZ'):
        start_date = datetime.strptime(start_date, '%Y-%m-%dT%H:%M:%fZ')
    if stop_date:
        stop_date = datetime.strptime(stop_date, '%Y-%m-%dT%H:%M:%fZ')

    scans = Scan.objects.filter(updated_at__gte=start_date)
    #scans = Scan.objects.filter(owner_id=request.user.id, updated_at__gte=start_date, updated_at__lte=stop_date)
    for scan in scans:
        # expected format: {timestamp: value, timestamp2: value2 ... }
        data.update({scan.updated_at.strftime("%s"): 1})
    return JsonResponse(data)


def get_scans_by_date(request):
    scopes = ["year", "month", "week", "day", "hour", "minute"]
    data = []
    date = request.GET.get('date', None)
    stop_date = None
    scope = request.GET.get('scope', None)
    if date and datetime.strptime(date, '%Y-%m-%dT%H:%M:%fZ'):
        date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%fZ')
    else:
        return HttpResponse(status=400)

    if not scope in scopes:
        return HttpResponse(status=400)

    if scope == "hour":
        stop_date = date + timedelta(hours=1)
    elif scope == "day":
        stop_date = date + timedelta(days=1)
    elif scope == "week":
        stop_date = date + timedelta(days=7)
    elif scope == "month":
        stop_date = date + timedelta(days=30)

    scans = Scan.objects.filter(updated_at__gte=date, updated_at__lte=stop_date)
    for scan in scans:
        # expected format: {timestamp: value, timestamp2: value2 ... }
        data.append({'scan_id': scan.id,
                     "status": scan.status,
                     "engine_type": scan.engine_type.name,
                     "title": scan.title,
                     "summary": json.dumps(scan.summary),
                     "updated_at": scan.updated_at,
                     "scan_definition_id": scan.scan_definition.id})
    return JsonResponse(data, safe=False)


def get_scan_report_html(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    tmp_scan = model_to_dict(scan)
    tmp_scan['assets'] = []
    for asset in scan.assets.all():
        tmp_scan['assets'].append(asset.value)

    tmp_scan['engine_type_name'] = scan.engine_type.name
    tmp_scan['engine_name'] = scan.engine.name
    tmp_scan['engine_policy_name'] = scan.engine_policy.name

    findings = RawFinding.objects.filter(scan=scan.id)

    #{asset1: [{finding1}, {finding2}]}
    findings_tmp = list()
    for sev in ["high", "medium", "low", "info"]:
        tmp = RawFinding.objects.filter(scan=scan, severity=sev).order_by('type')
        if tmp.count() > 0: findings_tmp += tmp

    findings_by_asset = dict()
    for asset in scan.assets.all():
        findings_by_asset_tmp = list()
        for sev in ["high", "medium", "low", "info"]:
            tmp = RawFinding.objects.filter(scan=scan, asset=asset, severity=sev).order_by('type')
            if tmp.count() > 0: findings_by_asset_tmp += tmp
        findings_by_asset.update({asset.value: findings_by_asset_tmp})

    findings_stats = {
        "total": findings.count(),
        "high": findings.filter(severity='high').count(),
        "medium": findings.filter(severity='medium').count(),
        "low": findings.filter(severity='low').count(),
        "info": findings.filter(severity='info').count(),
    }

    for asset in scan.assets.all():
        findings_stats.update({
            asset.value: {
                "total": findings.filter(asset=asset).count(),
                "high": findings.filter(asset=asset, severity='high').count(),
                "medium": findings.filter(asset=asset, severity='medium').count(),
                "low": findings.filter(asset=asset, severity='low').count(),
                "info": findings.filter(asset=asset, severity='info').count(),
            }
        })

    return render(request, 'report-scan.html', {
        'scan': tmp_scan,
        'findings': findings_by_asset,
        'findings_stats': findings_stats})

def get_scan_report_json(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)

    filename = str(scan.report_filepath) # Select your file here.
    if not os.path.isfile(filename):
        return HttpResponse(status=404)

    wrapper = FileWrapper(file(filename))
    response = HttpResponse(wrapper, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename=report_'+os.path.basename(filename)
    response['Content-Length'] = os.path.getsize(filename)

    return response

def get_scan_report_csv(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename=report_{}.csv'.format(scan_id)

    writer = csv.writer(response, delimiter=';')
    writer.writerow([
        'asset_value', 'asset_type',
        'engine_type', 'engine_name',
        'scan_title', 'scan_policy',
        'finding_id', 'finding_type', 'finding_status', 'finding_tags',
        'finding_severity', 'finding_description', 'finding_solution', 'finding_hash',
        'finding_creation_date', 'finding_risk_info', 'finding_cvss',
        'finding_links'
        ])
    for finding in RawFinding.objects.filter(scan=scan).order_by('asset__name', 'severity', 'title'):
        if 'links' in finding.risk_info.keys():
            finding_links = ", ".join(finding.risk_info['links'])
        else:
            finding_links = None
        writer.writerow([
            finding.asset.value, finding.asset.type,
            scan.engine_type.name, scan.engine.name,
            scan.title, scan.engine_policy.name,
            finding.id, finding.type, finding.status, ','.join(finding.tags),
            finding.severity, finding.description, finding.solution, finding.hash,
            finding.created_at, finding.risk_info, finding.risk_info['cvss_base_score'],
            finding_links
        ])

    return response

# todo: to update
def send_scan_reportzip(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)

    filename = str(scan.report_filepath) # Select your file here.
    print filename
    temp = tempfile.TemporaryFile()
    archive = zipfile.ZipFile(temp, 'w', zipfile.ZIP_DEFLATED)
    # for index in range(10):
    #     filename = __file__ # Select your files here.
    #     archive.write(filename, 'file%d.txt' % index)
    archive.write(filename)
    archive.close()
    wrapper = FileWrapper(temp)
    response = HttpResponse(wrapper, content_type='application/zip')
    response['Content-Disposition'] = "attachment; filename=scan_report_{}.zip".format(scan_id)
    response['Content-Length'] = temp.tell()
    temp.seek(0)
    return response


def delete_scan_view(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    if request.method == 'POST':
        scan.delete()
        messages.success(request, 'Scan successfully deleted!')
        #return redirect('list_scans_view')
        return redirect('list_scan_def_view')
    return render(request, 'delete-scan.html', {'scan': scan})


### Scan campaigns
def list_scan_campaigns(request):
    scan_campaigns = []
    for scan in ScanCampaign.objects.all():
        tmp_scan = model_to_dict(scan, exclude=['assets_list', 'scans_list'])
        tmp_scan['assets'] = list(scan['assets'])
        scan_campaigns.append(tmp_scan)
    return JsonResponse(scan_campaigns, safe=False)


def list_scan_campaigns_view(request):
    scan_campaigns = ScanCampaign.objects.filter(owner_id=request.user.id).order_by('-updated_at')
    return render(request, 'list-scan-campaigns.html', { 'scan_campaigns': scan_campaigns })


# @csrf_exempt
# def delete_scan_campaigns(request):
#     if request.method != 'POST':
#         return JsonResponse({'status': 'error'})
#
#     scan_campaigns = json.loads(request.body)
#     for scan_campaign_id in scan_campaigns:
#         ScanCampaign.objects.filter(scan_campaign_id=scan_campaign_id,owner_id=request.user.id).delete()
#
#     return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


def delete_scan_campaign_view(request, scan_campaign_id):
    scan_campaign = ScanCampaign.objects.filter(scan_campaign_id=scan_campaign_id,owner_id=request.user.id).first()
    if request.method == 'POST':
        scan_campaign.delete()
        messages.success(request, 'Scan Campaign successfully deleted!')
        return redirect('list_scan_campaigns_view')
    return render(request, 'delete-scan-campaign.html', {'scan_campaign': scan_campaign})


def add_scan_campaign_view(request):
    form = None
    if request.method == 'GET':
        form = ScanCampaignForm(initial={'scan_campaign_id': uuid.uuid4(), 'owner_id': request.user.id})
    elif request.method == 'POST':
        form = ScanCampaignForm(request.POST)
        if form.is_valid():
            scan_campaign_args = {
                'title':        form.cleaned_data['title'],
                #'scan_type':    form.cleaned_data['scan_type'],
                'owner_id':     request.user.id,
                'status':       "created",
                'scan_def_list': set(form.data.getlist('scan_def_list')),
                'enabled':      form.cleaned_data['enabled'] == "True",
                'scheduled_at': form.cleaned_data['scheduled_at']
            }
            scan_campaign = ScanCampaign(**scan_campaign_args)
            scan_campaign.save()

            messages.success(request, 'Creation submission successful')
            return redirect('list_scan_campaigns_view')

    return render(request, 'add-scan-campaign.html', {'form': form })


def edit_scan_campaign_view(request, scan_campaign_id):
    try:
        scan_campaign = ScanCampaign.objects.get(scan_campaign_id=scan_campaign_id, owner_id=request.user.id)
    except ScanCampaign.DoesNotExist:
        return HttpResponse(status=404)

    form = None
    if request.method == 'GET':
        form = ScanCampaignForm(initial=scan_campaign)
    elif request.method == 'POST':
        form = ScanCampaignForm(request.POST)
        if form.is_valid():
            scan_campaign.title         = form.cleaned_data['title']
            #scan_campaign.scan_type     = form.cleaned_data['scan_type']
            scan_campaign.scheduled_at  = form.cleaned_data['scheduled_at']
            scan_campaign.enabled       = form.cleaned_data['enabled'] == "True"
            scan_campaign.scan_def_list = set(form.data.getlist('scan_def_list'))

            scan_campaign.save()
            messages.success(request, 'Update submission successful')
            return redirect('list_scan_campaigns_view')

    return render(request, 'edit-scan-campaign.html', {'form': form, 'scan_campaign_id': scan_campaign_id})


def run_scan_campaign(request, scan_campaign_id):
    try:
        scan_campaign = ScanCampaign.objects.get(scan_campaign_id=scan_campaign_id, owner_id=request.user.id)
    except ScanCampaign.DoesNotExist:
        return HttpResponse(status=404)

    for scan_def_id in scan_campaign.scan_def_list:
        if scan_campaign.scan_type == "single":
            _run_scan(scan_def_id, request.user.id)

    messages.success(request, 'Scans enqueued!')
    return redirect('list_scan_def_view')


@csrf_exempt
def toggle_scan_campaign_status(request, scan_campaign_id):
    scan_campaign = ScanCampaign.objects.get(scan_campaign_id=scan_campaign_id, owner_id=request.user.id)
    scan_campaign.enabled = not scan_campaign.enabled
    scan_campaign.save()

    for scan_id in scan_campaign.scan_def_list:
        scan = ScanDefinition.objects.get(scan_definition_id=scan_id, owner_id=request.user.id)
        if scan.scan_type == 'periodic':
            try:
                periodic_task = PeriodicTask.objects.get(id=scan.periodic_task_id)
                periodic_task.enabled = not periodic_task.enabled
                periodic_task.last_run_at = None
                periodic_task.save()
            except PeriodicTask.DoesNotExist:
                pass

    ######  Todo: wait celery beat fix
    _update_celerybeat()
    ######LOL end

    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


## Scan Definitions
def list_scan_def_view(request):
    scans = Scan.objects.all()
    scan_defs = ScanDefinition.objects.all().order_by('-updated_at').annotate(scan_count=Count('scan')).annotate(engine_type_name=F('engine_type__name'))
    return render(request, 'list-scan-definitions.html', {
        'scan_defs': scan_defs, 'scans': scans })


def delete_scan_def_view(request, scan_def_id):
    scan_definition = get_object_or_404(ScanDefinition, id=scan_def_id)

    if request.method == 'POST':
        if scan_definition.scan_type == "periodic":
            try:
                periodic_task = scan_definition.periodic_task
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
    return render(request, 'delete-scan-definition.html', {'scan_def': scan_definition })


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
        #print "ScanDefinitionForm(request.POST):", ScanDefinitionForm(request.POST).errors
        if ScanDefinitionForm(request.POST).errors:
            print (ScanDefinitionForm(request.POST).errors)
        form = ScanDefinitionForm()

    elif request.method == 'POST':
        form = ScanDefinitionForm(request.POST)

        if form.is_valid():
            scan_definition = ScanDefinition()
            # scan_definition.engine_policy = EnginePolicy.objects.get(id=form.cleaned_data['engine_policy_id'])
            scan_definition.engine_policy = form.cleaned_data['engine_policy']
            scan_definition.engine_type = scan_definition.engine_policy.engine
            scan_definition.scan_type = form.cleaned_data['scan_type']
            scan_definition.title = form.cleaned_data['title']
            scan_definition.description = form.cleaned_data['description']
            scan_definition.owner = User.objects.get(id=request.user.id)
            scan_definition.status = "created"
            scan_definition.enabled = form.data['start_scan'] == "now"
            if form.cleaned_data['scan_type'] == 'periodic':
                scan_definition.every  = int(form.cleaned_data['every'])
                scan_definition.period = form.cleaned_data['period']

            if form.data['start_scan'] == "scheduled":
                try:
                    if form.cleaned_data['scheduled_at'] > datetime.now(): # check if it's future ...
                        scan_definition.scheduled_at = timezone(TIME_ZONE).localize(form.cleaned_data['scheduled_at'])
                        # scan_definition.scheduled_at = form.cleaned_data['scheduled_at']
                        scan_definition.enabled = True
                except:
                    scan_definition.scheduled_at = None

            if int(form.data['engine_id']) > 0:
                # todo: check if the engine is compliant with the scan policy
                scan_definition.engine = EngineInstance.objects.get(id=form.data['engine_id'])

            scan_definition.save()

            assets_list = []
            #print "form.data.getlist('assets_list'):", form.data.getlist('assets_list')
            for asset_id in form.data.getlist('assets_list'):
                asset = Asset.objects.get(id=asset_id)
                scan_definition.assets_list.add(asset)
                assets_list.append(asset.value)

            #print "form.data.getlist('assetgroups_list'):", form.data.getlist('assetgroups_list')
            assetgroups_list = []
            for assetgroup_id in form.data.getlist('assetgroups_list'):
                assetgroup = AssetGroup.objects.get(id=assetgroup_id)
                scan_definition.assetgroups_list.add(assetgroup)
                assetgroups_list.append(assetgroup.name)
            scan_definition.save()

            # Todo: check if no asset or asset group is defined
            messages.success(request, 'Creation submission successful')


            # Todo: check if the engine instance id is set (dedicated scanner)
            parameters = {
                "scan_params": {
                    "assets": assets_list,
                    "assetgroups": assetgroups_list,
                    "options": scan_definition.engine_policy.options,
                    #"scan_args": model_to_dict(scan_definition)
                },
                "scan_definition_id": str(scan_definition.id),
                "engine_name": str(scan_definition.engine_type.name).lower(),
                "owner_id": request.user.id,
            }

            #todo: check if its a direct, a scheduled or a periodic task
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

                periodic_task.enabled = False
                periodic_task.save()

                scan_definition.periodic_task = periodic_task
                _update_celerybeat()
            else: #Single later/now/scheduled
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
        'scan_policies': scan_policies })


def edit_scan_def_view(request, scan_def_id):
    scan_definition = get_object_or_404(ScanDefinition, id=scan_def_id)

    form = None
    if request.method == 'GET':
        form = ScanDefinitionForm(instance=scan_definition)
    elif request.method == 'POST':
        form = ScanDefinitionForm(request.POST)

        if form.is_valid():
            scan_definition.title = form.cleaned_data['title']
            scan_definition.status = "edited"
            scan_definition.description = form.cleaned_data['description']
            scan_definition.enabled = form.cleaned_data['enabled'] == True
            scan_definition.engine_policy = form.cleaned_data['engine_policy']
            scan_definition.engine_type = scan_definition.engine_policy.engine
            if len(form.data['engine']) > 0:
                # todo: check if the engine is compliant with the scan policy
                scan_definition.engine = EngineInstance.objects.get(id=form.data['engine'])
            else:
                scan_definition.engine = None

            scan_definition.assets_list.clear()
            scan_definition.assetgroups_list.clear()
            for asset_id in form.data.getlist('assets_list'):
                asset = Asset.objects.get(id=asset_id)
                scan_definition.assets_list.add(asset)
            for assetgroup_id in form.data.getlist('assetgroups_list'):
                assetgroup = AssetGroup.objects.get(id=assetgroup_id)
                scan_definition.assetgroups_list.add(assetgroup)

            if form.cleaned_data['scan_type'] == 'single':
                scan_definition.every = None
                scan_definition.period = None

            if form.cleaned_data['scan_type'] == 'single' and form.cleaned_data['scan_type'] == 'periodic':
                scan_definition.every = int(form.cleaned_data['every'])
                scan_definition.period = form.cleaned_data['period']

                schedule, created = IntervalSchedule.objects.get_or_create(
                    every=int(scan_definition.every),
                    period=scan_definition.period,
                )

                periodic_task = PeriodicTask.objects.create(
                    interval=schedule,
                    name='[PO] {}@{}'.format(scan_definition.title, scan_definition.id),
                    task='engines.tasks.start_periodic_scan_task',
                    args=json.dumps([parameters]),
                    #expires=datetime.utcnow() + timedelta(seconds=30),
                    queue='scan-'+scan_definition.engine_type.name.lower(),
                    routing_key='scan.'+scan_definition.engine_type.name.lower(),
                    last_run_at=None,
                )

                periodic_task.enabled = False
                periodic_task.save()

                scan_definition.periodic_task = periodic_task
                _update_celerybeat()

            scan_definition.save()
            messages.success(request, 'Update submission successful')
            return redirect('list_scan_def_view')

    return render(request, 'edit-scan-definition.html', {'form': form, 'scan_def_id': scan_def_id})


@csrf_exempt
def toggle_scan_def_status(request, scan_def_id):
    scan_def = get_object_or_404(ScanDefinition, id=scan_def_id)
    scan_def.enabled = not scan_def.enabled
    scan_def.save()

    if scan_def.scan_type == 'periodic':
        try:
            periodic_task = scan_def.periodic_task
            periodic_task.enabled = scan_def.enabled
            periodic_task.last_run_at = None
            periodic_task.save()
            #Todo: wait celery beat fix
            _update_celerybeat()
        except PeriodicTask.DoesNotExist:
            print ("Fuck, PeriodicTask '{}' does not exists".format(periodic_task.id))
            return JsonResponse({'status': 'error'}, 403)

    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


def detail_scan_def_view(request, scan_definition_id):
    scan_def = get_object_or_404(ScanDefinition, id=scan_definition_id)
    return render(request, 'details-scan-def.html', {
        'scan_def': scan_def})

def run_scan_def(request, scan_def_id):
    scan_def = get_object_or_404(ScanDefinition, id=scan_def_id)

    if scan_def.scan_type == "single":
        _run_scan(scan_def_id, request.user.id)
        messages.success(request, 'Scan enqueued!')
    else:
        messages.success(request, 'Error: Periodic scans are not runnable on demand')

    return redirect('list_scan_def_view')


def _run_scan(scan_def_id, owner_id, eta=None):
    scan_def = get_object_or_404(ScanDefinition, id=scan_def_id)

    if scan_def.engine:
        engine = scan_def.engine
    else:
        engines = EngineInstance.objects.filter(engine=scan_def.engine_type)
        if engines.count() > 0:
            engine = random.choice(engines)
        else:
            engine = None


    scan = Scan.objects.create(
        scan_definition=scan_def,
        title=scan_def.title,
        status="created",
        engine=engine,
        engine_type=scan_def.engine_type,
        engine_policy=scan_def.engine_policy,
        owner=User.objects.get(id=owner_id),
        #started_at=datetime.datetime.now()
    )
    scan.save()

    assets_list = []
    for asset in scan_def.assets_list.all():
        scan.assets.add(asset)
        #assets_list.append(asset.value)
        assets_list.append({
            "id": asset.id,
            "value": asset.value.strip(),
            "criticity": asset.criticity,
            "datatype": asset.type
        })
    # append assets related to the asset groups
    for assetgroup in scan_def.assetgroups_list.all():
        for a in assetgroup.assets.all():
            scan.assets.add(a)
            assets_list.append({
                "id": a.id,
                "value": a.value.strip(),
                "criticity": a.criticity,
                "datatype": a.type
            })

    if not engine:
        scan.status = "error"
        scan.started_at=datetime.now() #todo: check timezone
        scan.finished_at=datetime.now() #todo: check timezone
        scan.save()
        return False

    parameters = {
        "scan_definition_id": scan_def.id,
        "scan_params": {
            "assets": assets_list,
            "options": scan.engine_policy.options,
            "engine_id": engine.id,
            "scan_id": scan.id},
        "engine_id": engine.id,
        "engine_name": str(scan.engine_type.name).lower(),
        "owner_id": owner_id
    }

    scan_options = {
        "args": [parameters],
        "queue": 'scan-'+scan.engine_type.name.lower(),
        "routing_key": 'scan.'+scan.engine_type.name.lower(),
        "retry": False,
        "countdown": 1
    }

    if eta is not None:
        scan_options.update({"eta": eta})

    # enqueue the task in the right queue
    resp = startscan_task.apply_async(**scan_options)
    scan.status = "enqueued"
    scan.task_id = uuid.UUID(str(resp))
    scan.save()

    return scan


## Compare scans
def compare_scans_view(request):
    scan_a_id = request.GET.get("scan_a_id", None)
    scan_b_id = request.GET.get("scan_b_id", None)
    scan_a = get_object_or_404(Scan, id=scan_a_id)
    scan_b = get_object_or_404(Scan, id=scan_b_id)

    scan_a_missing_findings = scan_b.rawfinding_set.all().exclude(hash__in=scan_a.rawfinding_set.values_list('hash'))
    scan_b_missing_findings = scan_a.rawfinding_set.all().exclude(hash__in=scan_b.rawfinding_set.values_list('hash'))

    return render(request, 'compare-scans.html', {
        'scan_a': scan_a,
        'scan_b': scan_b,
        'scan_a_missing_findings': scan_a_missing_findings,
        'scan_b_missing_findings': scan_b_missing_findings
        })
