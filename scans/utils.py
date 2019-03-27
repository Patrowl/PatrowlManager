# -*- coding: utf-8 -*-

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.utils import timezone
from app.settings import SUPERVISORD_API_URL
from .models import Scan, ScanDefinition, SCAN_STATUS
from engines.models import EngineInstance
from engines.tasks import startscan_task

import xmlrpclib
import uuid
import random


def _update_celerybeat():
    print("INFO: Updating Celery Beat Scheduler...")
    server = xmlrpclib.Server(SUPERVISORD_API_URL)

    try:
        if server.supervisor.getProcessInfo("celery-beat")['statename'] in ['RUNNING', 'RESTARTING']:
            server.supervisor.stopProcess("celery-beat")
    except Exception:
        print ("error ", server.supervisor.getProcessInfo("celery-beat")['statename'])

    try:
        if server.supervisor.getProcessInfo("celery-beat")['statename'] in ['FATAL', 'SHUTDOWN', 'STOPPED']:
            server.supervisor.startProcess("celery-beat", False)
    except Exception:
        print ("error:", server.supervisor.getProcessInfo("celery-beat")['statename'])

    return server.supervisor.getProcessInfo("celery-beat")['statename']


def _run_scan(scan_def_id, owner_id, eta=None):
    scan_def = get_object_or_404(ScanDefinition, id=scan_def_id)
    engine = None

    if scan_def.engine:
        engine = scan_def.engine
    else:
        engines = EngineInstance.objects.filter(engine=scan_def.engine_type)
        if engines.count() > 0:
            engine = random.choice(engines)

    scan = Scan.objects.create(
        scan_definition=scan_def,
        title=scan_def.title,
        status="created",
        engine=engine,
        engine_type=scan_def.engine_type,
        engine_policy=scan_def.engine_policy,
        owner=User.objects.get(id=owner_id)
    )
    scan.save()

    if engine is None:
        scan.status = "error"
        scan.started_at = timezone.now()
        scan.finished_at = timezone.now()
        scan.save()
        return False

    assets_list = []
    for asset in scan_def.assets_list.all():
        scan.assets.add(asset)
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
        "queue": 'scan',
        "retry": False,
        "countdown": 1,
        "ignore_result": True
    }

    if eta is not None:
        print("eta:", eta)
        scan_options.update({"eta": eta})

    # enqueue the task in the right queue
    resp = startscan_task.apply_async(**scan_options)
    scan.status = "enqueued"
    scan.task_id = uuid.UUID(str(resp))
    scan.save()

    return True


def _search_scans(request):
    filters = {}
    excludes = {}
    filter_limit = request.GET.get('limit', "")
    filter_by_title = request.GET.get('_title', None)
    filter_by_title_cond = request.GET.get('_title_cond', None)
    filter_by_status = request.GET.get('_status', None)
    filter_by_status_cond = request.GET.get('_status_cond', None)

    if filter_by_title:
        if filter_by_title_cond in ["exact", "icontains", "istartwith", "iendwith"]:
            filters.update({"title__{}".format(filter_by_title_cond): filter_by_title})
        elif filter_by_asset_cond in ["not_exact", "not_icontains", "not_istartwith", "not_iendwith"]:
            excludes.update({"title__{}".format(filter_by_title_cond[4:]): filter_by_title})
    if filter_by_status and filter_by_status in SCAN_STATUS:
        if filter_by_status_cond == "exact":
            filters.update({"status__{}".format(filter_by_status_cond): filter_by_status})
        elif filter_by_status_cond == "not_exact":
            excludes.update({"status__{}".format(filter_by_status_cond[4:]): filter_by_status})

    if str(filter_limit).isdigit():
        scans = Scan.objects.filter(**filters).exclude(**excludes)[:int(filter_limit)]
    else:
        scans = Scan.objects.filter(**filters).exclude(**excludes)

    return scans
