# -*- coding: utf-8 -*-

from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from app.settings import SUPERVISORD_API_URL
from .models import Scan, ScanDefinition
from engines.models import EngineInstance
from engines.tasks import startscan_task

import xmlrpclib
import uuid
import random
from datetime import datetime


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

    if not engine:
        scan.status = "error"
        scan.started_at = datetime.now()  # todo: check timezone
        scan.finished_at = datetime.now()  # todo: check timezone
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
