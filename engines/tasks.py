# -*- coding: utf-8 -*-

from __future__ import absolute_import
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from celery import shared_task
from celery.task.control import revoke
from .models import EngineInstance, Engine, EnginePolicy
from .utils import _get_engine_status, _get_scan_status, _run_scan, _import_findings
from findings.models import Finding, RawFinding
from assets.models import Asset, AssetGroup
from scans.models import Scan, ScanDefinition
from events.models import Event
from events.utils import new_finding_alert, missing_finding_alert
from common.utils import net
import requests
import json
import time
import datetime
import random
import uuid
import os
from copy import deepcopy

NB_MAX_RETRIES = 5
SLEEP_RETRY = 5
PROXIES = settings.PROXIES
TIMEOUT = settings.ENGINE_HTTP_TIMEOUT  # 10 minutes by default


@shared_task(bind=True, acks_late=True)
def test_task(self, queue_name):
    Event.objects.create(
        message="[EngineTasks/test_task()] Test Celery+RabbitMQ connexion on queue '{}'.".format(queue_name),
        type="DEBUG", severity="INFO",
        description="timezone.now(): {}".format(timezone.now())
    )
    return True


@shared_task(bind=True, acks_late=True)
def refresh_engines_status_task(self):
    for engine in EngineInstance.objects.filter(enabled=True).only("api_url", "status"):
        try:
            resp = requests.get(
                url=str(engine.api_url)+"status",
                verify=False, timeout=TIMEOUT, proxies=PROXIES)

            if resp.status_code == 200:
                engine.status = json.loads(resp.text)['status'].strip().upper()
            else:
                engine.status = "ERROR"
        except requests.exceptions.RequestException:
            engine.status = "ERROR"

        engine.save()

    return True


@shared_task(bind=True, acks_late=True)
def get_engine_status_task(self, engine_id):
    try:
        engine = EngineInstance.objects.filter(id=engine_id).only("api_url", "status").first()
        _get_engine_status(engine)
    except Exception:
        return False
    return True


@shared_task(bind=True, acks_late=True)
def get_engine_info_task(self, engine_id):
    try:
        engine = EngineInstance.objects.filter(id=engine_id).only("api_url", "status").first()
    except Exception:
        return False
    try:
        resp = requests.get(
            url=str(engine.api_url)+"info",
            verify=False, timeout=TIMEOUT, proxies=PROXIES)

        if resp.status_code == 200:
            engine.status = json.loads(resp.text)['status'].strip().upper()
        else:
            engine.status = "ERROR"
    except requests.exceptions.RequestException:
        engine.status = "ERROR"

    engine.save()
    return True


@shared_task(bind=True, acks_late=True)
def importfindings_task(self, report_filename, owner_id, engine, min_level):
    Event.objects.create(message="[EngineTasks/importfindings_task/{}] Task started with engine {}.".format(self.request.id, engine), type="INFO", severity="INFO")

    level_to_value = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    value_to_level = {v: k for k, v in level_to_value.items()}

    min_level = level_to_value.get(min_level, 0)

    if engine == 'nessus':

        summary = {
            "info": 0, "low": 0, "medium": 0, "high": 0, "critical": 0,
            "missing": 0, "new": 0, "total": 0
        }

        Event.objects.create(message='[EngineTasks/importfindings_task()] engine: nessus', type="INFO", severity="DEBUG")
        try:
            import cElementTree as ET
        except ImportError:
            try:
                # Python 2.5 need to import a different module
                import xml.etree.cElementTree as ET
            except ImportError:
                Event.objects.create(message="[EngineTasks/importfindings_task()] Unable to import xml parser.", type="ERROR", severity="ERROR")
                return False
        # parse nessus file
        data = list()
        try:
            dom = ET.parse(open(report_filename, "r"))
            root = dom.getroot()
        except Exception as e:
            Event.objects.create(message="[EngineTasks/importfindings_task()] Unable to open and parse report file.", description="{}".format(e.message),
                         type="ERROR", severity="ERROR")
            return False
        try:
            for block in root:
                if block.tag == 'Report':
                    for report_host in block:
                        asset = dict()
                        asset['name'] = report_host.attrib['name']
                        for report_item in report_host:
                            if report_item.tag == 'HostProperties':
                                for tag in report_item:
                                    asset[tag.attrib['name']] = tag.text
                            if not net.is_valid_ip(asset.get('host-ip', asset.get('name'))):
                                Event.objects.create(
                                    message="[EngineTasks/importfindings_task()] finding not added.",
                                    type="DEBUG", severity="DEBUG",
                                    description="No ip address for asset {} found".format(asset.get('name'))
                                )
                                summary['missing'] += 1
                                continue
                            if 'pluginName' in report_item.attrib:
                                summary['total'] += 1
                                finding = {
                                    "target": {
                                        "addr": [asset.get('host-ip', asset.get('name'))]
                                    },
                                    "metadata": {
                                        "risk": {
                                            "cvss_base_score": "0.0"
                                        },
                                        "vuln_refs": {},
                                        "links": list(),
                                        "tags": ["nessus"]
                                    },
                                    "title": report_item.attrib['pluginName'],
                                    "type": "nessus_manual_import",
                                    "confidence": "3",
                                    "severity": "info",
                                    "description": "n/a",
                                    "solution": "n/a",
                                    "raw": None
                                }
                                if int(report_item.attrib['severity']) < min_level:
                                    # if below min level descard finding
                                    summary['missing'] += 1
                                    continue
                                finding['severity'] = value_to_level.get(int(report_item.attrib['severity']), 'info')
                                summary[finding['severity']] += 1

                                for param in report_item:
                                    if param.tag == 'vuln_publication_date':
                                        finding['metadata']['vuln_publication_date'] = param.text

                                    if param.tag == 'solution':
                                        finding['solution'] = param.text
                                    if param.tag == 'description':
                                        finding['description'] = param.text

                                    if param.tag == 'cvss_vector':
                                        finding['metadata']['risk']['cvss_vector'] = param.text
                                    if param.tag == 'cvss_base_score':
                                        finding['metadata']['risk']['cvss_base_score'] = param.text

                                    if param.tag == 'cvss_temporal_vector':
                                        finding['metadata']['risk']['cvss_temporal_vector'] = param.text
                                    if param.tag == 'cvss_temporal_score':
                                        finding['metadata']['risk']['cvss_temporal_score'] = param.text

                                    if param.tag == 'cvss3_vector':
                                        finding['metadata']['risk']['cvss3_vector'] = param.text
                                    if param.tag == 'cvss3_base_score':
                                        finding['metadata']['risk']['cvss3_base_score'] = param.text

                                    if param.tag == 'cvss3_temporal_vector':
                                        finding['metadata']['risk']['cvss3_temporal_vector'] = param.text
                                    if param.tag == 'cvss3_temporal_score':
                                        finding['metadata']['risk']['cvss3_temporal_score'] = param.text

                                    if param.tag == 'exploit_available':
                                        finding['metadata']['risk']['exploit_available'] = param.text
                                    if param.tag == 'exploitability_ease':
                                        finding['metadata']['risk']['exploitability_ease'] = param.text
                                    if param.tag == 'exploited_by_nessus':
                                        finding['metadata']['risk']['exploited_by_nessus'] = param.text
                                    if param.tag == 'patch_publication_date':
                                        finding['metadata']['risk']['patch_publication_date'] = param.text

                                    if param.tag == 'cve':
                                        finding['metadata']['vuln_refs']['CVE'] = param.text.split(', ')
                                    if param.tag == 'bid':
                                        finding['metadata']['vuln_refs']['BID'] = param.text.split(', ')
                                    if param.tag == 'xref':
                                        finding['metadata']['vuln_refs'][param.text.split(':')[0].upper()] = param.text.split(':')[1]
                                    if param.tag == 'see_also':
                                        for link in param.text.split('\n'):
                                            finding['metadata']['links'].append(link)

                                    if param.tag == 'plugin_output':
                                        finding['raw'] = param.text
                                data.append(finding)
        except Exception as e:
            Event.objects.create(message="[EngineTasks/importfindings_task()] Error parsing nessus file.", description="{}".format(e.message),
                         type="ERROR", severity="ERROR")
            return False
        try:
            nessus_engine = Engine.objects.filter(name='NESSUS').first()
            nessus_import_policy = EnginePolicy.objects.filter(id=17).first()
            scan_definition = ScanDefinition.objects.filter(title='Nessus import').first()
            if scan_definition is None:
                scan_definition = ScanDefinition.objects.create(title='Nessus import',
                                                                scan_type='single',
                                                                description='Scan definition for nessus imports',
                                                                engine_type=nessus_engine,
                                                                engine_policy=nessus_import_policy)
            scan = Scan.objects.create(title='nessus_' + datetime.date.today().isoformat(),
                                       status='finished',
                                       summary=summary,
                                       engine_type=nessus_engine,
                                       engine_policy=nessus_import_policy,
                                       owner=get_user_model().objects.filter(id=owner_id).first(),
                                       scan_definition=scan_definition)
            scan.save()
            _import_findings(findings=data, scan=scan)
        except Exception as e:
            Event.objects.create(message="[EngineTasks/importfindings_task()] Error importing findings.", description="{}".format(e.message),
                type="ERROR", severity="ERROR")
            return False
    else:
        # has to be json
        with open(report_filename) as data_file:
            data = json.load(data_file)

        try:
            _import_findings(findings=data['issues'], scan=Scan.objects.filter(title='test').first())
        except Exception as e:
            Event.objects.create(message="[EngineTasks/importfindings_task()] Error importing findings.", description="{}".format(e.message),
                type="ERROR", severity="ERROR")
            return False

    return True


@shared_task(bind=True, acks_late=True)
def stopscan_task(self, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    Event.objects.create(message="[EngineTasks/stopscan_task/{}] Task started.".format(self.request.id), type="INFO", severity="INFO", scan=scan)

    # Revoke Scan job tasks
    for scanjob in scan.scanjob_set.all():
        try:
            revoke(str(scanjob.task_id), terminate=True, signal='SIGKILL')
        except Exception:
            pass

    # Revoke Scan task
    try:
        revoke(str(scan.task_id), terminate=True, signal='SIGKILL')
    except Exception:
        pass

    engine = scan.engine
    for scanjob in scan.scanjob_set.all():
        try:
            resp = requests.get(url=str(engine.api_url)+"stop/"+str(scanjob.id), verify=False, proxies=PROXIES)
            if resp.status_code != 200 or json.loads(resp.text)['status'] == "error":
                scan.update_status('error', 'finished_at')
                Event.objects.create(message="[EngineTasks/stopscan_task/{}] Error when stopping scan job '{}'.".format(self.request.id, scanjob.id), type="ERROR", severity="ERROR", scan=scan, description="STATUS CODE={}, {}".format(resp.status_code, json.loads(resp.text)))
                return False
        except Exception as e:
            scan.update_status('error', 'finished_at')
            Event.objects.create(message="[EngineTasks/stopscan_task/{}] Error when stopping scan job '{}' (exception).".format(self.request.id, scanjob.id), type="ERROR", severity="ERROR", scan=scan, description="{}".format(e.message))
            return False

    scan.update_status('stopped', 'finished_at')

    Event.objects.create(message="[EngineTasks/stopscan_task/{}] Scan successfully stopped.".format(self.request.id), type="INFO", severity="INFO", scan=scan)
    return True


@shared_task(bind=True, acks_late=True)
def startscan_task(self, params):
    evt_prefix = "[EngineTasks/startscan_task/{}] ".format(self.request.id)

    scan = Scan.objects.get(id=params['scan_params']['scan_id'])
    Event.objects.create(message=f"{evt_prefix} Task started.", type="INFO", severity="INFO", scan=scan)
    scan.update_status('started', 'started_at')

    return _run_scan(evt_prefix, scan.id)


@shared_task(bind=True, acks_late=True)
def start_periodic_scan_task(self, params):
    evt_prefix = "[EngineTasks/start_periodic_scan_task/{}] ".format(self.request.id)
    scan_def = ScanDefinition.objects.get(id=params['scan_definition_id'])
    Event.objects.create(message=f"{evt_prefix} Task started.", type="INFO", severity="INFO")

    # -0- Create the Scan entry in db
    scan = Scan.objects.create(
        scan_definition=scan_def,
        title=scan_def.title,
        status="started",
        engine_type=scan_def.engine_type,
        engine_policy=scan_def.engine_policy,
        owner=scan_def.owner,
        started_at=timezone.now(),
        task_id=uuid.UUID(str(self.request.id))
    )
    scan.save()
    Event.objects.create(message=f"{evt_prefix} Scan created.", type="INFO", severity="INFO", scan=scan)

    return _run_scan(evt_prefix, scan.id)
