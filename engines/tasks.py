# -*- coding: utf-8 -*-

from __future__ import absolute_import
from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404
from celery import shared_task
from celery.task.control import revoke
from .models import EngineInstance, Engine, EnginePolicy
from findings.models import Finding, RawFinding
from assets.models import Asset, AssetGroup, AssetCategory
from scans.models import Scan, ScanDefinition
from events.models import Event
from events.utils import new_finding_alert, missing_finding_alert
from common.utils import net
from assets.apis import _add_asset_tags
import requests
import json
import time
import datetime
import random
import uuid
import os
from copy import deepcopy
import re
import logging

NB_MAX_RETRIES = 5
SLEEP_RETRY = 5
PROXIES = settings.PROXIES
TIMEOUT = settings.SCAN_TIMEOUT  # 10 minutes by default


@shared_task(bind=True, acks_late=True)
def test_task(self, queue_name):
    Event.objects.create(
        message="[EngineTasks/test_task()] Test celery+RabbitMQ connexion on queue '{}'.".format(queue_name),
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
    for engine in EngineInstance.objects.filter(id=engine_id).only("api_url", "status"):
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
def get_engine_info_task(self, engine_id):
    for engine in EngineInstance.objects.filter(id=engine_id).only("api_url", "status"):
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
    Event.objects.create(message="[EngineTasks/stopscan_task/{}] Task started.".format(self.request.id),
        type="INFO", severity="INFO", scan=scan)

    revoke(str(scan.task_id), terminate=True)

    engine = scan.engine
    resp = None
    try:
        if scan.engine_type == Engine.objects.filter(name='NESSUS').first():
            #scan_status = _get_scan_status(engine=engine, scan_id=scan.id, scan_options=scan.options)
            resp = requests.get(url=str(engine.api_url)+"stop/"+str(scan_id)+"/"+str(scan.nessscan_id), verify=False, proxies=PROXIES)
        else:
            resp = requests.get(url=str(engine.api_url)+"stop/"+str(scan_id), verify=False, proxies=PROXIES)
        if resp.status_code != 200 or json.loads(resp.text)['status'] == "error":
            scan.status = "error"
            scan.finished_at = timezone.now()
            scan.save()
            Event.objects.create(message="[EngineTasks/stopscan_task/{}] Error when stopping scan.".format(self.request.id),
                type="ERROR", severity="ERROR", scan=scan, description="STATUS CODE={}, {}".format(resp.status_code, json.loads(resp.text)))
            return False
    except Exception as e:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        Event.objects.create(message="[EngineTasks/stopscan_task/{}] Error when stopping scan (exception).".format(self.request.id),
            type="ERROR", severity="ERROR", scan=scan, description="{}".format(e.message))
        return False

    scan.status = "stopped"
    scan.finished_at = timezone.now()
    scan.save()
    Event.objects.create(message="[EngineTasks/stopscan_task/{}] Scan successfully stopped.".format(self.request.id),
        type="INFO", severity="INFO", scan=scan)
    return True


@shared_task(bind=True, acks_late=True)
def startscan_task(self, params):
    scan = Scan.objects.get(id=params['scan_params']['scan_id'])
    scan.status = "started"
    scan.started_at = timezone.now()
    scan.save()

    Event.objects.create(message="[EngineTasks/startscan_task/{}] Task started.".format(self.request.id),
        type="INFO", severity="INFO", scan=scan)

    # Check if the assets list is not empty
    if len(params['scan_params']['assets']) == 0:
        Event.objects.create(message="[EngineTasks/startscan_task/{}] BeforeScan - No assets set. Task aborted.".format(self.request.id), type="ERROR", severity="ERROR", scan=scan)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        return False

    # Check if the engine policy complies with the asset types
    allowed_asset_types = eval(scan.engine_type.allowed_asset_types)
    has_error = False
    for asset in params['scan_params']['assets']:
        if asset['datatype'] not in allowed_asset_types:
            has_error = True
            Event.objects.create(message="[EngineTasks/startscan_task/{}] BeforeScan - Asset '' has type '{}' unsupported by the engine policy ('{}'). Task aborted.".format(self.request.id, asset["value"], asset["datatype"], ", ".join(allowed_asset_types)), type="ERROR", severity="ERROR", scan=scan)

    if has_error is True:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        return False

    engine_inst = None
    # -0- select an engine instance
    if scan.scan_definition.engine is None:
        engine_candidates = EngineInstance.objects.filter(
            engine__name=str(scan.scan_definition.engine_type.name).upper(),
            status="READY",
            enabled=True)
        if len(engine_candidates) > 0:
            engine_inst = random.choice(engine_candidates)
        else:
            engine_inst = None
            Event.objects.create(message="[EngineTasks/startscan_task/{}] BeforeScan - No engine '{}' available. Task aborted.".format(self.request.id, scan.scan_definition.engine_type.name), type="ERROR", severity="ERROR", scan=scan)
    else:
        engine_inst = scan.scan_definition.engine
        if engine_inst.status != "READY" or engine_inst.enabled is False:
            Event.objects.create(message="[EngineTasks/startscan_task/{}] BeforeScan - Engine '{}' not available (status: {}, enabled: {}). Task aborted.".format(self.request.id, engine_inst.name, engine_inst.status, engine_inst.enabled), type="ERROR", severity="ERROR", scan=scan)
            engine_inst = None

    # check if the selected engine instance is available
    if engine_inst is None:
        Event.objects.create(message="[EngineTasks/startscan_task/{}] BeforeScan - No engine '{}' available. Task aborted.".format(self.request.id, params['engine_name']), type="ERROR", severity="ERROR", scan=scan)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        return False

    Event.objects.create(message="[EngineTasks/startscan_task/{}] Engine '{}' has been selected.".format(self.request.id, engine_inst.name), type="INFO", severity="INFO", scan=scan)
    scan.engine = engine_inst
    scan.save()

    # -1- wait the engine come available for accepting scans (status=ready)
    retries = NB_MAX_RETRIES
    while _get_engine_status(engine=engine_inst) != "READY" and retries > 0:
        time.sleep(1)
        retries -= 1

    if retries == 0:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        Event.objects.create(message="[EngineTasks/startscan_task/{}] BeforeScan - max_retries ({}) reached. Task aborted.".format(self.request.id, retries),
                     type="ERROR", severity="ERROR", scan=scan)
        return False

    # -2- call the engine REST API /startscan
    resp = None
    try:
        resp = requests.post(
            url=str(engine_inst.api_url)+"startscan",
            data=json.dumps(params['scan_params']),
            headers={'Content-type': 'application/json', 'Accept': 'application/json'},
            proxies=PROXIES,
            timeout=TIMEOUT)
        scan_options=json.dumps(params['scan_params']['options'])
        if scan.engine_type == Engine.objects.filter(name='NESSUS').first():
            nessscan_id = int(json.loads(resp.text)['nessscan_id'])
            scan.nessscan_id = nessscan_id
            scan.save()

        # if resp.status_code != 200 or json.loads(resp.text)['status'] != "accepted":
        if resp.status_code != 200 or json.loads(resp.text)['status'] not in ["accepted", "ACCEPTED"]:
            scan.status = "error"
            scan.finished_at = timezone.now()
            scan.save()
            response_reason = 'Unknown'
            if 'details' in json.loads(resp.text) and 'reason' in json.loads(resp.text)['details']:
                response_reason = json.loads(resp.text)['details']['reason']
            elif 'reason' in json.loads(resp.text):
                response_reason = json.loads(resp.text)['reason']

            Event.objects.create(message="[EngineTasks/startscan_task/{}] DuringScan - something goes wrong (response_status_code={}, response_status={}, response_details={}). Task aborted.".format(self.request.id, resp.status_code, json.loads(resp.text)['status'], response_reason),
                description=str(resp.text), type="ERROR", severity="ERROR", scan=scan)
            return False
    except requests.exceptions.RequestException as e:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        Event.objects.create(message="[EngineTasks/startscan_task/{}] DuringScan - something goes wrong. Task aborted.".format(self.request.id),
            description=str(e), type="ERROR", severity="ERROR", scan=scan)

        return False

    # -3- wait the engine come available for accepting scans (status=ready)
    retries = NB_MAX_RETRIES  # test value
    scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id, scan_options=scan_options)

    while scan_status not in ['FINISHED', 'READY'] and retries > 0:
        if scan_status in ['STARTED', 'SCANNING', 'PAUSING', 'STOPING']:
            retries = NB_MAX_RETRIES
        else:
            Event.objects.create(message="[EngineTasks/startscan_task/{}] DuringScan - bad scanner status: {} (retries left={}).".format(self.request.id, scan_status, retries),
                type="ERROR", severity="ERROR", scan=scan)
            retries -= 1
        time.sleep(SLEEP_RETRY)
        scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id, scan_options=scan_options)
        print("scan status (in loop): {}".format(scan_status))

    if retries == 0:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        Event.objects.create(message="[EngineTasks/startscan_task/{}] DuringScan - max_retries ({}) reached. Task aborted.".format(self.request.id, retries),
            type="ERROR", severity="ERROR", scan=scan)
        return False

    Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - scan report is now available: {}.".format(self.request.id, str(engine_inst.api_url)+"getreport/"+str(scan.id)),
                         type="DEBUG", severity="DEBUG", scan=scan)
    Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - findings are now available: {}.".format(self.request.id, str(engine_inst.api_url)+"getfindings/"+str(scan.id)),
                         type="DEBUG", severity="DEBUG", scan=scan)

    # @Todo: change to wait the report becomes available until a timeout
    time.sleep(60)  # wait the scan process finish to write the report

    # -4- get the results (findings)
    try:
        if scan.engine_type == Engine.objects.filter(name='NESSUS').first():
            scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id, scan_options=scan_options)
            resp = requests.get(url=str(engine_inst.api_url)+"getfindings/"+str(scan.id)+"/"+str(scan.nessscan_id), proxies=PROXIES)
        else:
            resp = requests.get(
                url=str(engine_inst.api_url) + "getfindings/" + str(scan.id),
                proxies=PROXIES)
        if resp.status_code != 200 or json.loads(resp.text)['status'] == "error":
            scan.status = "error"
            scan.finished_at = timezone.now()
            scan.save()
            response_reason = "Undefined"

            if 'details' in json.loads(resp.text) and 'reason' in json.loads(resp.text)['details']:
                response_reason = json.loads(resp.text)['details']['reason']
            elif 'reason' in json.loads(resp.text):
                response_reason = json.loads(resp.text)['reason']

            Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong"
                                         " in 'getfindings' call (response_status_code={}, response_status={}, "
                                         "response_details={}). Task aborted.".format(self.request.id,
                                         resp.status_code,json.loads(resp.text)['status'], response_reason),
                                        type="ERROR", severity="ERROR", scan=scan, description="{}".format(resp.text))
            return False

    except Exception as e:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in 'getfindings' call (request_status_code={}). Task aborted.".format(self.request.id, resp.status_code),
            type="ERROR", severity="ERROR", scan=scan, description="{}\n{}".format(e, resp.text))
        return False


    # -5- import the results in DB
    try:
        _import_findings(findings=deepcopy(json.loads(resp.text)['issues']), scan=scan)

    except Exception as e:
        Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in '_import_findings' call. Task aborted.".format(self.request.id), description="{}".format(e),
            type="ERROR", severity="ERROR", scan=scan)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        return False

    # -6- get and store the report
    try:
        resp = requests.get(url=str(engine_inst.api_url)+"getreport/"+str(scan.id), stream=True, proxies=PROXIES)
        if resp.status_code == 200:
            user_report_dir = settings.MEDIA_ROOT + "/reports/"+str(params['owner_id'])+"/"
            if not os.path.exists(user_report_dir):
                os.makedirs(user_report_dir)
            fname = str(engine_inst.name) + "_" + str(scan.id) + ".json"
            scan.report_filepath = user_report_dir+str(fname)
            with open(scan.report_filepath, 'wb') as f:
                for chunk in resp:
                    f.write(chunk)
        else:
            scan.status = "error"
            scan.finished_at = timezone.now()
            scan.save()
            Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in 'getreport' call: {}. Task aborted.".format(self.request.id, resp.status_code),
                type="ERROR", severity="ERROR", scan=scan)
            return False

    except Exception as e:
        print(e.message)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in 'getreport' call. Task aborted.".format(self.request.id), description="{}".format(e.message), type="ERROR", severity="ERROR", scan=scan)
        return False

    scan.status = "finished"
    scan.finished_at = timezone.now()
    scan.save()
    Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - scan finished at: {}.".format(self.request.id, scan.finished_at), type="DEBUG", severity="INFO", scan=scan)
    return True


@shared_task(bind=True, acks_late=True)
def start_periodic_scan_task(self, params):
    scan_def = ScanDefinition.objects.get(id=params['scan_definition_id'])
    Event.objects.create(
        message="[EngineTasks/start_periodic_scan_task/{}] Task started.".format(self.request.id),
        type="INFO", severity="INFO")

    engine_inst = None
    # select an instance of the scanner
    if scan_def.engine:
        engine_inst = scan_def.engine
        if engine_inst.status != "READY" or engine_inst.enabled is False:
            Event.objects.create(message="[EngineTasks/start_periodic_scan_task/{}] BeforeScan - Engine '{}' not available (status: {}, enabled: {}). Task aborted.".format(self.request.id, engine_inst.name, engine_inst.status, engine_inst.enabled), type="ERROR", severity="ERROR", scan=scan_def)
            engine_inst = None
    else:
        engine_candidates = EngineInstance.objects.filter(engine__name=str(scan_def.engine_type.name).upper(), status="READY", enabled=True)
        if len(engine_candidates) > 0:
            engine_inst = random.choice(engine_candidates)
        else:
            Event.objects.create(message="[EngineTasks/start_periodic_scan_task/{}] BeforeScan - No engine '{}' available. Task aborted.".format(self.request.id, scan_def.engine_type.name), type="ERROR", severity="ERROR", scan=scan_def)
            engine_inst = None

    # -0- create the Scan entry in db
    scan = Scan.objects.create(
        scan_definition=scan_def,
        title=scan_def.title,
        status="started",
        engine_type=scan_def.engine_type,
        engine=engine_inst,
        engine_policy=scan_def.engine_policy,
        owner=scan_def.owner,
        started_at=timezone.now(),
        task_id=uuid.UUID(str(self.request.id))
    )
    scan.save()
    Event.objects.create(
        message="[EngineTasks/start_periodic_scan_task/{}] Scan created.".format(self.request.id),
        type="INFO", severity="INFO", scan=scan)

    # Check if the engine policy complies with the asset types
    allowed_asset_types = eval(scan_def.engine_type.allowed_asset_types)
    has_error = False
    for asset in params['scan_params']['assets']:
        if asset['datatype'] not in allowed_asset_types:
            has_error = True
            Event.objects.create(message="[EngineTasks/start_periodic_scan_task/{}] BeforeScan - Asset '' has type '{}' unsupported by the engine policy ('{}'). Task aborted.".format(self.request.id, asset["value"], asset["datatype"], ", ".join(allowed_asset_types)), type="ERROR", severity="ERROR", scan=scan)

    if has_error is True:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        return False

    # check if the selected engine instance is available
    if not engine_inst:
        # print("ERROR: startscan_task/select_instance: not engine '{}' available".format(params['engine_name']))
        Event.objects.create(message="[EngineTasks/start_periodic_scan_task/{}] BeforeScan - No '{}' engine available. Task aborted.".format(self.request.id, scan_def.engine_type.name),
                 type="ERROR", severity="ERROR", scan=scan)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        return False

    # Append assets
    for asset in scan_def.assets_list.all():
        scan.assets.add(asset)
    for assetgroup in scan_def.assetgroups_list.all():
        for a in assetgroup.assets.all():
            scan.assets.add(a)
    for taggroup in scan_def.taggroups_list.all():
        for a in taggroup.asset_set.all():
            scan.assets.add(a)
    scan.save()
    assets_list = []
    for asset in scan.assets.all():
        assets_list.append({
            "id": asset.id,
            "value": asset.value.strip(),
            "criticity": asset.criticity,
            "datatype": asset.type
        })
    params['scan_params']['assets'] = assets_list

    # Check if the assets list is not empty
    if len(params['scan_params']['assets']) == 0:
        Event.objects.create(message="[EngineTasks/start_periodic_scan_task/{}] BeforeScan - No assets set. Task aborted.".format(self.request.id), type="ERROR", severity="ERROR", scan=scan)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        return False

    params['scan_params']['scan_id'] = str(scan.id)

    # params['scan_params']['scan_definition_id_options'] = str(params['scan_definition_id'])

    # -1- wait the engine come available for accepting scans (status=ready)
    retries = NB_MAX_RETRIES
    while _get_engine_status(engine=engine_inst) != "READY" and retries > 0:
        print("--waiting scanner ready: {}".format(_get_engine_status(engine=engine_inst)))
        time.sleep(1)
        retries -= 1

    if retries == 0:
        print("ERROR: start_periodicscan_task/beforescan - max_retries ({}) reached.".format(NB_MAX_RETRIES))
        Event.objects.create(message="ERROR: start_periodicscan_task/beforescan - max_retries ({}) reached.".format(NB_MAX_RETRIES), type="ERROR", severity="ERROR", scan=scan)
        return False

    # -2- call the engine REST API /startscan
    try:
        resp = requests.post(
            url=str(engine_inst.api_url)+"startscan",
            data=json.dumps(params['scan_params']),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json'},
            proxies=PROXIES,
            timeout=TIMEOUT)
        scan_options=json.dumps(params['scan_params']['options'])
        if scan.engine_type == Engine.objects.filter(name='NESSUS').first():
            nessscan_id = int(json.loads(resp.text)['nessscan_id'])
            scan.nessscan_id = nessscan_id
            scan.save()

        # if resp.status_code != 200 or json.loads(resp.text)['status'] != "accepted":
        if resp.status_code != 200 or json.loads(resp.text)['status'] not in ["accepted", "ACCEPTED"]:
            print("Something goes wrong in 'startscan_task/scan' (request_status_code={}, scan_response={})",
                  resp.status_code, str(resp.text))
            Event.objects.create(message="Something goes wrong in 'startscan_task/scan' (request_status_code={}, scan_response={})".format(resp.status_code, str(resp.text)), type="ERROR", severity="ERROR", scan=scan)
            return False
    except requests.exceptions.RequestException:
        print("Something goes wrong in 'startscan_task/scan' (request_status_code={}, engine_status={})", resp.status_code, json.loads(resp.text)['status'])
        Event.objects.create(message="Something goes wrong in 'startscan_task/scan' (request_status_code={}, engine_status={})".format(resp.status_code, json.loads(resp.text)['status']), type="ERROR", severity="ERROR", scan=scan)
        return False

    # -3- wait the engine come available for accepting scans (status=ready)
    retries = NB_MAX_RETRIES  # test value
    scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id, scan_options=scan_options)
    # print("status: {}".format(scan_status))

    while scan_status not in ['READY', 'FINISHED'] and retries > 0:
        if scan_status in ['SCANNING', 'PAUSING']:
            retries = NB_MAX_RETRIES
        else:
            print("bad scanner status: {} (retries left={})".format(scan_status, retries))
            retries -= 1
        time.sleep(SLEEP_RETRY)
        scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id, scan_options=scan_options)
        print("status: {}".format(scan_status))

    if retries == 0:
        print("ERROR: startscan_task/scaninprogress - max_retries ({}) reached.".format(NB_MAX_RETRIES))
        Event.objects.create(message="ERROR: startscan_task/scaninprogress - max_retries ({}) reached.".format(NB_MAX_RETRIES), type="ERROR", severity="ERROR", scan=scan)
        return False

    # Todo: change to wait the report becomes available
    time.sleep(5)  # wait the scan process finish to write the report

    # -4- get the results
    try:
        if scan.engine_type == Engine.objects.filter(name='NESSUS').first():
            scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id, scan_options=scan_options)
            resp = requests.get(url=str(engine_inst.api_url)+"getfindings/"+str(scan.id)+"/"+str(scan.nessscan_id), proxies=PROXIES)
        else:
            resp = requests.get(url=str(engine_inst.api_url) + "getfindings/" + str(scan.id), proxies=PROXIES)
        if resp.status_code != 200 or json.loads(resp.text)['status'] == "error":
            print("Something goes wrong in 'startscan_task/results' (request_status_code={}, engine_error={})", resp.status_code, json.loads(resp.text)['reason'])
            Event.objects.create(message="Something goes wrong in 'startscan_task/results' (request_status_code={}, engine_error={})".format(resp.status_code, json.loads(resp.text)['reason']), type="ERROR", severity="ERROR", scan=scan)
            return False
    except requests.exceptions.RequestException:
        print("Something goes wrong in 'startscan_task/results' (request_status_code={}, engine_status={})", resp.status_code, json.loads(resp.text)['status'])
        Event.objects.create(message="Something goes wrong in 'startscan_task/results' (request_status_code={}, engine_status={})".format(resp.status_code, json.loads(resp.text)['status']), type="ERROR", severity="ERROR", scan=scan)
        return False

    # -5- import the results in DB
    try:
        _import_findings(findings=deepcopy(json.loads(resp.text)['issues']), scan=scan)
    except Exception as e:
        print(e.__doc__)
        print(e.message)
        Event.objects.create(message="Error when importing findings", type="ERROR", severity="ERROR", scan=scan)
        return False

    # -6- get and store the report
    try:
        resp = requests.get(url=str(engine_inst.api_url)+"getreport/"+str(scan.id), stream=True, proxies=PROXIES)
        if resp.status_code == 200:
            user_report_dir = settings.MEDIA_ROOT + "/reports/"+str(params['owner_id'])+"/"
            if not os.path.exists(user_report_dir):
                os.makedirs(user_report_dir)
            fname = str(engine_inst.name) + "_" + str(scan.id) + ".json"
            scan.report_filepath = user_report_dir+str(fname)
            with open(scan.report_filepath, 'wb') as f:
                for chunk in resp:
                    f.write(chunk)
        else:
            scan.status = "error"
            scan.finished_at = timezone.now()
            scan.save()
            print("Something goes wrong in 'startscan_task/getreport' (request_status_code={})", resp.status_code)
            Event.objects.create(message="Something goes wrong in 'startscan_task/getreport' (request_status_code={})".format(resp.status_code), type="ERROR", severity="ERROR", scan=scan)
            return False

    except Exception as e:
        print (e.__doc__)
        print (e.message)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        print("Something goes wrong in 'startscan_task/getreport' (request_status_code={})", resp.status_code)
        Event.objects.create(message="Something goes wrong in 'startscan_task/getreport' (request_status_code={})".format(resp.status_code), type="ERROR", severity="ERROR", scan=scan)
        return False

    scan.status = "finished"
    scan.finished_at = timezone.now()
    scan.save()

    return True


def _get_engine_status(engine):
    engine_status = "undefined"

    try:
        resp = requests.get(url=str(engine.api_url)+"status", verify=False, proxies=PROXIES, timeout=TIMEOUT)

        if resp.status_code == 200:
            engine_status = json.loads(resp.text)['status'].strip().upper()
            engine.set_status(engine_status)
        else:
            engine.set_status("STOPPED")
    except requests.exceptions.RequestException:
        engine.set_status("ERROR")

    engine.save()
    return engine_status


def _get_scan_status(engine, scan_id, scan_options):
    scan_status = "undefined"
    scan = Scan.objects.get(id=scan_id)
    try:
        if scan.engine_type == Engine.objects.filter(name='NESSUS').first():
            resp = requests.post(url=str(engine.api_url) + "status/" + str(scan_id) + "/"
                                    + str(scan.nessscan_id),data=scan_options,
            headers={'Content-type': 'application/json', 'Accept': 'application/json'},
                                 verify=False, proxies=PROXIES,
                                timeout=TIMEOUT)
        else:
            resp = requests.get(url=str(engine.api_url)+"status/"+str(scan_id), verify=False, proxies=PROXIES, timeout=TIMEOUT)
        if resp.status_code == 200:
            scan_status = json.loads(resp.text)['status'].strip().upper()
        else:
            scan_status = "ERROR"
    except requests.exceptions.RequestException:
        scan_status = "ERROR"

    return scan_status


def _create_asset_on_import(asset_value, scan, asset_type='unknown', parent=None):
    Event.objects.create(message="[EngineTasks/_create_asset_on_import()] create: '{}/{} from parent {}'.".format(asset_value, asset_type, parent), type="DEBUG", severity="INFO", scan=scan)

    # create assets if data_type is ip-subnet or ip-range
    if scan and net.is_valid_ip(asset_value):
        assets = scan.assets.filter(type__in=['ip-subnet', 'ip-range'])
        asset_type = "ip"

        # Search parent asset
        parent_asset = None
        for pa in assets:
            if net.is_ip_in_ipset(ip=asset_value, ipset=pa.value):
                parent_asset = pa
                break
        if parent_asset:
            name = asset_value
            criticity = parent_asset.criticity
            owner = parent_asset.owner
        else:
            name = asset_value
            criticity = 'medium'
            owner = get_user_model().objects.filter(username='admin').first()
    else:
        if net.is_valid_ip(asset_value):
            asset_type = "ip"
        elif net._is_valid_domain(asset_value):
            asset_type = "domain"
        elif net._is_valid_url(asset_value):
            asset_type = "url"
        else:
            asset_type = "keyword"  # default :/
        name = asset_value
        criticity = 'medium'
        owner = get_user_model().objects.filter(username='admin').first()

    # Create the new asset ...
    asset_args = {
        'value': asset_value,
        'name': name,
        'type': asset_type,
        'criticity': criticity,
        'description': "Asset dynamically created",
        'owner': owner
    }
    asset = Asset(**asset_args)
    asset.save()
    # Add Type as Tag
    new_tag = _add_asset_tags(asset, asset_type)
    asset.categories.add(new_tag)
    asset.save()
    scan.assets.add(asset)

    # Then add the asset to every related asset groups
    for ag in AssetGroup.objects.filter(assets__type__in=['ip-subnet', 'ip-range']):
        for aga in ag.assets.all():
            if net.is_ip_in_ipset(ip=asset_value, ipset=aga.value):
                ag.assets.add(asset)
                ag.save()
                ag.calc_risk_grade()
                ag.save()

    # Creation/Update of the AssetGroup
    if parent is not None:
        Event.objects.create(message="[EngineTasks/_create_asset_on_import()] Looking for a group named : {}".format(parent), type="DEBUG", severity="INFO", scan=scan)
        asset_group = AssetGroup.objects.filter(name="{} assets".format(parent)).first()
        if asset_group is None:   # Create an asset group dynamically
            Event.objects.create(message="[EngineTasks/_create_asset_on_import()] Create a group named : {}".format(parent), type="DEBUG", severity="INFO", scan=scan)
            assetgroup_args = {
               'name': "{} assets".format(parent),
               'criticity': criticity,
               'description': "AssetGroup dynamically created",
               'owner': owner
            }
            asset_group = AssetGroup(**assetgroup_args)
            asset_group.save()

        Event.objects.create(message="[EngineTasks/_create_asset_on_import()] Add {} in group {}".format(asset, parent), type="DEBUG", severity="INFO", scan=scan)
        # Add the asset to the new group
        asset_group.assets.add(asset)
        asset_group.save()

        # Caculate the risk grade
        asset_group.calc_risk_grade()
        asset_group.save()

    return asset


def _import_findings_save(findings, scan, engine_name=None, engine_id=None, owner_id=None):

    scan_id = None
    if scan:
        Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] Importing findings for scan '{}'.".format(scan.id, scan.title), type="DEBUG", severity="INFO", scan=scan)
        scan_id = scan.id
    else:
        Event.objects.create(message="[EngineTasks/_import_findings()/direct] Importing findings manually.", type="DEBUG", severity="INFO")
        scan_id = 0

    scopes = scan.engine_policy.scopes.all()
    fid = 0
    for finding in findings:
        fid += 1
        # get the hostnames received and check if they are known in the user' assets
        assets = []

        for addr in list(finding['target']['addr']):
            asset = Asset.objects.filter(value=addr).first()
            if asset is None:  # asset unknown by the manager
                if "parent" not in finding["target"]:
                    finding["target"]["parent"] = None
                asset = _create_asset_on_import(asset_value=addr, scan=scan, parent=finding["target"]["parent"])
            if asset:
                assets.append(asset)
            if asset and not scan.assets.filter(value=asset.value):
                scan.assets.add(asset)

        # Prepare metadata fields
        risk_info = {}
        vuln_refs = {}
        links = []
        tags = []
        if 'metadata' in finding.keys():
            if 'risk' in finding['metadata'].keys():
                risk_info = finding['metadata']['risk']
            if 'vuln_refs' in finding['metadata'].keys():
                vuln_refs = finding['metadata']['vuln_refs']
            if 'links' in finding['metadata'].keys():
                links = finding['metadata']['links']
            if 'tags' in finding['metadata'].keys():
                tags = finding['metadata']['tags']

        # Update default values for risk.cvss_base_score and risk.vuln_publication_date if not set
        if 'cvss_base_score' not in risk_info.keys():
            cvss_base_score = 0.0
            if finding['severity'] == 'critical':
                cvss_base_score = 9.0
            if finding['severity'] == "high":
                cvss_base_score = 7.5
            if finding['severity'] == "medium":
                cvss_base_score = 5.0
            if finding['severity'] == "low":
                cvss_base_score = 4.0
            risk_info.update({"cvss_base_score": cvss_base_score})
        else:
            # Ensure it's a float
            risk_info.update({"cvss_base_score": float(risk_info["cvss_base_score"])})
        if 'vuln_publication_date' not in risk_info.keys():
            risk_info.update({"vuln_publication_date": datetime.datetime.today().strftime('%Y/%m/%d')})

        raw_data = {}
        if 'raw' in finding.keys():
            raw_data = finding['raw']

        for asset in assets:
            # Store finding in the RawFinding table
            new_raw_finding = RawFinding.objects.create(
                asset       = asset,
                asset_name  = asset.value,
                scan        = scan,
                owner       = scan.owner,
                title       = finding['title'],
                type        = finding['type'],
                confidence  = finding['confidence'],
                severity    = finding['severity'],
                description = finding['description'],
                solution    = finding['solution'],
                status      = "new",
                engine_type = scan.engine_type.name,
                risk_info   = risk_info,
                vuln_refs   = vuln_refs,
                links       = links,
                tags        = tags,
                raw_data    = raw_data
                #found_at = ???
            )
            new_raw_finding.save()

            # Add the engine policy scopes
            for scope in scopes:
                new_raw_finding.scopes.add(scope.id)
            new_raw_finding.save()

            # Check if this finding is new
            f = Finding.objects.filter(asset=asset, title=finding['title']).only('checked_at', 'status').first()

            if f:
                # A similar finding was alreaddy created
                f.checked_at = timezone.now()
                if f.status in ['patched', 'closed']:
                    f.status = "undone"
                f.save()
                new_raw_finding.status = f.status
                new_raw_finding.save()
            else:
                # Create a new finding:
                # Raise an alert
                new_finding_alert(new_raw_finding.id, new_raw_finding.severity)

                # Create an event if logging level OK
                Event.objects.create(
                    message="[EngineTasks/_import_findings()/scan_id={}] New finding: {}".format(scan_id, finding['title']),
                    description="Asset: {}\nFinding: {}".format(asset.value, finding['title']),
                    type="DEBUG", severity="INFO", scan=scan)
                new_finding = Finding.objects.create(
                    raw_finding = new_raw_finding,
                    asset       = asset,
                    asset_name  = asset.value,
                    scan        = scan,
                    owner       = scan.owner,
                    title       = finding['title'],
                    type        = finding['type'],
                    confidence  = finding['confidence'],
                    severity    = finding['severity'],
                    description = finding['description'],
                    solution    = finding['solution'],
                    status      = "new",
                    engine_type = scan.engine_type.name,
                    risk_info   = risk_info,
                    vuln_refs   = vuln_refs,
                    links       = links,
                    tags        = tags,
                    raw_data    = raw_data
                )
                new_finding.save()

                # Add the engine policy scopes
                for scope in scopes:
                    new_finding.scopes.add(scope.id)
                new_finding.save()

                # Evaluate alerting rules
                try:
                    new_finding.evaluate_alert_rules(trigger='auto')
                except Exception as e:
                    Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] Error in alerting".format(scan_id),
                        type="ERROR", severity="ERROR", scan=scan, description=str(e))

    scan.save()
    scan.update_sumary()

    # Search missing findings

    # Reevaluate the risk level of the asset on new risk
    for a in scan.assets.all():
        a.calc_risk_grade(update_groups=True)

    # @Todo: Revaluate the risk level of all asset groups

    scan.save()
    Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] Findings imported.".format(scan_id), type="INFO", severity="INFO", scan=scan)
    return True


def _import_findings(findings, scan, engine_name=None, engine_id=None, owner_id=None):
    """
    Import findings into scan.

    It includes:
    - Create new asset if any
    - Create a RawFinding
    - Create ou update a Finding (if new or has changes)
    - Create an alert if a neww or a missing finding is found
    - Update asset score and scan summary
    """
    scan_id = None
    if scan:
        Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] Importing findings for scan '{}'.".format(scan.id, scan.title), type="DEBUG", severity="INFO", scan=scan)
        scan_id = scan.id
    else:
        Event.objects.create(message="[EngineTasks/_import_findings()/direct] Importing findings manually.", type="DEBUG", severity="INFO")
        scan_id = 0

    # Initialize scan_scopes
    scan_scopes = scan.engine_policy.scopes.all()

    # Initilize the array containing same findings
    known_findings_list = []

    for finding in findings:
        # get the hostnames received and check if they are known in the user' assets
        assets = []

        #Add new domains discovered from owl_dns engine
        if scan.engine_type == Engine.objects.filter(name='OWL_DNS').first():
            if "Subdomain found" in finding['title']:
                subdomain=finding['title'].split(": ",1)[1]
                domain = Asset.objects.filter(value=subdomain).first()
                if domain is None:  # asset unknown by the manager
                    if "parent" not in finding["target"]:
                        finding["target"]["parent"] = None
                    asset = _create_asset_on_import(asset_value=subdomain, scan=scan, parent=finding["target"]["parent"])
                    if asset:
                        assets.append(asset)
                    if asset and not scan.assets.filter(value=asset.value):
                        scan.assets.add(asset)



        for addr in list(finding['target']['addr']):
            asset = Asset.objects.filter(value=addr).first()
            if asset is None:  # asset unknown by the manager
                if "parent" not in finding["target"]:
                    finding["target"]["parent"] = None
                asset = _create_asset_on_import(asset_value=addr, scan=scan, parent=finding["target"]["parent"])
            if asset:
                assets.append(asset)
            if asset and not scan.assets.filter(value=asset.value):
                scan.assets.add(asset)

        # Prepare metadata fields
        risk_info = {}
        vuln_refs = {}
        links = []
        tags = []
        if 'metadata' in finding.keys():
            if 'risk' in finding['metadata'].keys():
                risk_info = finding['metadata']['risk']
            if 'vuln_refs' in finding['metadata'].keys():
                vuln_refs = finding['metadata']['vuln_refs']
            if 'links' in finding['metadata'].keys():
                links = finding['metadata']['links']
            if 'tags' in finding['metadata'].keys():
                tags = finding['metadata']['tags']

        # Update default values for risk.cvss_base_score and risk.vuln_publication_date if not set
        if 'cvss_base_score' not in risk_info.keys():
            cvss_base_score = 0.0
            if finding['severity'] == 'critical':
                cvss_base_score = 9.0
            if finding['severity'] == "high":
                cvss_base_score = 7.5
            if finding['severity'] == "medium":
                cvss_base_score = 5.0
            if finding['severity'] == "low":
                cvss_base_score = 4.0
            risk_info.update({"cvss_base_score": cvss_base_score})
        else:
            # ensure it's a float
            risk_info.update({"cvss_base_score": float(risk_info["cvss_base_score"])})
        if 'vuln_publication_date' not in risk_info.keys():
            risk_info.update({"vuln_publication_date": datetime.datetime.today().strftime('%Y/%m/%d')})

        raw_data = {}
        if 'raw' in finding.keys():
            raw_data = finding['raw']

        for asset in assets:
            # Store finding in the RawFinding table
            new_raw_finding = RawFinding.objects.create(
                asset       = asset,
                asset_name  = asset.value,
                scan        = scan,
                owner       = scan.owner,
                title       = finding['title'],
                type        = finding['type'],
                confidence  = finding['confidence'],
                severity    = finding['severity'],
                description = finding['description'],
                solution    = finding['solution'],
                status      = "new",
                engine_type = scan.engine_type.name,
                risk_info   = risk_info,
                vuln_refs   = vuln_refs,
                links       = links,
                tags        = tags,
                raw_data    = raw_data
            )
            new_raw_finding.save()

            # Add the engine policy scopes
            for scope in scan_scopes:
                new_raw_finding.scopes.add(scope.id)
            new_raw_finding.save()

            # Check if this finding is new (don't already exists)
            f = Finding.objects.filter(asset=asset, title=finding['title']).only('checked_at', 'status').first()

            if f:
                # We already see you
                f.checked_at = timezone.now()
                if f.status in ['patched', 'closed']:
                    f.status = "undone"
                f.save()
                new_raw_finding.status = f.status
                new_raw_finding.save()

                known_findings_list.append(new_raw_finding.hash)
            else:
                # Raise an alert
                new_finding_alert(new_raw_finding.id, new_raw_finding.severity)

                # Vtasio Add Tags
                if 'is running on port' in finding['title']:
                    service = re.findall(r"'(.*?)'", finding['title'])
                    new_tag = _add_asset_tags(asset,service[0])
                    Event.objects.create(
                        message="[EngineTasks/_import_findings()/scan_id={}] New Tag: {}".format(scan_id,
                                                                                                     service[0]),
                        description="Asset: {}\nFinding: {}".format(asset.value, finding['title']),
                        type="DEBUG", severity="INFO", scan=scan)
                    asset.categories.add(new_tag)
                    asset.save()

                # Create an event if logging level OK
                Event.objects.create(
                    message="[EngineTasks/_import_findings()/scan_id={}] New finding: {}".format(scan_id, finding['title']),
                    description="Asset: {}\nFinding: {}".format(asset.value, finding['title']),
                    type="DEBUG", severity="INFO", scan=scan)
                new_finding = Finding.objects.create(
                    raw_finding = new_raw_finding,
                    asset       = asset,
                    asset_name  = asset.value,
                    scan        = scan,
                    owner       = scan.owner,
                    title       = finding['title'],
                    type        = finding['type'],
                    confidence  = finding['confidence'],
                    severity    = finding['severity'],
                    description = finding['description'],
                    solution    = finding['solution'],
                    status      = "new",
                    engine_type = scan.engine_type.name,
                    risk_info   = risk_info,
                    vuln_refs   = vuln_refs,
                    links       = links,
                    tags        = tags,
                    raw_data    = raw_data
                )
                new_finding.save()

                # Add the engine policy scopes
                for scope in scan_scopes:
                    new_finding.scopes.add(scope.id)
                new_finding.save()

                # Evaluate alerting rules
                try:
                    new_finding.evaluate_alert_rules(trigger='auto')
                except Exception as e:
                    Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] Error in alerting".format(scan_id),
                        type="ERROR", severity="ERROR", scan=scan, description=str(e))
    scan.save()
    scan.update_sumary()

    # Reevaluate the risk level of the asset on new risk
    for a in scan.assets.all():
        a.calc_risk_grade(update_groups=True)

    # Search missing findings
    # - check if a previous scan exists
    last_scan = scan.scan_definition.scan_set.exclude(id=scan.id).order_by('-id').first()
    if last_scan is not None:
        # Loop in missing findings
        for mf in last_scan.rawfinding_set.exclude(hash__in=known_findings_list):
            missing_finding_alert(mf.id, scan.id, mf.severity)

    # @Todo: Revaluate the risk level of all asset groups

    scan.save()
    Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] Findings imported.".format(scan_id), type="INFO", severity="INFO", scan=scan)
    return True
