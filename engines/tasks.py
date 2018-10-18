from __future__ import absolute_import
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from celery import shared_task
from celery.task.control import revoke
from .models import EngineInstance, Engine, EnginePolicyScope, EnginePolicy
from findings.models import Finding, RawFinding
from assets.models import Asset, AssetGroup
from scans.models import Scan, ScanDefinition
from events.models import Event
from common.utils import net
import requests, json, time, datetime, random, uuid, hashlib, re, os
from copy import deepcopy

NB_MAX_RETRIES = 5
SLEEP_RETRY = 5
PROXIES = settings.PROXIES

@shared_task(bind=True)
def refresh_engines_status_task(self):
    print ("task: starting refresh_engines_status_task !")
    for engine in EngineInstance.objects.filter(enabled=True):
        try:
            resp = requests.get(url=str(engine.api_url)+"status", verify=False, timeout=5, proxies=PROXIES)

            if resp.status_code == 200:
                engine.status = json.loads(resp.text)['status'].strip().upper()
            else:
                engine.status = "ERROR"
        except requests.exceptions.RequestException:
            engine.status = "ERROR"

        engine.save()

    return True


@shared_task(bind=True)
def importfindings_task(self, report_filename, owner_id, engine, min_level):
    Event.objects.create(message="[EngineTasks/importfindings_task/{}] Task started with engine {}.".format(self.request.id, engine),
                 type="INFO", severity="INFO")

    level_to_value = {'info': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
    value_to_level = {v: k for k, v in level_to_value.iteritems()}

    min_level = level_to_value.get(min_level, 0)

    if engine == 'nessus':

        summary = {"info": 0, "medium": 0, "missing": 0, "high": 0, "critical": 0, "low": 0, "new": 0, "total": 0}

        Event.objects.create(message='[EngineTasks/importfindings_task()] engine: nessus', type="INFO", severity="INFO")
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
                                    type="DEBUG", severity="INFO",
                                    scan=scan,
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
                                                "tags": list()
                                            },
                                            "title": report_item.attrib['pluginName'],
                                            "type": "Vuln",
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
                                        finding['metadata']['vuln_refs']['cve'] = param.text
                                    if param.tag == 'bid':
                                        finding['metadata']['vuln_refs']['bid'] = param.text
                                    if param.tag == 'xref':
                                        finding['metadata']['vuln_refs'][param.text.split(':')[0]] = param.text.split(':')[1]
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
                                       owner=User.objects.filter(id=owner_id).first(),
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
            #print (e.__doc__)
            #print (e.message)
            return False

    return True


@shared_task(bind=True)
def stopscan_task(self, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    Event.objects.create(message="[EngineTasks/stopscan_task/{}] Task started.".format(self.request.id),
                 type="INFO", severity="INFO", scan=scan)

    revoke(str(scan.task_id), terminate=True)

    engine = scan.engine
    resp = None
    try:
        resp = requests.get(url=str(engine.api_url)+"stop/"+str(scan_id), verify=False, proxies=PROXIES)
        if resp.status_code != 200 or json.loads(resp.text)['status'] == "error":
            scan.status = "error"
            scan.finished_at = timezone.now()
            scan.save()
            # print("ERROR: something goes wrong in 'stopscan_task' (request_status_code={}, engine_error={})",
            #        resp.status_code, json.loads(resp.text)['reason'])
            Event.objects.create(message="[EngineTasks/stopscan_task/{}] Error when stopping scan.".format(self.request.id),
                         type="ERROR", severity="ERROR", scan=scan)
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


@shared_task(bind=True)
def startscan_task(self, params):
    scan = Scan.objects.get(id=params['scan_params']['scan_id'])
    scan.status = "started"
    scan.started_at = timezone.now()
    scan.save()

    Event.objects.create(message="[EngineTasks/startscan_task/{}] Task started.".format(self.request.id),
                 type="INFO", severity="INFO", scan=scan)

    engine_inst = None
    # -0- select an engine instance
    if scan.scan_definition.engine is None:
        engine_inst = random.choice(EngineInstance.objects.filter(
            engine__name=str(scan.scan_definition.engine_type.name).upper(), status="READY", enabled=True))
    else:
        engine_inst = scan.scan_definition.engine
        if engine_inst.status != "READY" or engine_inst.enabled == False:
            Event.objects.create(message="[EngineTasks/startscan_task/{}] BeforeScan - Engine '{}' not available (status: {}, enabled: {}). Task aborted.".format(self.request.id, engine_inst.name, engine_inst.status, engine_inst.enabled), type="ERROR", severity="ERROR", scan=scan)
            engine_inst = None

    # check if the selected engine instance is available
    if not engine_inst:
        Event.objects.create(message="[EngineTasks/startscan_task/{}] BeforeScan - No engine '{}' available. Task aborted.".format(self.request.id, params['engine_name']), type="ERROR", severity="ERROR", scan=scan)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        return False


    Event.objects.create(message="[EngineTasks/startscan_task/{}] Engine '{}' has been selected.".format(self.request.id, engine_inst.name),
                 type="INFO", severity="INFO", scan=scan)
    scan.engine = engine_inst
    scan.save()

    # -1- wait the engine come available for accepting scans (status=ready)
    retries = NB_MAX_RETRIES
    while _get_engine_status(engine=engine_inst) != "READY" and retries > 0:
        print("--waiting scanner ready: {}".format(_get_engine_status(engine=engine_inst)))
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
    try:
        resp = requests.post(
            url=str(engine_inst.api_url)+"startscan",
            data=json.dumps(params['scan_params']),
            headers = {'Content-type': 'application/json', 'Accept': 'application/json'},
            proxies=PROXIES)

        if resp.status_code != 200 or json.loads(resp.text)['status'] != "accepted":
            scan.status = "error"
            scan.finished_at = timezone.now()
            scan.save()
            Event.objects.create(message="[EngineTasks/startscan_task/{}] DuringScan - something goes wrong (request_status_code={}). Task aborted.".format(self.request.id, resp.status_code),
                         description=str(resp.text), type="ERROR", severity="ERROR", scan=scan)
            return False
    except requests.exceptions.RequestException:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        Event.objects.create(message="[EngineTasks/startscan_task/{}] DuringScan - something goes wrong (request_status_code={}). Task aborted.".format(self.request.id, resp.status_code),
                     description=json.loads(resp.text)['status'], type="ERROR", severity="ERROR", scan=scan)
        return False


    # -3- wait the engine come available for accepting scans (status=ready)
    retries = NB_MAX_RETRIES # test value
    scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id)
    #print("scan status before insane looping: {}".format(scan_status))

    while not scan_status in ['FINISHED', 'READY'] and retries > 0:
        #print "## scan_status:", scan_status
        if scan_status in ['STARTED', 'SCANNING', 'PAUSING', 'STOPING']:
            retries = NB_MAX_RETRIES
        else:
            Event.objects.create(message="[EngineTasks/startscan_task/{}] DuringScan - bad scanner status: {} (retries left={}).".format(self.request.id, scan_status, retries),
                type="ERROR", severity="ERROR", scan=scan)
            retries -= 1
        time.sleep(SLEEP_RETRY)
        scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id)
        print("scan status (in loop): {}".format(scan_status))

    if retries == 0:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        #print("ERROR: startscan_task/scaninprogress - max_retries ({}) reached.".format(retries))
        Event.objects.create(message="[EngineTasks/startscan_task/{}] DuringScan - max_retries ({}) reached. Task aborted.".format(self.request.id, retries),
            type="ERROR", severity="ERROR", scan=scan)
        return False

    Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - scan report is now available: {}.".format(self.request.id, str(engine_inst.api_url)+"getreport/"+str(scan.id)),
                         type="DEBUG", severity="INFO", scan=scan)
    Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - findings are now available: {}.".format(self.request.id, str(engine_inst.api_url)+"getfindings/"+str(scan.id)),
                         type="DEBUG", severity="INFO", scan=scan)


    #Todo: change to wait the report becomes available
    time.sleep(5) # wait the scan process finish to write the report

    # -4- get the results (findings)
    try:
        resp = requests.get(url=str(engine_inst.api_url)+"getfindings/"+str(scan.id), proxies=PROXIES)#, data=params['scan_params'])
        if resp.status_code != 200 or json.loads(resp.text)['status'] == "error":
            scan.status = "error"
            scan.finished_at = timezone.now()
            scan.save()
            Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in 'getfindings' call (request_status_code={}, engine_error={}). Task aborted.".format(self.request.id, resp.status_code, json.loads(resp.text)['reason']),
                type="ERROR", severity="ERROR", scan=scan)
            return False
    except:
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in 'getfindings' call (request_status_code={}). Task aborted.".format(self.request.id, resp.status_code),
            type="ERROR", severity="ERROR", scan=scan)
        return False


    # -5- import the results in DB
    try:
        _import_findings(findings=deepcopy(json.loads(resp.text)['issues']), scan=scan)

    except Exception as e:
        Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in '_import_findings' call. Task aborted.".format(self.request.id), description="{}".format(e.message),
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
        print (e.message)
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


@shared_task(bind=True)
def start_periodic_scan_task(self, params):
    Event.objects.create(message="[EngineTasks/start_periodic_scan_task/{}] Task started.".format(self.request.id),
                 type="INFO", severity="INFO", scan=scan)

    scan_def = ScanDefinition.objects.get(id=params['scan_definition_id'])
    engine_inst = None
    # select an instance of the scanner
    if scan_def.engine: #dedicated scanner
        engine_inst = scan_def.engine
        if engine_inst.status != "READY" or engine_inst.enabled is False:
            Event.objects.create(message="[EngineTasks/start_periodic_scan_task/{}] BeforeScan - Engine '{}' not available (status: {}, enabled: {}). Task aborted.".format(self.request.id, engine_inst.name, engine_inst.status, engine_inst.enabled), type="ERROR", severity="ERROR", scan=scan_def)
            engine_inst = None
    else:
        engine_inst = random.choice(EngineInstance.objects.filter(engine__name=scan_def.engine_type.name, status="READY", enabled=True))

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

    # check if the selected engine instance is available
    if not engine_inst:
        print("ERROR: startscan_task/select_instance: not engine '{}' available".format(params['engine_name']))
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
    scan.save()

    params['scan_params']['scan_id'] = str(scan.id)

    # -1- wait the engine come available for accepting scans (status=ready)
    retries = NB_MAX_RETRIES
    while _get_engine_status(engine=engine_inst) != "READY" and retries > 0:
        print("--waiting scanner ready: {}".format(_get_engine_status(engine=engine_inst)))
        time.sleep(1)
        retries -= 1

    if retries == 0:
        print("ERROR: start_periodicscan_task/beforescan - max_retries ({}) reached.".format(retries))
        return False

    # -2- call the engin REST API /start
    try:
        resp = requests.post(
            url=str(engine_inst.api_url)+"startscan",
            data=json.dumps(params['scan_params']),
            headers={
                'Content-type': 'application/json',
                'Accept': 'application/json'},
            proxies=PROXIES)
        if resp.status_code != 200 or json.loads(resp.text)['status'] != "accepted":
            print("something goes wrong in 'startscan_task/scan' (request_status_code={}, scan_response={})",
                  resp.status_code, str(resp.text))
            return False
    except requests.exceptions.RequestException:
        print("something goes wrong in 'startscan_task/scan' (request_status_code={}, engine_status={})",
              resp.status_code, json.loads(resp.text)['status'])
        return False

    # -3- wait the engine come available for accepting scans (status=ready)
    retries = NB_MAX_RETRIES  # test value
    scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id)
    print("status: {}".format(scan_status))

    while not scan_status in ['READY', 'FINISHED'] and retries > 0:
        if scan_status in ['SCANNING', 'PAUSING']:
            retries = NB_MAX_RETRIES
        else:
            print("bad scanner status: {} (retries left={})".format(scan_status, retries))
            retries -= 1
        #print("--waiting scan finished: {}".format(_get_engine_status(params)))
        time.sleep(SLEEP_RETRY)
        scan_status = _get_scan_status(engine=engine_inst, scan_id=scan.id)
        print("status: {}".format(scan_status))

    if retries == 0:
        print("ERROR: startscan_task/scaninprogress - max_retries ({}) reached.".format(retries))
        return False

    print("@@@@@@@ The scan report is now available: {}".format(str(engine_inst.api_url)+"getreport/"+str(scan.id)))
    print("@@@@@@@ The findings are now available: {}".format(str(engine_inst.api_url)+"getfindings/"+str(scan.id)))

    #Todo: change to wait the report becomes available
    time.sleep(5) # wait the scan process finish to write the report


    # -4- get the results
    try:
        resp = requests.get(url=str(engine_inst.api_url)+"getfindings/"+str(scan.id), proxies=PROXIES)#, data=params['scan_params'])
        if resp.status_code != 200 or json.loads(resp.text)['status'] == "error":
            print("something goes wrong in 'startscan_task/results' (request_status_code={}, engine_error={})",
                   resp.status_code, json.loads(resp.text)['reason'])
            return False
    except requests.exceptions.RequestException:
        print("something goes wrong in 'startscan_task/results' (request_status_code={}, engine_status={})",
              resp.status_code, json.loads(resp.text)['status'])
        return False


    # -5- import the results in DB
    try:
        _import_findings(findings=deepcopy(json.loads(resp.text)['issues']), scan=scan)
    except Exception as e:
        print (e.__doc__)
        print (e.message)
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
            print("something goes wrong in 'startscan_task/getreport' (request_status_code={}", resp.status_code)
            return False

    except Exception as e:
        print (e.__doc__)
        print (e.message)
        scan.status = "error"
        scan.finished_at = timezone.now()
        scan.save()
        print("something goes wrong in 'startscan_task/getreport' (request_status_code={})",
              resp.status_code)
        return False

    scan.status = "finished"
    scan.finished_at = timezone.now()
    scan.save()

    return True


def _get_engine_status(engine):
    #print("I'm inside the _get_engine_status with args '{}'".format(engine))

    engine_status = "undefined"

    try:
        resp = requests.get(url=str(engine.api_url)+"status", verify=False, proxies=PROXIES)

        if resp.status_code == 200:
            engine_status = json.loads(resp.text)['status'].strip().upper()
            engine.set_status(engine_status)
        else:
            engine.set_status("STOPPED")
    except requests.exceptions.RequestException:
        engine.set_status("ERROR")

    engine.save()
    return engine_status


def _get_scan_status(engine, scan_id):
    #print("I'm inside the _get_scan_status with args 'engine={}, scan_id={}'".format(engine, scan_id))
    scan_status = "undefined"

    try:
        resp = requests.get(url=str(engine.api_url)+"status/"+str(scan_id), verify=False, proxies=PROXIES)
        if resp.status_code == 200:
            scan_status = json.loads(resp.text)['status'].strip().upper()
        else:
            scan_status = "ERROR"
    except requests.exceptions.RequestException:
        scan_status = "ERROR"

    return scan_status


def _create_asset_on_import(asset_value, scan, asset_type = 'unknown'):
    Event.objects.create(message="[EngineTasks/_create_asset_on_import()] create: '{}/{}'.".format(asset_value, asset_type), type="DEBUG", severity="INFO", scan=scan)

    # create assets if data_type is ip-subnet or ip-range
    if scan and asset_type == 'ip':
        assets = scan.assets.filter(type__in=['ip-subnet', 'ip-range'])

        # Search parent asset
        parent_asset = None
        for pa in assets:
            if net.is_ip_in_ipset(ip=asset_value, ipset=pa.value):
                parent_asset = pa
                break
        if parent_asset:
            name = "{} (from '{}')".format(asset_value, parent_asset.name)
            criticity = parent_asset.criticity
            owner = parent_asset.owner
        else:
            name = asset_value
            criticity = 'medium'
            owner = User.objects.filter(username='admin').first()
    else:
        if net.is_valid_ip(asset_value):
            asset_type = "ip"
        elif net._is_valid_domain(asset_value):
            asset_type = "domain"
        elif net._is_valid_url(asset_value):
            asset_type = "url"
        else:
            asset_type = "fqdn"  # default :/
        name = asset_value
        criticity = 'medium'
        owner = User.objects.filter(username='admin').first()

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
    scan.assets.add(asset)

    # Then add the asset to every related asset groups
    for ag in AssetGroup.objects.filter(assets__type__in=['ip-subnet', 'ip-range']):
        for aga in ag.assets.all():
            if net.is_ip_in_ipset(ip=asset_value, ipset=aga.value):
                ag.assets.add(asset)
                ag.save()
                ag.calc_risk_grade()
                ag.save()

    return asset


def _import_findings(findings, scan, engine_name=None, engine_id=None, owner_id=None):
    scan_id = None
    if scan:
        Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] Importing findings for scan '{}'.".format(scan.id, scan.title), type="DEBUG", severity="INFO", scan=scan)
        scan_id = scan.id
    else:
        Event.objects.create(message="[EngineTasks/_import_findings()/direct] Importing findings manually.", type="DEBUG", severity="INFO")
        scan_id = 0

    for finding in findings:
        # get the hostnames received and check if they are known in the user' assets
        assets = []

        for addr in list(finding['target']['addr']):
            asset = Asset.objects.filter(value=addr).first()
            if asset is None:  # asset unknown by the manager
                asset = _create_asset_on_import(asset_value=addr, scan=scan)
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
            # update scan_summary
            # scan_summary.update({
            #     "total": scan_summary['total'] + 1,
            #     finding['severity']: scan_summary[finding['severity']] + 1
            # })

            # store finding in the RawFinding table
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
            for scope in scan.engine_policy.scopes.all():
                new_raw_finding.scopes.add(EnginePolicyScope.objects.get(id=scope.id))
            new_raw_finding.save()

            # check if this finding is new
            f = Finding.objects.filter(
                hash=hashlib.sha1(str(asset.value)+str(finding['title'])).hexdigest()).first()

            if f:
                f.checked_at = timezone.now()
                f.save()
            else:
                # create a new asset:
                #print "#########NEW:", new_raw_finding.title
                Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] New finding: {}".format(scan_id, new_raw_finding.title), type="DEBUG", severity="INFO", scan=scan)
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
                for scope in scan.engine_policy.scopes.all():
                    new_finding.scopes.add(EnginePolicyScope.objects.get(id=scope.id))
                new_finding.save()

                # reevaluate the risk level of the asset on new risk
                asset.evaluate_risk()
                asset.calc_risk_grade()
                new_finding.evaluate_alert_rules(trigger='auto')

    scan.save()
    scan.update_sumary()
    scan.save()
    #print("All findings are now imported")
    Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}] Findings imported.".format(scan_id), type="DEBUG", severity="INFO", scan=scan)
    return True
