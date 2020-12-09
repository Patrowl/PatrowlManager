from django.conf import settings
from django.utils import timezone
from django.contrib.auth import get_user_model
from celery import shared_task, chord, group
from .models import EngineInstance
from assets.models import Asset, AssetGroup, AssetCategory
from events.models import Event
from events.utils import new_finding_alert, missing_finding_alert
from findings.models import Finding, RawFinding
from scans.models import ScanJob, Scan
from common.utils import chunked_queryset
from common.utils import net
from assets.apis import _add_asset_tags
import json
import random
import requests
import time
import datetime
import uuid
from copy import deepcopy
import re
# import logging
# logger = logging.getLogger(__name__)

HTTP_REQUEST_MAX_TIMEOUT=getattr(settings, 'HTTP_REQUEST_MAX_TIMEOUT', 60)
SCAN_JOB_DEFAULT_TIMEOUT=getattr(settings, 'SCAN_JOB_DEFAULT_TIMEOUT', 7200)
SCAN_JOB_DEFAULT_SPLIT_ASSETS=getattr(settings, 'SCAN_JOB_DEFAULT_SPLIT_ASSETS', 100)
NB_MAX_RETRIES=5


def _get_engine_status(engine):
    engine_status = "undefined"

    try:
        resp = requests.get(url=str(engine.api_url)+"status", verify=False, proxies=settings.PROXIES, timeout=HTTP_REQUEST_MAX_TIMEOUT)

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
    scan_status = "undefined"

    try:
        resp = requests.get(url=str(engine.api_url)+"status/"+str(scan_id), verify=False, proxies=settings.PROXIES, timeout=HTTP_REQUEST_MAX_TIMEOUT)
        if resp.status_code == 200:
            scan_status = json.loads(resp.text)['status'].strip().upper()
        else:
            scan_status = "ERROR"
    except requests.exceptions.RequestException:
        scan_status = "ERROR"

    return scan_status


def _run_scan(evt_prefix, scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Exception:
        return False
    scan.update_status('started', 'started_at')

    # Sync the asset lists
    assets_list = []
    for asset in scan.scan_definition.assets_list.all():
        if not scan.assets.filter(id=asset.id).exists():
            scan.assets.add(asset)

    # Append assets related to the asset groups
    for assetgroup in scan.scan_definition.assetgroups_list.all():
        for a in assetgroup.assets.all():
            if not scan.assets.filter(id=a.id).exists():
                scan.assets.add(a)

    # Check if the assets list is not empty
    if scan.assets.count() == 0:
        Event.objects.create(message=f"{evt_prefix} BeforeScan - No assets set. Task aborted.", type="ERROR", severity="ERROR", scan=scan)
        scan.update_status('error', 'finished_at')
        return False

    # Check if the engine policy complies with the asset types
    allowed_asset_types = eval(scan.engine_type.allowed_asset_types)
    has_error = False
    for asset in assets_list:
        if asset['datatype'] not in allowed_asset_types:
            has_error = True
            Event.objects.create(message="{} BeforeScan - Asset '{}' has type '{}' unsupported by the engine policy ('{}'). Task aborted.".format(evt_prefix, asset["value"], asset["datatype"], ", ".join(allowed_asset_types)), type="ERROR", severity="ERROR", scan=scan)

    if has_error is True:
        scan.update_status('error', 'finished_at')
        return False

    # Split assets in chunks
    # - Priorities:
    #   * Scan options
    #   * Engine policy option
    #   * Application default setting (SCAN_JOB_DEFAULT_SPLIT_ASSETS)
    assets_chunk_size = SCAN_JOB_DEFAULT_SPLIT_ASSETS
    if 'split_assets_by' in scan.scan_definition.engine_policy.options.keys():
        sab = scan.scan_definition.engine_policy.options['split_assets_by']
        if sab not in ['', None] and sab.isnumeric():
            assets_chunk_size = int(sab)
    try:
        jobs_sig = []
        position = 1

        for ac in chunked_queryset(scan.assets.all(), assets_chunk_size):
            # jobs_sig.append(_run_scan_job.s(evt_prefix, scan_id, [a.id for a in ac], position).set(queue='scan').set(ignore_result=True))
            jobs_sig.append(_run_scan_job.s(evt_prefix, scan_id, [a.id for a in ac], position).set(queue='scan'))
            position += 1
        # Run all scan jobs
        jobs = (
            group(jobs_sig) | _finish_scan.si(evt_prefix, scan_id).set(queue='scan')
        )()

    except Exception as e:
        print(e)

    return True


@shared_task(bind=True, ignore_result=False)
def _finish_scan(self, evt_prefix, scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Exception as e:
        print(e)
        return False
    Event.objects.create(message="{} AfterScan - scan finishing.".format(evt_prefix), type="DEBUG", severity="INFO", scan=scan)

    # Check if error hase been raised
    has_errors = False
    for scan_job in scan.scanjob_set.all():
        if scan_job.status != 'finished':
            has_errors = True

    if has_errors:
        scan.update_status('error', 'finished_at')
    else:
        scan.update_status('finished', 'finished_at')

    Event.objects.create(message="{} AfterScan - scan finished at: {}.".format(evt_prefix, scan.finished_at), type="DEBUG", severity="INFO", scan=scan)
    return True


# @shared_task(bind=True, acks_late=True, ignore_result=False)
@shared_task(bind=True, ignore_result=False)
def _run_scan_job(self, evt_prefix, scan_id, assets_subset, position=1, max_timeout=SCAN_JOB_DEFAULT_TIMEOUT):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Exception:
        return False

    evt_prefix = f"{evt_prefix}[Job={position}]"
    timeout = time.time() + max_timeout

    # Check Scan status
    if scan.status not in ["started", "enqueued"]:
        Event.objects.create(message="{} BeforeScan - Bad scan status: '{}'. Task aborted.".format(evt_prefix, scan.status), type="ERROR", severity="ERROR", scan=scan)
        scan_job.update_status('finished', 'finished_at')
        return False

    scan_job = ScanJob.objects.create(
        position=position,
        scan=scan,
        task_id=uuid.UUID(str(self.request.id)),
        status="started",
        engine_type=scan.engine_type,
        engine_policy=scan.engine_policy,
        summary={},
        options={},
        started_at=timezone.now(),
    )
    scan_job.save()

    # Set the assets
    for asset_id in assets_subset:
        try:
            scan_job.assets.add(Asset.objects.get(id=asset_id))
        except Exception as e:
            print("bad asset id:", asset_id, str(e))
            pass

    # -x- Select an engine instance
    engine_inst = None
    if scan.scan_definition.engine is None:
        engine_candidates = EngineInstance.objects.filter(
            engine__name=str(scan.scan_definition.engine_type.name).upper(),
            status="READY",
            enabled=True)
        if len(engine_candidates) > 0:
            engine_inst = random.choice(engine_candidates)
        else:
            # Otherwise, check Busy ones
            engine_candidates_busy = EngineInstance.objects.filter(
                engine__name=str(scan.scan_definition.engine_type.name).upper(),
                status="BUSY",
                enabled=True)
            if len(engine_candidates_busy) > 0:
                engine_inst = random.choice(engine_candidates_busy)
            else:
                engine_inst = None
    else:
        engine_inst = scan.scan_definition.engine
        if engine_inst.status not in ["READY", "BUSY"] or engine_inst.enabled is False:
            engine_inst = None
            Event.objects.create(message="{} BeforeScan - Engine '{}' not available (status: {}, enabled: {}). Task aborted.".format(evt_prefix, engine_inst.name, engine_inst.status, engine_inst.enabled), type="ERROR", severity="ERROR", scan=scan)

    # Check if the selected engine instance is available
    if engine_inst is None:
        Event.objects.create(message="{} BeforeScan - No engine '{}' available. Task aborted.".format(evt_prefix, scan.scan_definition.engine_type.name), type="ERROR", severity="ERROR", scan=scan)
        scan_job.update_status('error', 'finished_at')
        return False

    # Engine is selected (could be BUSY)
    Event.objects.create(message="{} Engine '{}' has been selected.".format(evt_prefix, engine_inst.name), type="INFO", severity="INFO", scan=scan)
    scan_job.engine = engine_inst
    scan_job.save()

    # -1- Wait the engine availability for accepting scans (status=READY)
    Event.objects.create(message="{} BeforeScan - Waiting for available engine.".format(evt_prefix), type="INFO", severity="INFO", scan=scan)

    while True:
        if time.time() > timeout:
            scan_job.update_status('error', 'finished_at')
            Event.objects.create(message="{} BeforeScan - max timeout ({}) reached. Task aborted.".format(evt_prefix, max_timeout), type="ERROR", severity="ERROR", scan=scan)
            return False
        if _get_engine_status(engine=engine_inst) == "READY":
            break
        time.sleep(5)

    Event.objects.create(message="{} BeforeScan - Engine available: {}.".format(evt_prefix, engine_inst), type="INFO", severity="INFO", scan=scan)

    # -2- Call the engine REST API /startscan
    assets_list = []
    for a in scan_job.assets.all():
        assets_list.append({
            "id": a.id,
            "value": a.value.strip(),
            "criticity": a.criticity,
            "datatype": a.type
        })

    scan_params ={
        "assets": assets_list,
        "options": scan.scan_definition.engine_policy.options,
        "engine_id": engine_inst.id,
        "scan_id": scan_job.id
    }
    try:
        resp = requests.post(
            url=str(engine_inst.api_url)+"startscan",
            data=json.dumps(scan_params),
            headers={'Content-type': 'application/json', 'Accept': 'application/json'},
            proxies=settings.PROXIES,
            timeout=HTTP_REQUEST_MAX_TIMEOUT
        )

        if resp.status_code != 200 or json.loads(resp.text)['status'] not in ["accepted", "ACCEPTED"]:
            scan_job.update_status('error', 'finished_at')
            response_reason = 'Unknown'
            try:
                if 'details' in json.loads(resp.text) and 'reason' in json.loads(resp.text)['details']:
                    response_reason = json.loads(resp.text)['details']['reason']
                elif 'reason' in json.loads(resp.text):
                    response_reason = json.loads(resp.text)['reason']
            except Exception:
                pass

            Event.objects.create(message="{} DuringScan - something goes wrong (response_status_code={}, response_status={}, response_details={}). Task aborted.".format(evt_prefix, resp.status_code, json.loads(resp.text)['status'], response_reason),
                description=str(resp.text), type="ERROR", severity="ERROR", scan=scan)
            return False
    except requests.exceptions.RequestException as e:
        scan_job.update_status('error', 'finished_at')
        Event.objects.create(message=f"{evt_prefix} DuringScan - Something goes wrong. Task aborted.",
            description=str(e), type="ERROR", severity="ERROR", scan=scan)
        return False

    # -3- Wait the scan if finished until timeout ring
    retries = NB_MAX_RETRIES  # test value
    scan_status = _get_scan_status(engine=engine_inst, scan_id=scan_job.id)

    while scan_status not in ['FINISHED', 'READY'] and retries > 0:
        if time.time() > timeout:
            scan_job.update_status('error', 'finished_at')
            Event.objects.create(message=f"{evt_prefix} DuringScan - ScanJob timeout reached. Task aborted.", type="ERROR", severity="ERROR", scan=scan)
            return False

        if scan_status in ['STARTED', 'SCANNING', 'PAUSING', 'STOPING']:
            retries = NB_MAX_RETRIES
        else:
            Event.objects.create(message="{} DuringScan - bad scanner status: {} (retries left={}).".format(evt_prefix, scan_status, retries), type="ERROR", severity="ERROR", scan=scan)
            retries -= 1
        time.sleep(5)
        scan_status = _get_scan_status(engine=engine_inst, scan_id=scan_job.id)
        print("scan status (in loop): {}".format(scan_status))

    if retries == 0:
        scan_job.update_status('error', 'finished_at')
        Event.objects.create(message="{} DuringScan - max_retries ({}) reached. Task aborted.".format(evt_prefix, retries), type="ERROR", severity="ERROR", scan=scan)
        return False

    Event.objects.create(message=f"{evt_prefix} AfterScan - Scan Finished: findings are now available.", type="DEBUG", severity="DEBUG", scan=scan)

    # @Todo: change to wait the report becomes available until a timeout
    time.sleep(5)  # wait the scan process finish to write the report

    # -4- get the results (findings)
    try:
        resp = requests.get(url=str(engine_inst.api_url)+"getfindings/"+str(scan_job.id), proxies=settings.PROXIES)
        if resp.status_code != 200 or json.loads(resp.text)['status'] == "error":
            scan_job.update_status('error', 'finished_at')
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
        scan_job.update_status('error', 'finished_at')
        Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in 'getfindings' call (request_status_code={}). Task aborted.".format(self.request.id, resp.status_code),
            type="ERROR", severity="ERROR", scan=scan, description="{}\n{}".format(e, resp.text))
        return False

    # -5- Import the results in DB
    try:
        _import_findings(findings=deepcopy(json.loads(resp.text)['issues']), scan=scan, scanjob_id=scan_job.id)

    except Exception as e:
        Event.objects.create(message=f"{evt_prefix} AfterScan - something goes wrong in '_import_findings' call. Task aborted.", description=str(e), type="ERROR", severity="ERROR", scan=scan)
        scan_job.update_status('error', 'finished_at')
        return False

    # -6- Get and store the report
    try:
        resp = requests.get(url=str(engine_inst.api_url)+"getreport/"+str(scan_job.id), stream=True, proxies=settings.PROXIES)
        # if resp.status_code == 200:
        #     user_report_dir = settings.MEDIA_ROOT + "/reports/"+str(params['owner_id'])+"/"
        #     if not os.path.exists(user_report_dir):
        #         os.makedirs(user_report_dir)
        #     fname = str(engine_inst.name) + "_" + str(scan.id) + ".json"
        #     scan.report_filepath = user_report_dir+str(fname)
        #     with open(scan.report_filepath, 'wb') as f:
        #         for chunk in resp:
        #             f.write(chunk)
        # else:
        #     scan_job.update_status('error', 'finished_at')
        #     Event.objects.create(message="[EngineTasks/startscan_task/{}] AfterScan - something goes wrong in 'getreport' call: {}. Task aborted.".format(self.request.id, resp.status_code),
        #         type="ERROR", severity="ERROR", scan=scan)
        #     return False

    except Exception as e:
        # print(e.message)
        scan.update_status('error', 'finished_at')
        Event.objects.create(message=f"{evt_prefix} AfterScan - something goes wrong in 'getreport' call. Task aborted.", description="{}".format(e.message), type="ERROR", severity="ERROR", scan=scan)
        return False

    scan_job.update_status('finished', 'finished_at')
    Event.objects.create(message="{} AfterScan - scan job finished at: {}.".format(evt_prefix, scan_job.finished_at), type="DEBUG", severity="INFO", scan=scan)
    return True


def _import_findings(findings, scan, engine_name=None, engine_id=None, owner_id=None, scanjob_id=None):
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
        Event.objects.create(message="[EngineTasks/_import_findings()/scan_id={}/{}] Importing findings for scan '{}'.".format(scan.id, scanjob_id, scan.title), type="DEBUG", severity="INFO", scan=scan)
        scan_id = scan.id
    else:
        Event.objects.create(message="[EngineTasks/_import_findings()/direct] Importing findings manually.", type="DEBUG", severity="INFO")
        scan_id = 0
    evt_prefix = "[EngineTasks/_import_findings()/scan_id={}/{}]".format(scan_id, scanjob_id)

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
                try:
                    asset = _create_asset_on_import(asset_value=addr, scan=scan, parent=finding["target"]["parent"])
                except Exception as e:
                    print(e)
                    asset = None
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

            #Check description . If CGI in text count the vulnerable parameteres . Only for Nessus
            count__old_vuln_params =0
            count__new_vuln_params =0
            tmp_status = "new"
            if scan.engine_type.name == "NESSUS" and "CGI" in finding['title']:
                #logger.error("mesa sto if")
                #regex = re.compile(".*?\((.*?)\)")
                #f_new_nessus = re.sub(" [\(\[].*?[\)\]]", "", finding['title'])
                tmp_f_new_nessus = finding['title'].split('(')
                tmp_f_new_nessus = tmp_f_new_nessus[:-1]
                f_new_nessus = '('.join(tmp_f_new_nessus).strip()
                f_nessus = Finding.objects.filter(asset=asset, title__istartswith=f_new_nessus).only('checked_at', 'status').first()
                if f_nessus:
                    tmp_status = "duplicate"
                #count__old_vuln_params = f_nessus.description.count("+ The '")
                #count__new_vuln_params = finding['description'].count("+ The '")

            if f is not None:
                # We already see you
                f.checked_at = timezone.now()
                if f.status in ['patched', 'closed']:
                    f.status = "undone"
                f.save()
                new_raw_finding.status = f.status
                new_raw_finding.save()

                known_findings_list.append(new_raw_finding.hash)
            else:
                new_raw_finding.status = tmp_status
                new_raw_finding.save()
                # Raise an alert
                if tmp_status != "duplicate":
                    new_finding_alert(new_raw_finding.id, new_raw_finding.severity)

                # Vtasio Add Tags
                if 'is running on port' in finding['title']:
                    service = re.findall(r"'(.*?)'", finding['title'])
                    new_tag = _add_asset_tags(asset, service[0])
                    Event.objects.create(message = "[EngineTasks/_import_findings()/scan_id={}] New Tag: {}".format(scan_id, +service[0]),description = "Asset: {}\nFinding: {}".format(asset.value,finding['title']),type = "DEBUG", severity = "INFO", scan = scan)
                    asset.categories.add(new_tag)
                    asset.save()
                if 'Failed to resolve' in finding['title'] and asset.type=="domain":
                    new_tag = _add_asset_tags(asset, 'inactive-domain')
                    asset.categories.add(new_tag)
                    asset.save()
                if 'Failed to resolve' in finding['title'] and asset.type=="ip":
                    new_tag = _add_asset_tags(asset, 'inactive-ip')
                    asset.categories.add(new_tag)
                    asset.save()
                if 'Host' in finding['title'] and 'is up' in finding['title'] and asset.type=="domain":
                    new_tag = _add_asset_tags(asset, 'active-domain')
                    asset.categories.add(new_tag)
                    asset.save()
                if 'Host' in finding['title'] and 'is up' in finding['title'] and asset.type=="ip":
                    new_tag = _add_asset_tags(asset, 'active-ip')
                    asset.categories.add(new_tag)
                    asset.save()

                # Create an event if logging level OK
                Event.objects.create(
                    message="{} New finding: {}".format(evt_prefix, finding['title']),
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
                    status      = tmp_status,
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
                    Event.objects.create(message="{} Error in alerting".format(evt_prefix),
                        type="ERROR", severity="ERROR", scan=scan, description=str(e))

    scan.save()
    scan.update_sumary()

    # Reevaluate the risk level of the asset on new risk
    for a in scan.assets.all():
        a.calc_risk_grade()
    for ag in scan.scan_definition.assetgroups_list.all():
        ag.calc_risk_grade()

    # Search missing findings
    # - check if a previous scan exists
    last_scan = scan.scan_definition.scan_set.exclude(id=scan.id).order_by('-id').first()
    if last_scan is not None:
        # Loop in missing findings
        for mf in last_scan.rawfinding_set.exclude(hash__in=known_findings_list):
            missing_finding_alert(mf.id, scan.id, mf.severity)
            # Remove Tags for missing findings
            rawfinding = RawFinding.objects.filter(id=mf.id).first()
            if 'is running on port' in rawfinding.title:
                service = re.findall(r"'(.*?)'", rawfinding.title)
                invalid_tag = _add_asset_tags(asset, service[0])
                asset.categories.remove(invalid_tag)
                asset.save()
            if 'Failed to resolve' in rawfinding.title and asset.type=="domain":
                invalid_tag = _add_asset_tags(asset, 'inactive-domain')
                asset.categories.remove(invalid_tag)
                asset.save()
            if 'Failed to resolve' in rawfinding.title and asset.type=="ip":
                invalid_tag = _add_asset_tags(asset, 'inactive-ip')
                asset.categories.remove(invalid_tag)
                asset.save()
            if 'Host' in rawfinding.title and 'is up' in rawfinding.title and asset.type=="domain":
                invalid_tag = _add_asset_tags(asset, 'active-domain')
                asset.categories.remove(invalid_tag)
                asset.save()
            if 'Host' in rawfinding.title and 'is up' in rawfinding.title and asset.type=="ip":
                invalid_tag = _add_asset_tags(asset, 'active-ip')
                asset.categories.remove(invalid_tag)
                asset.save()

    scan.save()
    Event.objects.create(message="{} Findings imported.".format(evt_prefix), type="INFO", severity="INFO", scan=scan)
    return True


def _create_asset_on_import(asset_value, scan, asset_type='unknown', parent=None):
    evt_prefix = "[EngineTasks/_create_asset_on_import()]"
    Event.objects.create(message="{} Create: '{}/{} from parent {}'.".format(evt_prefix, asset_value, asset_type, parent), type="DEBUG", severity="INFO", scan=scan)

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
        Event.objects.create(message="{} Looking for a group named : {}".format(evt_prefix, parent), type="DEBUG", severity="INFO", scan=scan)
        asset_group = AssetGroup.objects.filter(name="{} assets".format(parent)).first()
        if asset_group is None:   # Create an asset group dynamically
            Event.objects.create(message="{} Create a group named : {}".format(evt_prefix, parent), type="DEBUG", severity="INFO", scan=scan)
            assetgroup_args = {
               'name': "{} assets".format(parent),
               'criticity': criticity,
               'description': "AssetGroup dynamically created",
               'owner': owner
            }
            asset_group = AssetGroup(**assetgroup_args)
            asset_group.save()

        Event.objects.create(message="{} Add {} in group {}".format(evt_prefix, asset, parent), type="DEBUG", severity="INFO", scan=scan)
        # Add the asset to the new group
        asset_group.assets.add(asset)
        asset_group.save()

        # Caculate the risk grade
        asset_group.calc_risk_grade()
        asset_group.save()

    return asset
