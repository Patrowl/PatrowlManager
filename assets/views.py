from django.http import JsonResponse, HttpResponse, HttpResponseRedirect
from django.forms.models import model_to_dict
from django.utils.encoding import smart_str
from django.utils import timezone
from django.core.files.storage import FileSystemStorage
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import Value, CharField, Case, When, Q, F, Count


from wsgiref.util import FileWrapper

from django.contrib import messages
from django.contrib.auth.models import User
from django.contrib.postgres.aggregates import ArrayAgg
from django.shortcuts import render, redirect, render_to_response, get_object_or_404

from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.decorators import api_view, authentication_classes, permission_classes

from app.settings import MEDIA_ROOT
from .serializers import AssetSerializer
from .forms import AssetForm, AssetGroupForm, AssetBulkForm, AssetOwnerForm, AssetOwnerDocumentForm, AssetOwnerContactForm
from .models import Asset, AssetGroup, AssetOwner, AssetOwnerContact, AssetOwnerDocument, AssetCategory, ASSET_INVESTIGATION_LINKS
from findings.models import Finding
from engines.models import EnginePolicyScope
from events.models import Event
from scans.models import Scan, ScanDefinition

import uuid, json, ast, csv, os, mimetypes, datetime, urllib


def get_assets_stats(request):
    assets = Asset.objects.all()
    data = {
        "nb_assets": assets.count(),
        "nb_assets_high": assets.filter(criticity="high").count(),
        "nb_assets_medium": assets.filter(criticity="medium").count(),
        "nb_assets_low": assets.filter(criticity="low").count(),
        "nb_assets_info": assets.filter(criticity="info").count(),
    }
    return JsonResponse(data, json_dumps_params={'indent': 2})


@api_view(['GET'])
@authentication_classes((SessionAuthentication, BasicAuthentication))
@permission_classes((IsAuthenticated,))
def get_asset_details_api(request, asset_name):
    asset = get_object_or_404(Asset, value=asset_name)

    # Asset details
    response = model_to_dict(asset, fields=[field.name for field in asset._meta.fields])

    # Related asset groups
    asset_groups = []
    for asset_group in asset.assetgroup_set.all():
        asset_group_dict = model_to_dict(asset_group, fields=[field.name for field in asset_group._meta.fields])
        asset_groups.append(asset_group_dict)
    response.update({
        "asset_groups": asset_groups
    })

    # Related findings
    findings = []
    for finding in asset.finding_set.all():
        finding_dict = model_to_dict(finding, fields=[field.name for field in finding._meta.fields])
        findings.append(finding_dict)
    response.update({
        "findings": findings
    })

    # Last 10 scans
    scans = []
    for scan in asset.scan_set.all()[:10]:
        scan_dict = model_to_dict(scan, fields=[field.name for field in scan._meta.fields])
        scans.append(scan_dict)
    response.update({
        "last10scans": scans
    })

    return JsonResponse(response, json_dumps_params={'indent': 2}, safe=False)


def get_asset_trends(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)
    data = []
    ticks_by_period = {'week': 7, 'month': 30, 'trimester': 120, 'year': 365 }
    grade_levels = { 'A': 6, 'B': 5, 'C': 4, 'D': 3, 'E': 2, 'F': 1, 'n/a': 0 }

    # period = x-axis
    period = request.GET.get('period_by', None)    # 'days', 'weeks', 'months', 'year'
    if period not in ticks_by_period.keys():
        period = 7
    else:
        period = ticks_by_period[period]

    nb_ticks = int(request.GET.get('max_ticks', 15))
    if nb_ticks < period:
        delta = period // nb_ticks
    else:
        delta = 1
    #print "period", period, ", delta:", delta, ", nb_ticks:", nb_ticks

    startdate = datetime.datetime.today()
    for i in range(0,nb_ticks):
        enddate = startdate - datetime.timedelta(days=i*delta)
        findings_stats = {
            'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0,
            'new': 0,
            'risk_grade': 'n/a',
            'date': str(enddate.date())}
        for f in asset.finding_set.filter(created_at__lte=enddate):
            findings_stats['total'] = findings_stats.get('total') + 1
            findings_stats[f.severity] = findings_stats.get(f.severity) + 1
            if f.status == 'new':
                findings_stats['new'] = findings_stats.get('new') + 1

        if findings_stats['total'] != 0:
            findings_stats['risk_grade'] = grade_levels[asset.get_risk_grade(history=i)]
            # findings_stats['risk_grade'] = grade_levels[asset.get_risk_grade(history=i)['grade']]
        else:
            findings_stats['risk_grade'] = 0
        data.append(findings_stats)

    return JsonResponse(data[::-1], json_dumps_params={'indent': 2}, safe=False)


def list_assets_api(request):
    q = request.GET.get("q", None)
    if q:
        assets = list(Asset.objects.filter(value__icontains=q)
                      .annotate(format=Value("asset",output_field=CharField()))
                      .values('id', 'value', 'format'))
        assetgroups = list(AssetGroup.objects.filter(name__icontains=q)
                       .extra(select={'value': 'name'})
                       .annotate(format=Value("assetgroup",output_field=CharField()))
                       .values('id', 'value', 'format'))
    else:
        assets = list(Asset.objects
                      .annotate(format=Value("asset",output_field=CharField()))
                      .values('id', 'value', 'format'))
        assetgroups = list(AssetGroup.objects
                           .extra(select={'value': 'name'})
                           .annotate(format=Value("assetgroup",output_field=CharField()))
                           .values('id', 'value', 'format'))
    return JsonResponse(assets + assetgroups, safe=False)


@api_view(['GET', 'POST'])
@csrf_exempt
def list_assets(request):
    #res = {"page": "list_assets"}
    if request.method == 'GET':
        assets = Asset.objects.all()
        ser = AssetSerializer(assets, many=True)
        return JsonResponse(ser.data, safe=False)
    elif request.method == 'POST':
        data = JSONParser().parse(request)
        ser = AssetSerializer(data=data)
        if ser.is_valid():
            ser.save()
            return JsonResponse(ser.data, status=201)
        return JsonResponse(ser.errors, status=400)
    else:
        return JsonResponse({"status": "error"}, status=400)


@api_view(['GET', 'PUT', 'DELETE'])
@csrf_exempt
def asset_details(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)

    if request.method == 'GET':
        ser = AssetSerializer(asset)
        return JsonResponse(ser.data, safe=False)

    elif request.method == 'PUT':
        data = JSONParser().parse(request)
        ser = AssetSerializer(asset, data=data)
        if ser.is_valid():
            ser.save()
            return JsonResponse(ser.data)
        return JsonResponse(ser.errors, status=400)

    elif request.method == 'DELETE':
        asset.delete()
        return HttpResponse(status=204)


def list_assets_view(request):
    # Check sorting options
    allowed_sort_options = ["id", "name", "criticity_num", "score", "type", "updated_at", "risk_level", "risk_level__grade",
                            "-id", "-name", "-criticity_num", "-score", "-type", "-updated_at", "-risk_level", "-risk_level__grade"]
    sort_options = request.GET.get("sort", "-updated_at")
    sort_options_valid = []
    for s in sort_options.split(","):
        if s in allowed_sort_options and s not in sort_options_valid:
            sort_options_valid.append(str(s))

    # Check Filtering options
    filter_options = request.GET.get("filter", "")

    #Todo: filter on fields
    allowed_filter_fields = ["id", "name", "criticity", "type", "score"] #score
    filter_criterias = filter_options.split(" ")
    filter_fields = {}
    filter_opts = ""
    for criteria in filter_criterias:
        field = criteria.split(":")
        if len(field) > 1 and field[0] in allowed_filter_fields:
            # allowed field
            if field[0] == "score":
                filter_fields.update({"risk_level__grade": field[1]})
            else:
                filter_fields.update({str(field[0]): field[1]})
        else:
            filter_opts = filter_opts + str(criteria.strip())

    # Query
    assets_list = Asset.objects.filter(**filter_fields).filter(
        Q(value__icontains=filter_opts)|
        Q(name__icontains=filter_opts)|
        Q(description__icontains=filter_opts)
        ).annotate(
            criticity_num=Case(
                When(criticity="high", then=Value("1")),
                When(criticity="medium", then=Value("2")),
                When(criticity="low", then=Value("3")),
                default=Value("1"),
                output_field=CharField())
            ).annotate(cat_list=ArrayAgg('categories__value')).order_by(*sort_options_valid)

    # Pagination assets
    nb_rows = request.GET.get('n', 16)
    assets_paginator = Paginator(assets_list, nb_rows)
    page = request.GET.get('page')
    try:
        assets = assets_paginator.page(page)
    except PageNotAnInteger:
        assets = assets_paginator.page(1)
    except EmptyPage:
        assets = assets_paginator.page(assets_paginator.num_pages)

    ## List asset groups
    asset_groups = []
    for asset_group in AssetGroup.objects.all():
        ag = model_to_dict(asset_group)
        # extract asset names to diplay
        asset_list = []
        for asset in asset_group.assets.all():
            asset_list.append(asset.value)

        ag["assets_names"] = ", ".join(asset_list)
        ag["risk_grade"] = asset_group.get_risk_grade()
        asset_groups.append(ag)

    return render(request, 'list-assets.html', {'assets': assets, 'asset_groups': asset_groups})


def refresh_all_asset_grade_api(request):
    for asset in Asset.objects.all():
        asset.calc_risk_grade()
    for assetgroup in AssetGroup.objects.all():
        assetgroup.calc_risk_grade()
    return redirect('list_assets_view')


def refresh_asset_grade_api(request, asset_id = None):
    if asset_id:
        asset = get_object_or_404(Asset, id=asset_id)
        asset.calc_risk_grade()
    else:
        # update all
        for asset in Asset.objects.all():
            asset.calc_risk_grade()
    return redirect('list_assets_view')


def refresh_assetgroup_grade_api(request, assetgroup_id=None):
    if assetgroup_id:
        assetgroup = get_object_or_404(AssetGroup, id=assetgroup_id)
        assetgroup_id.calc_risk_grade()
    else:
        # update all
        for assetgroup in AssetGroup.objects.all():
            assetgroup.calc_risk_grade()
    return JsonResponse({"status": "success"}, safe=False)

def export_assets(request, assetgroup_id=None):
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = 'attachment; filename="patrowl_assets.csv"'
    writer = csv.writer(response, delimiter=';')

    assets = []
    if assetgroup_id:
        asset_group = AssetGroup.objects.get(id=assetgroup_id)
        for asset in asset_group.assets.all():
            assets.append(asset)
    else:
        # assets = Asset.objects.filter(owner_id=request.user.id)
        assets = Asset.objects.all()

    writer.writerow(['asset_value', 'asset_name', 'asset_type', 'asset_description', 'asset_criticity', 'asset_tags'])
    for asset in assets:
        writer.writerow([smart_str(asset.value), asset.name, asset.type, smart_str(asset.description), asset.criticity, ",".join([a.value for a in asset.categories.all()])])
    return response


def add_asset_view(request):
    form = None

    if request.method == 'GET':
        form = AssetForm()
    elif request.method == 'POST':
        form = AssetForm(request.POST)
        if form.is_valid():

            # check if the value is already stored
            # if form.cleaned_data['value'] in [a['value'] for a in Asset.objects.filter(owner__id=request.user.id).only({"value"})]:
            #     messages.error(request, 'Asset already saved, import another one or cancel')
            #     return redirect('add_asset_view')

            asset_args = {
                'value': form.cleaned_data['value'],
                'name': form.cleaned_data['name'],
                'type': form.cleaned_data['type'],
                'criticity': form.cleaned_data['criticity'],
                'description': form.cleaned_data['description'],
                'owner': request.user,
            }
            asset = Asset(**asset_args)
            asset.save()

            if asset.type in ['ip-range', 'ip-subnet']:
                # Create an asset group dynamically
                assetgroup_args = {
                    'name': "{} assets".format(asset.name),
                    'criticity': asset.criticity,
                    'description': "Asset dynamically created. Imported desc: {}".format(asset.description),
                    'owner': request.user
                }
                asset_group = AssetGroup(**assetgroup_args)
                asset_group.save()

                # Add the asset to the new group
                asset_group.assets.add(asset)
                asset_group.save()

                # Caculate the risk grade
                asset_group.calc_risk_grade()
                asset_group.save()

            messages.success(request, 'Creation submission successful')

            return redirect('list_assets_view')
    return render(request, 'add-asset.html', {'form': form })


def edit_asset_view(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)

    form = AssetForm()
    if request.method == 'GET':
        form = AssetForm(instance=asset)
    elif request.method == 'POST':
        form = AssetForm(request.POST, instance=asset)
        if form.is_valid():
            asset.value = form.cleaned_data['value']
            asset.name = form.cleaned_data['name']
            asset.type = form.cleaned_data['type']
            asset.description = form.cleaned_data['description']
            asset.criticity = form.cleaned_data['criticity']
            asset.evaluate_risk()

            if form.data.getlist('categories'):
                asset.categories.clear()
                for cat_id in form.data.getlist('categories'):
                    asset.categories.add(AssetCategory.objects.get(id=cat_id))
            asset.save()

            messages.success(request, 'Update submission successful')
            return redirect('list_assets_view')

    return render(request, 'edit-asset.html', {'form': form, 'asset': asset})

def delete_asset_view(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)

    if request.method == 'POST':
        asset.delete()

        messages.success(request, 'Asset successfully deleted!')
        return redirect('list_assets_view')
    return render(request, 'delete-asset.html', {'asset': asset})


@csrf_exempt #not secure!!!
def delete_assets(request):
    if request.method != 'POST':
        return JsonResponse({'status': 'error'})

    assets = json.loads(request.body)
    for asset_id in assets:
        a = Asset.objects.get(id=asset_id)
        a.delete()

    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


def get_asset_tags_api(request):
    tags = AssetCategory.objects.values_list('value', flat=True)
    return JsonResponse(list(tags), safe=False)


def add_asset_tags(asset, new_value):
    new_tag = AssetCategory.objects.filter(value__iexact=new_value).first()
    if not new_tag:
        custom_tags = AssetCategory.objects.get(value="Custom")
        new_tag = custom_tags.add_child(value=new_value)

        Event.objects.create(message="[AssetCategory/add_asset_tags()] New AssetCategory created: '{}' with id: {}.".format(new_value, new_tag.id),
                     type="INFO", severity="INFO")

    if not new_tag in asset.categories.all(): # Not already set
        # Check if futures parents has been already selected. If True: delete them
        cats = list(asset.categories.all().values_list('value', flat=True))
        if new_tag.get_all_parents():
            pars = [t.value for t in new_tag.get_all_parents()]
        else:
            pars = []
        intersec_par = set(pars).intersection(cats)
        if intersec_par:
            asset.categories.remove(AssetCategory.objects.get(value=list(intersec_par)[0]))

        # Check if current tags are not children of the new tag. If True: delete them
        chis = [t.value for t in new_tag.get_children()]
        for c in set(chis).intersection(cats):
            asset.categories.remove(AssetCategory.objects.get(value=c))

    return new_tag


def add_asset_tags_api(request, asset_id):
    if request.method == 'POST':
        asset = get_object_or_404(Asset, id=asset_id)
        new_tag = add_asset_tags(asset, request.POST.getlist('input-search-tags')[0])
        asset.categories.add(new_tag)
        messages.success(request, 'Tag successfully added!')

    return redirect('detail_asset_view', asset_id=asset_id)


def add_asset_group_tags_api(request, assetgroup_id):
    if request.method == 'POST':
        asset_group = get_object_or_404(AssetGroup, id=assetgroup_id)
        new_tag = add_asset_tags(asset_group, request.POST.getlist('input-search-tags')[0])
        asset_group.categories.add(new_tag)
        messages.success(request, 'Tag successfully added!')

    return redirect('detail_asset_group_view', assetgroup_id=assetgroup_id)


def delete_asset_tags_api(request, asset_id):
    tag_id = request.POST.get('tag_id', None)
    try:
        tag = AssetCategory.objects.get(id=tag_id)
    except AssetCategory.DoesNotExist:
        Event.objects.create(message="[AssetCategory/delete_asset_tags_api()] Asset with id '{}' was not found.".format(asset_id),
                     type="ERROR", severity="ERROR")
        return redirect('detail_asset_view', asset_id=asset_id)

    if request.method == 'POST':
        asset = get_object_or_404(Asset, id=asset_id)
        asset.categories.remove(tag) # @todo: check error cases

    return redirect('detail_asset_view', asset_id=asset_id)


def delete_asset_group_tags_api(request, assetgroup_id):
    tag_id = request.POST.get('tag_id', None)
    try:
        tag = AssetCategory.objects.get(id=tag_id)
    except AssetCategory.DoesNotExist:
        Event.objects.create(message="[AssetCategory/delete_asset_tags_api()] AssetGroup with id '{}' was not found.".format(assetgroup_id),
                     type="ERROR", severity="ERROR")
        return redirect('detail_asset_group_view', assetgroup_id=assetgroup_id)

    if request.method == 'POST':
        assetgroup = get_object_or_404(AssetGroup, id=assetgroup_id)
        assetgroup.categories.remove(tag) # @todo: check error cases

    return redirect('detail_asset_group_view', assetgroup_id=assetgroup_id)


def add_asset_group_view(request):
    form = None

    if request.method == 'GET':
        form = AssetGroupForm()
    elif request.method == 'POST':
        form = AssetGroupForm(request.POST)
        if form.is_valid():
            asset_args = {
                'name': form.cleaned_data['name'],
                'criticity': form.cleaned_data['criticity'],
                'description': form.cleaned_data['description'],
                'owner': request.user
            }
            asset_group = AssetGroup(**asset_args)
            asset_group.save()

            for asset_id in form.data.getlist('assets'):
                asset_group.assets.add(Asset.objects.get(id=asset_id))

            asset_group.save()
            asset_group.calc_risk_grade()
            asset_group.save()
            messages.success(request, 'Creation submission successful')

            return redirect('list_assets_view')
    return render(request, 'add-asset-group.html', {'form': form })


def edit_asset_group_view(request, assetgroup_id):
    asset_group = get_object_or_404(AssetGroup, id=assetgroup_id)

    form = AssetGroupForm()
    if request.method == 'GET':
        form = AssetGroupForm(instance=asset_group)
    elif request.method == 'POST':
        # form = AssetGroupForm(request.POST)
        form = AssetGroupForm(request.POST, instance=asset_group)
        if form.is_valid():
            if asset_group.name != form.cleaned_data['name']:
                asset_group.name = form.cleaned_data['name']
            asset_group.description = form.cleaned_data['description']
            asset_group.criticity = form.cleaned_data['criticity']
            asset_group.assets.clear()
            for asset_id in form.data.getlist('assets'):
                asset_group.assets.add(Asset.objects.get(id=asset_id))
            asset_group.evaluate_risk()
            asset_group.save()

            asset_group.calc_risk_grade()
            asset_group.save()

            messages.success(request, 'Update submission successful')
            return redirect('list_assets_view')

    return render(request, 'edit-asset-group.html',
                  {'form': form, 'assetgroup_id': assetgroup_id, 'asset_group': asset_group})


def delete_asset_group_view(request, assetgroup_id):
    asset_group = get_object_or_404(AssetGroup, id=assetgroup_id)
    if request.method == 'POST':
        asset_group.delete()
        messages.success(request, 'Asset group successfully deleted!')
        return redirect('list_assets_view')
    return render(request, 'delete-asset-group.html', {'asset_group': asset_group})


def bulkadd_asset_view(request):
    form = None

    if request.method == 'GET':
        form = AssetBulkForm()
    elif request.method == 'POST':
        form = AssetBulkForm(request.POST, request.FILES)
        if request.FILES:
            records = csv.reader(request.FILES['file'], delimiter=';')
            records.next()
            for line in records:
                # Add assets
                if Asset.objects.filter(value=line[0]).count() > 0:
                    print "{} already added".format(line[0])
                    continue

                asset_args = {
                    'value': line[0],
                    'name': line[1],
                    'type': line[2],
                    'description': line[3],
                    'criticity': line[4],
                    'owner': User.objects.get(id=request.user.id),
                    'status': "new",
                }
                asset = Asset(**asset_args)
                asset.save()

                # Manage tags (categories)
                #@todo
                if line[5] and line[5] != "":
                    print line[5]
                    for tag in line[5].split(","):
                        print tag

                # Add groups
                if line[6] and line[6] != "":
                    ag = AssetGroup.objects.filter(name=str(line[6])).first()
                    if ag is None: # Create new asset group
                        asset_args = {
                            'name': line[6],
                            'criticity': "low",
                            'description': "Created automatically on asset upload.",
                            'owner': request.user
                        }
                        ag = AssetGroup(**asset_args)
                        ag.save()
                    # add the asset to the group
                    ag.assets.add(asset)

            messages.success(request, 'Creation submission successful')

            return redirect('list_assets_view')
    return render(request, 'add-assets-bulk.html', {'form': form })


#todo: change to asset_id
def evaluate_asset_risk_view(request, asset_name):
    asset = get_object_or_404(Asset, value=asset_name)
    data = asset.evaluate_risk()
    return JsonResponse(data, safe=False)


def detail_asset_view(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)
    findings = Finding.objects.filter(asset=asset).annotate(
        severity_numm=Case(
            When(severity="high", then=Value("1")),
            When(severity="medium", then=Value("2")),
            When(severity="low", then=Value("3")),
            When(severity="info", then=Value("4")),
            default=Value("1"),
            output_field=CharField())
        ).annotate(
            scope_list=ArrayAgg('scopes__name')
        ).order_by('severity_numm', 'type', 'updated_at')

    findings_stats = {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'new': 0, 'ack': 0, 'cvss_gte_7': 0}
    engines_stats = {}
    references = {}

    engine_scopes = {}
    for engine_scope in EnginePolicyScope.objects.all():
        engine_scopes.update({
            engine_scope.name: {'priority': engine_scope.priority, 'id': engine_scope.id, 'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        })

    for finding in findings:
        findings_stats['total'] = findings_stats.get('total', 0) + 1
        findings_stats[finding.severity] = findings_stats.get(finding.severity, 0) + 1
        if finding.status == 'new':
            findings_stats['new'] = findings_stats.get('new', 0) + 1
        if finding.status == 'ack':
            findings_stats['ack'] = findings_stats.get('ack', 0) + 1
        for fs in finding.scope_list:
            if fs != None:
                c = engine_scopes[fs]
                engine_scopes[fs].update({'total': c['total']+1, finding.severity: c[finding.severity]+1})
        if not finding.engine_type in engines_stats.keys():
            engines_stats.update({finding.engine_type: 0})
        engines_stats[finding.engine_type] = engines_stats.get(finding.engine_type, 0) + 1
        if finding.risk_info["cvss_base_score"] > 7.0: findings_stats['cvss_gte_7'] = findings_stats.get('cvss_gte_7', 0) + 1

        if bool(finding.vuln_refs):
            for ref in finding.vuln_refs.keys():
                if ref not in references.keys(): references.update({ref: []})
                tref=references[ref]
                if type(finding.vuln_refs[ref]) is list:
                    tref = tref + finding.vuln_refs[ref]
                else:
                    tref.append(finding.vuln_refs[ref])
                # references.update({ref: list(set(tref))})

                references.update({ref: tref})

    # Show only unique references
    references_cleaned = {}
    for ref in references:
        references_cleaned.update({ref: sorted(list(set(references[ref])))})

    # Related scans
    scans_stats = {
        'performed': Scan.objects.filter(assets__in=[asset]).count(),
        'defined': ScanDefinition.objects.filter(assets_list__in=[asset]).count(),
        'periodic': ScanDefinition.objects.filter(assets_list__in=[asset], scan_type='periodic').count(),
        'ondemand': ScanDefinition.objects.filter(assets_list__in=[asset], scan_type='single').count(),
        'running': Scan.objects.filter(assets__in=[asset], status='started').count(), #bug: a regrouper par assets
        'lasts': Scan.objects.filter(assets__in=[asset]).order_by('-created_at')[:3]
        }

    asset_groups = list(AssetGroup.objects.filter(assets__in=[asset]).only("id"))
    scan_defs = ScanDefinition.objects.filter(Q(assets_list__in=[asset])|Q(assetgroups_list__in=asset_groups)).annotate(engine_type_name=F('engine_type__name')).annotate(scan_set_count=Count('scan'))
    scans = Scan.objects.filter(assets__in=[asset]).values("id", "title", "status", "summary", "updated_at").annotate(engine_type_name=F('engine_type__name'))

    # Investigation links
    investigation_links = []
    for i in ASSET_INVESTIGATION_LINKS:
        if asset.type in i["datatypes"]:
            i["link"] = i["link"].replace("%asset%", asset.value)
            investigation_links.append(i)


    # Calculate automatically risk grade
    asset.calc_risk_grade()
    asset_risk_grade = {
        'now': asset.get_risk_grade(),
        'day_ago': asset.get_risk_grade(history = 1),
        'week_ago': asset.get_risk_grade(history = 7),
        'month_ago': asset.get_risk_grade(history = 30),
        'year_ago': asset.get_risk_grade(history = 365)
        }

    return render(request, 'details-asset.html', {
        'asset': asset,
        'asset_risk_grade': asset_risk_grade,
        'findings': findings,
        'findings_stats': findings_stats,
        'references': references_cleaned,
        'scans_stats': scans_stats,
        'scans': scans,
        'scan_defs': scan_defs,
        'investigation_links': investigation_links,
        'engines_stats': engines_stats,
        #'asset_scopes': engine_scopes
        'asset_scopes': sorted(engine_scopes.iteritems(), key=lambda (x, y): y['priority'])
        #'asset_scopes': sorted(asset_scopes.iteritems(), key=lambda (x, y): y['priority'])
        })


def detail_asset_group_view(request, assetgroup_id):
    asset_group = get_object_or_404(AssetGroup, id=assetgroup_id)
    assets = asset_group.assets.all()
    # findings = Finding.objects.filter(asset__in=assets).order_by('asset','severity', 'type', 'title')
    findings = Finding.objects.filter(asset__in=assets).annotate(
        severity_numm=Case(
            When(severity="high", then=Value("1")),
            When(severity="medium", then=Value("2")),
            When(severity="low", then=Value("3")),
            When(severity="info", then=Value("4")),
            default=Value("1"),
            output_field=CharField())).annotate(scope_list=ArrayAgg('scopes__name')).order_by('asset', 'severity_numm', 'type', 'updated_at')

    asset_scopes = {}
    for scope in EnginePolicyScope.objects.all():
        asset_scopes.update({scope.name: {'priority': scope.priority, 'id': scope.id, 'total':0, 'high':0, 'medium':0, 'low':0, 'info':0}})

    findings_stats = {'total': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0, 'new': 0, 'ack': 0}
    engines_stats = {}

    for finding in findings:
        findings_stats['total'] = findings_stats.get('total', 0) + 1
        findings_stats[finding.severity] = findings_stats.get(finding.severity, 0) + 1
        if finding.status == 'new':
            findings_stats['new'] = findings_stats.get('new', 0) + 1
        if finding.status == 'ack':
            findings_stats['ack'] = findings_stats.get('ack', 0) + 1
        for fs in finding.scope_list:
            if fs != None:
                c = asset_scopes[fs]
                asset_scopes[fs].update({'total': c['total']+1, finding.severity: c[finding.severity]+1})

        if not finding.engine_type in engines_stats.keys():
            engines_stats.update({finding.engine_type: 0})
        engines_stats[finding.engine_type] = engines_stats.get(finding.engine_type, 0) + 1

    # Scans
    scan_defs = ScanDefinition.objects.filter(Q(assetgroups_list__in=[asset_group])).annotate(engine_type_name=F('engine_type__name'))
    scans = []
    for scan_def in scan_defs:
        scans = scans + list(scan_def.scan_set.all())

    scans_stats = {
        'performed': len(scans),
        'defined': len(scan_defs),
        'periodic': scan_defs.filter(scan_type='periodic').count(),
        'ondemand': scan_defs.filter(scan_type='single').count(),
        'running': scan_defs.filter(status='started').count(), #bug: a regrouper par assets
        }

    # calculate automatically risk grade
    #asset_group.calc_risk_grade()
    asset_group_risk_grade = {
        'now': asset_group.get_risk_grade(),
        # 'day_ago': asset_group.get_risk_grade(history = 1),
        # 'week_ago': asset_group.get_risk_grade(history = 7),
        # 'month_ago': asset_group.get_risk_grade(history = 30),
        # 'year_ago': asset_group.get_risk_grade(history = 365)
        }

    return render(request, 'details-asset-group.html', {
        'asset_group': asset_group,
        'asset_group_risk_grade': asset_group_risk_grade,
        'assets': assets,
        'findings': findings,
        'findings_stats': findings_stats,
        'scans_stats': scans_stats,
        'scans': scans,
        'scan_defs': scan_defs,
        'engines_stats': engines_stats,
        'asset_scopes': sorted(asset_scopes.iteritems(), key=lambda (x, y): y['priority'])
    })


# get asset report on last unique findings
def get_asset_report_html(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)

    findings_tmp = list()
    findings_stats = {}

    # @todo: invert loops
    for sev in ["high", "medium", "low", "info"]:
        tmp = Finding.objects.filter(asset=asset.id, severity=sev).order_by('type')
        if tmp.count() > 0: findings_tmp += tmp
        findings_stats.update({sev: tmp.count()})
    findings_stats.update({"total": len(findings_tmp)})

    return render(request, 'report-asset-findings.html', {
        'asset': asset,
        'findings': findings_tmp,
        'findings_stats': findings_stats})


def get_asset_report_json(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)

    findings_tmp = list()
    findings_stats = {}

    # @todo: invert loops
    for sev in ["high", "medium", "low", "info"]:
        tmp = Finding.objects.filter(asset=asset.id, severity=sev).order_by('type')
        findings_stats.update({sev: tmp.count()})
        if tmp.count() > 0:
            findings_tmp.append([model_to_dict(f) for f in tmp])

    asset_dict = model_to_dict(asset, exclude=["categories"])
    asset_tags = [tag.value for tag in asset.categories.all()]
    asset_dict.update({"categories": asset_tags})

    return JsonResponse({
        'asset': asset_dict,
        'findings': findings_tmp,
        'findings_stats': findings_stats
        }, safe=False)


def get_asset_group_report_html(request, asset_group_id):
    asset_group = get_object_or_404(AssetGroup, id=asset_group_id)

    return render(request, 'report-assetgroup-findings.html', {
        'asset_group': asset_group})


## Asset Owners
def list_asset_owners_view(request):
    owners = []
    for owner in AssetOwner.objects.all():
        tmp_owner = model_to_dict(owner)
        tmp_owner["nb_assets"]      = owner.assets.all().count()
        tmp_owner["nb_contacts"]    = owner.contacts.all().count()
        tmp_owner["nb_documents"]   = owner.documents.all().count()
        owners.append(tmp_owner)

    return render(request, 'list-asset-owners.html', { 'owners': owners })


def add_asset_owner_view(request):
    form = None
    if request.method == 'GET':
        form = AssetOwnerForm()
    elif request.method == 'POST':
        form = AssetOwnerForm(request.POST)

        if form.errors: print (form.errors)

        if form.is_valid():
            owner_args = {
                'name': form.cleaned_data['name'],
                'url': form.cleaned_data['url'],
                'comments': form.cleaned_data['comments'],
                'owner': request.user,
            }
            owner = AssetOwner(**owner_args)
            owner.save()
            for asset_id in form.data.getlist('assets'):
                owner.assets.add(Asset.objects.get(id=asset_id))
            owner.save()
            messages.success(request, 'Creation submission successful')

            return redirect('list_asset_owners_view')
    return render(request, 'add-asset-owner.html', {'form': form })


def delete_asset_owner_view(request, asset_owner_id):
    if request.method == 'POST':
        owner = get_object_or_404(AssetOwner, id=asset_owner_id)
        owner.delete()
        messages.success(request, 'Asset owner successfully deleted!')
        return redirect('list_asset_owners_view')
    return render(request, 'delete-asset-owner.html', {'owner': owner})


def details_asset_owner_view(request, asset_owner_id):
    owner = model_to_dict(get_object_or_404(AssetOwner, id=asset_owner_id))
    return render(request, 'details-asset-owner.html', { 'owner': owner})


def add_asset_owner_document(request, asset_owner_id):
    if request.method != 'POST':
        return HttpResponse(status=400)

    owner = get_object_or_404(AssetOwner, id=asset_owner_id)
    form = AssetOwnerDocumentForm(request.POST, request.FILES)
    if form.is_valid():
        doc_args = {
            'doctitle': form.cleaned_data['doctitle'],
            'tlp_color': form.cleaned_data['tlp_color'],
            'comments': form.cleaned_data['comments'],
            'owner': request.user,
        }
        if request.FILES:
            # Create /media/ folders if not exists
            if not os.path.exists(MEDIA_ROOT+"/owners_docs"):
                os.makedirs(MEDIA_ROOT+"/owners_docs")
            if not os.path.exists(MEDIA_ROOT+"/owners_docs/"+str(request.user.id)):
                os.makedirs(MEDIA_ROOT+"/owners_docs/"+str(request.user.id))

            myfile = request.FILES['file']
            fs = FileSystemStorage(location=MEDIA_ROOT+"/owners_docs/"+str(request.user.id), base_url=MEDIA_ROOT+"/owners_docs/"+str(request.user.id))
            filename = fs.save(myfile.name, myfile)
            uploaded_file_url = fs.url(filename)
            doc_args.update({
                'filename': filename,
                'filepath': uploaded_file_url
            })

        doc = AssetOwnerDocument(**doc_args)
        doc.save()

        # Add this document to the asset owner
        owner.documents.add(doc)
        owner.save()
        messages.success(request, 'Creation submission successful')

    return redirect('details_asset_owner_view', asset_owner_id=asset_owner_id)


def get_asset_owner_doc(request, asset_owner_doc_id):
    doc = get_object_or_404(AssetOwnerDocument, id=asset_owner_doc_id)
    fp = urllib.unquote(doc.filepath)
    fn = urllib.unquote(doc.filename)

    file_wrapper = FileWrapper(file(fp, 'rb'))
    file_mimetype = mimetypes.guess_type(fp)
    response = HttpResponse(file_wrapper, content_type=file_mimetype )
    response['X-Sendfile'] = fp
    response['Content-Length'] = os.stat(fp).st_size
    response['Content-Disposition'] = 'attachment; filename=%s' % smart_str(fn)
    return response


@csrf_exempt
def edit_asset_owner_comments(request, asset_owner_id):
    new_comments = request.POST.get('new_comments', None)
    if not request.method == "POST" or not new_comments:
        return HttpResponse(status=400)

    owner = get_object_or_404(AssetOwner, id=asset_owner_id)
    owner.comments = new_comments
    owner.save()

    return HttpResponse(status=200)


def add_asset_owner_contact(request, asset_owner_id):
    if request.method != 'POST':
        return HttpResponse(status=400)

    owner = get_object_or_404(AssetOwner, id=asset_owner_id)

    form = AssetOwnerContactForm(request.POST)
    if form.is_valid():
        contact_args = {
            'name': form.cleaned_data['name'],
            'title': form.cleaned_data['title'],
            'email': form.cleaned_data['email'],
            'phone': form.cleaned_data['phone'],
            'address': form.cleaned_data['address'],
            'url': form.cleaned_data['url'],
            'comments': form.cleaned_data['comments'],
            'owner': request.user,
        }

        contact = AssetOwnerContact(**contact_args)
        contact.save()

        # Add this contact to the asset owner
        owner.contacts.add(contact)
        owner.save()
        messages.success(request, 'Creation submission successful')

    return redirect('details_asset_owner_view', asset_owner_id=asset_owner_id)


def delete_asset_owner_contact(request, asset_owner_id):
    if request.method != 'POST':
        return HttpResponse(status=400)

    contact = get_object_or_404(AssetOwnerContact, id=asset_owner_id)
    contact.delete()

    return redirect('details_asset_owner_view', asset_owner_id=asset_owner_id)


def delete_asset_owner_document(request, asset_owner_id):
    doc_id = request.POST.get('doc_id', None)
    if request.method != 'POST' or not doc_id:
        return HttpResponse(status=400)

    document = get_object_or_404(AssetOwnerDocument, id=doc_id)
    document.delete()

    return redirect('details_asset_owner_view', asset_owner_id=asset_owner_id)
