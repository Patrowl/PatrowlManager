# -*- coding: utf-8 -*-

from django.conf import settings
from django.http import HttpResponseRedirect
from django.contrib import messages
from django.core.files import File
from django.shortcuts import render, redirect, get_object_or_404
from django.db.models import F
from django_celery_beat.models import PeriodicTask
from .models import Engine, EngineInstance, EnginePolicy, EnginePolicyScope
from .forms import EnginePolicyForm, EngineInstanceForm, EngineForm, EnginePolicyImportForm
from common.utils import pro_group_required
import os
import json
import base64


@pro_group_required('EnginesManager', 'EnginesViewer')
def list_engines_view(request):
    engines = EngineInstance.objects.all().only(
        "name", "enabled", "status", "api_url", "updated_at"
    ).annotate(
        type=F("engine__name")
    ).order_by('name')
    autorefresh_task = PeriodicTask.objects.filter(name='[PO] Auto-refresh engines status')
    if autorefresh_task.count() > 0:
        autorefresh_status = autorefresh_task.first().enabled
    else:
        autorefresh_status = False
    return render(request, 'list-scan-engines.html', {
        'engines': engines,
        'autorefresh_status': autorefresh_status
    })


@pro_group_required('EnginesManager')
def add_engine_view(request):
    form = None

    if request.method == 'GET':
        form = EngineInstanceForm()
    elif request.method == 'POST':
        form = EngineInstanceForm(request.POST)

        if form.is_valid():
            engine_args = {
                'engine': form.cleaned_data['engine'],
                'name': form.cleaned_data['name'],
                'api_url': form.cleaned_data['api_url'],
                'enabled': form.cleaned_data['enabled'] is True,
                'authentication_method': form.cleaned_data['authentication_method'],
                'api_key': form.cleaned_data['api_key'],
                'username': form.cleaned_data['username'],
                'password': form.cleaned_data['password'],
            }

            engine = EngineInstance(**engine_args)
            engine.save()
            messages.success(request, 'Creation submission successful')
            return redirect('list_engines_view')

    return render(request, 'add-scan-engine.html', {'form': form})


@pro_group_required('EnginesManager')
def delete_engine_view(request, engine_id):
    engine = get_object_or_404(EngineInstance, id=engine_id)

    if request.method == 'POST':
        engine.delete()
        messages.success(request, 'Engine successfully deleted!')
        return redirect('list_engines_view')

    return render(request, 'delete-scan-engine.html', {'engine': engine})


@pro_group_required('EnginesManager')
def edit_engine_view(request, engine_id):
    engine = get_object_or_404(EngineInstance, id=engine_id)
    form = EngineInstanceForm()

    if request.method == 'GET':
        form = EngineInstanceForm(instance=engine)
    elif request.method == 'POST':
        form = EngineInstanceForm(request.POST, instance=engine)
        if form.is_valid():
            engine.engine = form.cleaned_data['engine']
            engine.name = form.cleaned_data['name']
            engine.api_url = form.cleaned_data['api_url']
            engine.enabled = form.cleaned_data['enabled'] is True
            engine.authentication_method = form.cleaned_data['authentication_method']
            engine.api_key = form.cleaned_data['api_key']
            engine.username = form.cleaned_data['username']
            engine.password = form.cleaned_data['password']
            engine.save()
            messages.success(request, 'Update submission successful')
            return redirect('list_engines_view')

    return render(request, 'edit-scan-engine.html', {
        'form': form,
        'engine_id': engine.id
    })


@pro_group_required('EnginePoliciesManager', 'EnginePoliciesViewer')
def list_policies_view(request):
    policies = EnginePolicy.objects.all().prefetch_related("scopes").annotate(
        type=F("engine__name")
    ).order_by("type", "name")
    return render(request, 'list-engine-policies.html', {'policies': policies})


@pro_group_required('EnginePoliciesManager')
def import_policies_view(request):
    if request.method == 'GET':
        form = EnginePolicyImportForm()
    elif request.method == 'POST':
        form = EnginePolicyImportForm(request.POST, request.FILES)
        if form.is_valid():
            # store the file in /media/imports/<owner_id>/<tmp_file>
            policies_path = settings.MEDIA_ROOT + "/policies/_imports/"
            if not os.path.exists(policies_path):
                os.makedirs(policies_path)

            # policies_file = policies_path + request.FILES['file'].name
            policies_file = os.path.normpath(os.path.join(policies_path, request.FILES['file'].name))
            with open(policies_file, 'wb') as destfile:
                for chunk in request.FILES['file'].chunks():
                    destfile.write(chunk)
            destfile.close()

            destfile = open(policies_file).read()
            ep_fields = ['description', 'scope_names', 'name', 'engine_name', 'options', 'file']

            for policy in json.loads(destfile)['policies']:
                # check if all keys are set
                if not set(ep_fields).issubset(policy.keys()):
                    messages.error(request, 'Error: missing args in policy "{}".'.format(policy['name']))
                    continue

                # check if engine_name exists
                if not Engine.objects.filter(name__iexact=policy['engine_name']):
                    messages.error(request, 'Error: policy "{}" defines an unknown engine ("{}").'.format(
                        policy['name'], policy['engine_name']))
                    continue

                # check if scope names exist
                has_error = False
                for scope in policy['scope_names']:
                    if not EnginePolicyScope.objects.filter(name__iexact=scope):
                        messages.error(request, 'Error: policy "{}" defines an unknown engine scope ("{}").'.format(policy['name'], scope))
                        has_error = True
                        continue
                if has_error:
                    continue

                # check if policy_name exists
                if EnginePolicy.objects.filter(name__iexact=policy['name']):
                    messages.error(request, 'Error: policy "{}" defines already exists (name check).'.format(policy['name']))
                    continue

                # All is OK: create new engine policy
                new_policy = EnginePolicy(
                    name=policy['name'],
                    description=policy['description'],
                    options=policy['options'],
                    engine=Engine.objects.get(name__iexact=policy['engine_name']),
                    owner=request.user,
                    default=False,
                    is_default=False
                )
                new_policy.save()
                for scope in policy['scope_names']:
                    new_policy.scopes.add(EnginePolicyScope.objects.get(name__iexact=scope))

                if policy["file"]:
                    # decode the file and store it in the right folder
                    fp_policy = settings.MEDIA_ROOT + "/policies/" + policy["engine_name"].upper() + "/"  # + str(request.user.id)
                    if not os.path.exists(fp_policy):
                        os.makedirs(fp_policy)
                    fp_policy_engine = fp_policy + str(request.user.id)
                    if not os.path.exists(fp_policy_engine):
                        os.makedirs(fp_policy_engine)
                    fh = open(settings.MEDIA_ROOT + "/policies/" + policy["engine_name"].upper() + "/" + str(request.user.id) + "/" + policy["file"]["filename"], "wb")
                    fh.write(base64.b64decode(policy["file"]["content"]))
                    fh.close()

                    # assign it to the new policy object
                    fh = open(settings.MEDIA_ROOT + "/policies/" + policy["engine_name"].upper() + "/" + str(request.user.id) + "/" + policy["file"]["filename"])
                    new_policy.file.save(policy["file"]["filename"], File(fh))
                    fh.close()

                new_policy.save()
                messages.success(request, 'policy "{}" successfully imported.'.format(policy["name"]))
            return redirect('list_policies_view')

    return render(request, 'import-engine-policies.html', {'form': form})


@pro_group_required('EnginePoliciesManager')
def add_policy_view(request):
    form = None

    if request.method == 'GET':
        form = EnginePolicyForm()
    elif request.method == 'POST':
        form = EnginePolicyForm(request.POST, request.FILES)

        if form.is_valid():
            policy_args = {
                'engine': form.cleaned_data['engine'],
                'name': form.cleaned_data['name'],
                'description': form.cleaned_data['description'],
                'options': form.cleaned_data['options'],
                'owner': request.user,
            }

            policy = EnginePolicy(**policy_args)
            if request.FILES:
                policy.file = request.FILES['file']
            policy.save()
            policy.scopes.set(form.cleaned_data['scopes'])
            policy.save()
            messages.success(request, 'Creation submission successful')
            return HttpResponseRedirect('list')

    return render(request, 'add-engine-policy.html', {'form': form})


@pro_group_required('EnginePoliciesManager')
def edit_policy_view(request, policy_id):
    policy = get_object_or_404(EnginePolicy, id=policy_id)
    form = EnginePolicyForm()

    if request.method == 'GET':
        form = EnginePolicyForm(None, instance=policy)
    elif request.method == 'POST':
        form = EnginePolicyForm(request.POST, request.FILES)
        if form.is_valid():
            policy.engine = form.cleaned_data['engine']
            policy.name = form.cleaned_data['name']
            policy.description = form.cleaned_data['description']
            # policy.scopes = form.cleaned_data['scopes']
            policy.is_default = form.cleaned_data['is_default'] is True
            policy.default = form.cleaned_data['is_default'] is True
            policy.status = "active"
            policy.options = form.cleaned_data['options']

            if 'file-clear' in form.data.keys() and form.data['file-clear'] == 'on':
                if policy.file.name and os.path.isfile(policy.file.path):
                    os.remove(policy.file.path)
                    policy.file = None
            if request.FILES:
                policy.file = request.FILES['file']

            policy.save()
            policy.scopes.set(form.cleaned_data['scopes'])
            policy.save()
            messages.success(request, 'Update submission successful')
            return redirect('list_policies_view')

    return render(request, 'edit-engine-policy.html', {
        'form': form,
        'policy_id': policy.id
    })


@pro_group_required('EnginesManager', 'EnginesViewer')
def list_engine_types_view(request):
    engines = Engine.objects.all().exclude(name__in=["MANUAL", "SKELETON"]).prefetch_related("engineinstance_set").order_by("name")
    for eng in engines:
        if eng.allowed_asset_types:
            eng.allowed_asset_types = ", ".join(eval(eng.allowed_asset_types))
    return render(request, 'list-engines.html', {'engines': engines})


@pro_group_required('EnginesManager', 'EnginesViewer')
def add_engine_types_view(request):
    form = None

    if request.method == 'GET':
        form = EngineForm()
    elif request.method == 'POST':
        form = EngineForm(request.POST)
        if form.is_valid():
            engine_args = {
                'name': form.cleaned_data['name'],
                'description': form.cleaned_data['description'],
                'allowed_asset_types': form.data.getlist('allowed_asset_types')
            }

            engine = Engine(**engine_args)
            engine.save()
            messages.success(request, 'Creation submission successful')
            return redirect('list_engine_types_view')

    return render(request, 'add-engine.html', {'form': form})


@pro_group_required('EnginesManager', 'EnginesViewer')
def edit_engine_type_view(request, engine_id):
    engine = get_object_or_404(Engine, id=engine_id)
    form = None

    if request.method == 'GET':
        form = EngineForm(instance=engine, initial={
            'allowed_asset_types': eval(engine.allowed_asset_types)
        })
    elif request.method == 'POST':
        form = EngineForm(request.POST, instance=engine)
        if form.is_valid():
            engine.name = form.cleaned_data['name']
            engine.description = form.cleaned_data['description']
            engine.save()
            messages.success(request, 'Update submission successful')
            return redirect('list_engine_types_view')

    return render(request, 'edit-engine.html', {
        'form': form,
        'engine_id': engine.id
    })


@pro_group_required('EnginesManager', 'EnginesViewer')
def delete_engine_type_view(request, engine_id):
    engine = get_object_or_404(Engine, id=engine_id)

    if request.method == 'POST':
        engine.delete()
        messages.success(request, 'Engine type successfully deleted!')
        return redirect('list_engine_types_view')

    return render(request, 'delete-engine.html', {'engine': engine})
