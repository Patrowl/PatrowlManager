from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth import login as login_d
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect

from rest_framework import viewsets
from users.serializers import UserSerializer
from users.forms import LoginForm
from assets.models import Asset, AssetGroup
from findings.models import Finding
from scans.models import Scan, ScanCampaign, ScanDefinition
from engines.models import Engine, EnginePolicy, EngineInstance
from reportings.views import homepage_dashboard_view


class UserViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer

@login_required(login_url="login/")
def home(request):
    # get logged user info:
    #
    # ## Assets
    # # OK- total number of assets
    # # OK- number of asset groups
    # # OK- number of assets by criticity
    # # - number of findings by asset
    # assets_stats = {}
    # assets = Asset.objects.filter(owner_id=request.user.id)
    # assets_stats.update({'count': assets.count()})
    # assets_stats.update({'count_low': assets.filter(criticity='low').count()})
    # assets_stats.update({'count_medium': assets.filter(criticity='medium').count()})
    # assets_stats.update({'count_high': assets.filter(criticity='high').count()})
    #
    # asset_groups = AssetGroup.objects.filter(owner_id=request.user.id)
    # assets_stats.update({'countgroups': asset_groups.count()})
    # assets_stats.update({'countgroups_low': asset_groups.filter(criticity='low').count()})
    # assets_stats.update({'countgroups_medium': asset_groups.filter(criticity='medium').count()})
    # assets_stats.update({'countgroups_high': asset_groups.filter(criticity='high').count()})
    #
    # ## Findings
    # # OK- total number of findings
    # # OK- number of findings by criticity
    # findings_stats = {}
    # findings = Finding.objects.filter(owner_id=request.user.id)
    # findings_stats.update({'count': findings.count()})
    # findings_stats.update({'count_info': findings.filter(severity='info').count()})
    # findings_stats.update({'count_low': findings.filter(severity='low').count()})
    # findings_stats.update({'count_medium': findings.filter(severity='medium').count()})
    # findings_stats.update({'count_high': findings.filter(severity='high').count()})
    #
    #
    # ## Scans
    # # OK- total number of scans performed
    # # OK- total number of active periodic scans
    # scans_stats = {}
    # scans = Scan.objects.filter(owner_id=request.user.id)
    # scan_definitions = ScanDefinition.objects.filter(owner_id=request.user.id)
    # scan_campaigns = ScanCampaign.objects.filter(owner_id=request.user.id)
    # scans_stats.update({'count_scans': scans.count()})
    # scans_stats.update({'count_scan_definitions': scan_definitions.count()})
    # scans_stats.update({'count_scan_campaigns': scan_campaigns.count()})
    # scans_stats.update({'count_active_periodic_scans': scan_definitions.filter(enabled=True).count()})
    #
    #
    # ## Engines
    # # OK- total number of engines configured
    # # OK- total number of engine instances configured
    # # - number of active engine instances
    # # - number of policies by engine
    # engines_stats = {}
    # engines = Engine.objects.all()
    # engines_stats.update({"count": engines.count()})
    # engines_stats.update({"names": ", ".join([e.name for e in engines])})

    # return render(request,"home.html", {
    #     'assets': assets_stats,
    #     'findings': findings_stats,
    #     'scans': scans_stats,
    #     'engines': engines_stats,
    #      })
    return redirect(homepage_dashboard_view)

@csrf_exempt
def login(request):
    default_form = LoginForm()
    if request.method == "POST":
        form = LoginForm(request, data=request.POST)
        user = authenticate(request, username=form.data["username"], password=form.data["password"])
        if user is not None:
            if user.is_active:
                login_d(request, user)
                return redirect('homepage_dashboard_view')
            else:
                return render(request, 'login.html', {'form': default_form})
        else:
            return render(request, 'login.html', {'form': default_form})
    else:
        return render(request, 'login.html', {'form': default_form})

@csrf_exempt
def signup(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            raw_password = form.cleaned_data.get('password1')
            user = authenticate(username=username, password=raw_password)
            django.contrib.auth.login(request, user)
            return redirect('homepage_dashboard_view')
    else:
        form = UserCreationForm()
    return render(request, 'signup.html', {'form': form})


def user_details_view(request):
    user = User.objects.get(id=request.user.id)
    return render(request, 'details-user.html', {'user': user})


def list_users_view(request):
    users = User.objects.all()
    return render(request, 'list-users.html', {'users': users})

@csrf_exempt
def add_user_view(request):
    form = None

    if request.method == 'GET':
        form = UserCreationForm()
    elif request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            User.objects.create_user(
                username=form.cleaned_data['username'],
                password=form.cleaned_data['password1']
            )

            messages.success(request, 'Creation submission successful')
            return redirect('list_users_view')

    return render(request, 'add-user.html', {'form': form })
