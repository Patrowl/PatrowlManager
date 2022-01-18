# -*- coding: utf-8 -*-

from django import forms
from .models import ScanCampaign, ScanDefinition
from engines.models import EnginePolicy
from assets.models import Asset, AssetGroup, DynamicAssetGroup
from datetimewidget.widgets import DateTimeWidget
from datetime import datetime
engines = []
policies = []
assets = []
scans = []
asset_groups = []

PERIOD_CHOICES = (
    ('days', 'Days'),
    ('hours', 'Hours'),
    ('minutes', 'Minutes'),
    ('seconds', 'Seconds'),
)

SCAN_TYPES = (
    ('single', 'single'),
    ('periodic', 'periodic'),
    ('scheduled', 'scheduled'),
)

dateTimeOptions = {
    'format': 'dd/mm/yyyy HH:ii P',
    'autoclose': True,
    'showMeridian': False,
    #'todayBtn': True
    'todayHighlight': True,
    'minuteStep': 5,
    'pickerPosition': 'bottom-right',
    'clearBtn': True
}


def validate_date(d):
    try:
        datetime.strptime(d, "%Y-%m-%d %H:%M:%f")
        return True
    except ValueError:
        return False


class ScanCampaignForm(forms.ModelForm):
    class Meta:
        model = ScanCampaign
        fields = ['title', 'scan_def_list', 'enabled', 'scheduled_at']

        widgets = {
            'description': forms.Textarea,
            'enabled': forms.CheckboxInput(),
        }

    scan_def_list = forms.CharField(label="Select scans")
    scheduled_at = forms.DateTimeField(required=False, widget=DateTimeWidget(attrs={'id':"id_scheduled_at"}, options=dateTimeOptions, usel10n=True))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(ScanCampaignForm, self).__init__(*args, **kwargs)

        oid = None
        if 'initial' in self.__dict__ and 'owner' in self.initial:
            oid = self.initial['owner_id']

            scans = list(ScanDefinition.objects.filter(owner_id=oid))
            scans = [(str(scan['scan_definition_id']), scan['title']) for scan in scans]
            self.fields['scan_def_list'].widget = forms.CheckboxSelectMultiple(choices=scans)


class ScanDefinitionForm(forms.ModelForm):
    class Meta:
        model = ScanDefinition
        fields = [
            'scan_type', 'title', 'engine', 'engine_policy',
            'description', 'every', 'period', 'enabled', 'scheduled_at',
            'dynassetgroups_list', 'assetgroups_list', 'assets_list'
        ]
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-sm', 'rows': '4'}),
            'enabled': forms.CheckboxInput(attrs={'checked': '', 'class': 'form-control form-control-sm'}),
            # 'scan_team': forms.CheckboxInput(attrs={'checked': '', 'class': 'form-control form-control-sm'}),
            'scheduled_at': DateTimeWidget(attrs={'id': "id_scheduled_at", 'class': 'form-control form-control-sm'}, options=dateTimeOptions)
        }

    scan_type = forms.CharField(widget=forms.Select(choices=SCAN_TYPES, attrs={'class': 'form-control form-control-sm'}))

    def clean(self):
        if 'scheduled_at' in self.data.keys():
            scheduled_at = self.data["scheduled_at"]
            if scheduled_at and not validate_date(scheduled_at):
                raise forms.ValidationError("Bad datetime format")

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(ScanDefinitionForm, self).__init__(*args, **kwargs)

        policies = [(policy.id, policy.name) for policy in EnginePolicy.objects.all().only("name")]
        self.fields['engine_policy'].widget = forms.RadioSelect(choices=policies)

        assets = [(asset.id, asset.value) for asset in Asset.objects.for_user(self.user).all().only('id', 'value')]
        self.fields['assets_list'].widget = forms.CheckboxSelectMultiple(choices=assets)

        assetgroups = [(a.id, a.name) for a in AssetGroup.objects.all().only('id', 'name')]
        self.fields['assetgroups_list'].widget = forms.CheckboxSelectMultiple(choices=assetgroups)

        dynassetgroups = [(a.id, a.name) for a in DynamicAssetGroup.objects.all().only('id', 'name')]
        self.fields['dynassetgroups_list'].widget = forms.CheckboxSelectMultiple(choices=dynassetgroups)
