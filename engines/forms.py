# -*- coding: utf-8 -*-

from django import forms
from .models import EnginePolicy, Engine, EngineInstance
from assets.models import ASSET_TYPES


class EnginePolicyForm(forms.ModelForm):
    class Meta:
        model = EnginePolicy
        fields = ['engine', 'name', 'description', 'options', 'file',
                  'is_default', 'scopes']
        widgets = {
            'owner_id': forms.HiddenInput(),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-sm'}),
            'options': forms.Textarea(attrs={'class': 'form-control form-control-sm'}),
            'scopes': forms.CheckboxSelectMultiple(),
            'name': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'engine': forms.Select(attrs={'class': 'form-control form-control-sm'})
        }
        #scopes = forms.ModelMultipleChoiceField(queryset=EnginePolicyScope.objects.all(), widget=forms.CheckboxSelectMultiple(), required=False)
        is_default = forms.BooleanField(widget=forms.CheckboxInput(), initial=False, required=False)


class EnginePolicyImportForm(forms.Form):
    class Meta:
        fields = ['file']

    file = forms.FileField()


engines = []


class EngineInstanceForm(forms.ModelForm):
    class Meta:
        model = EngineInstance
        fields = ['engine', 'name', 'api_url', 'enabled',
                  'authentication_method', 'api_key', 'username', 'password']
        widgets = {
            'enabled': forms.CheckboxInput(),
            'api_url': forms.URLInput(attrs={
                'class': 'form-control form-control-sm',
                'value': 'https://engine_ip:50xx/engines/<engine_name>/'}),
            'password': forms.PasswordInput(attrs={'class': 'form-control form-control-sm'}),
            'username': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'name': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'api_key': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'authentication_method': forms.Select(attrs={'class': 'form-control form-control-sm'})
        }

    def __init__(self, *args, **kwargs):
        super(EngineInstanceForm, self).__init__(*args, **kwargs)

        if 'initial' in self.__dict__:
            # Autocomple the list of engine types available
            engines = list(Engine.objects.exclude(name__in=['MANUAL', 'SKELETON']).values('name', 'id').order_by('name'))
            engines = [(engine['id'], engine['name']) for engine in engines]
            self.fields['engine'].widget = forms.Select(choices=engines, attrs={'class': 'form-control form-control-sm'})


class EngineForm(forms.ModelForm):
    class Meta:
        model = Engine
        fields = ['name', 'description', 'allowed_asset_types']

        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-sm'}),
        }

    def __init__(self, *args, **kwargs):
        super(EngineForm, self).__init__(*args, **kwargs)

        if 'initial' in self.__dict__:
            self.fields['allowed_asset_types'].widget = forms.CheckboxSelectMultiple(choices=ASSET_TYPES)
