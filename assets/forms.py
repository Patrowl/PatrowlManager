# -*- coding: utf-8 -*-

from django import forms
from django.conf import settings
from .models import Asset, AssetGroup, AssetOwner, AssetOwnerContact, AssetOwnerDocument
from .models import TLP_COLORS, ASSET_TYPES, ASSET_CRITICITIES
from users.models import Team

assets = []


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ['id', 'value', 'name', 'type', 'description', 'criticity', 'categories', 'teams']
        widgets = {
            'id': forms.HiddenInput(),
            'value': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'name': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-sm', 'rows': '4'}),
            'categories': forms.SelectMultiple(attrs={'class': 'form-control form-control-sm', 'size': '4'}),
            'teams': forms.SelectMultiple(attrs={'class': 'form-control form-control-sm', 'size': '4'})
        }

    type = forms.CharField(widget=forms.Select(choices=ASSET_TYPES, attrs={'class': 'form-control form-control-sm'}))
    criticity = forms.CharField(widget=forms.Select(choices=ASSET_CRITICITIES, attrs={'class': 'form-control form-control-sm'}))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(AssetForm, self).__init__(*args, **kwargs)

        # Check allowed teams (Available in Pro Edition)
        if settings.PRO_EDITION and not self.user.is_superuser:
            # List related TeamUsers
            self.fields['teams'].queryset = Team.objects.filter(organization_users__in=self.user.users_teamuser.all()).order_by('name')
        if settings.PRO_EDITION and self.user.is_superuser:
            # List related TeamUsers
            self.fields['teams'].queryset = Team.objects.order_by('name')
        # disable the value update (/!\ still bypassable)
        if self.initial != {} and 'value' in self.initial.keys():
            self.fields['value'].widget.attrs['readonly'] = True


class AssetBulkForm(forms.Form):
    owner_id = forms.HiddenInput()
    file = forms.CharField(widget=forms.FileInput())


class AssetGroupForm(forms.ModelForm):
    class Meta:
        model = AssetGroup
        fields = ['id', 'name', 'description', 'criticity', 'assets', 'categories', 'teams']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-sm', 'rows': '4'}),
            'categories': forms.SelectMultiple(attrs={'class': 'form-control form-control-sm'}),
            'teams': forms.SelectMultiple(attrs={'class': 'form-control form-control-sm', 'size': '4'})
        }

    criticity = forms.CharField(widget=forms.Select(choices=ASSET_CRITICITIES, attrs={'class': 'form-control form-control-sm'}))

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(AssetGroupForm, self).__init__(*args, **kwargs)

        # @Todo: RBAC_CHECK
        assets = [(asset.id, asset.value) for asset in Asset.objects.for_user(self.user).all().order_by('value')]
        self.fields['assets'].widget = forms.CheckboxSelectMultiple(choices=assets)

        # Check allowed teams (Available in Pro Edition)
        if settings.PRO_EDITION and not self.user.is_superuser:
            # List related TeamUsers
            self.fields['teams'].queryset = Team.objects.filter(organization_users__in=self.user.users_teamuser.all())


class AssetOwnerForm(forms.ModelForm):
    class Meta:
        model = AssetOwner
        fields = ['name', 'assets', 'comments', 'url']
        widgets = {
            'comments': forms.Textarea
        }

    url = forms.URLField(required=False)

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super(AssetOwnerForm, self).__init__(*args, **kwargs)

        assets = [(asset.id, asset.value) for asset in Asset.objects.for_user(self.user).all()]
        self.fields['assets'].widget = forms.CheckboxSelectMultiple(choices=assets)


class AssetOwnerDocumentForm(forms.ModelForm):
    class Meta:
        model = AssetOwnerDocument
        fields = ['doctitle', 'tlp_color', 'comments']
        widgets = {
            'comments': forms.Textarea
        }
        tlp_color = forms.CharField(widget=forms.Select(choices=TLP_COLORS))
        file = forms.FileField(widget=forms.ClearableFileInput(attrs={'multiple': False}))

    def __init__(self, *args, **kwargs):
        super(AssetOwnerDocumentForm, self).__init__(*args, **kwargs)


class AssetOwnerContactForm(forms.ModelForm):
    class Meta:
        model = AssetOwnerContact
        fields = ['name', 'department', 'title', 'email', 'phone',
                  'address', 'url', 'comments']
        widgets = {
            'comments': forms.Textarea
        }
        priority = forms.CharField(widget=forms.Select(choices=((1, 1), (2, 2))))

    def __init__(self, *args, **kwargs):
        super(AssetOwnerContactForm, self).__init__(*args, **kwargs)
