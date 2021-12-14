# -*- coding: utf-8 -*-

import os
from django import forms
from .models import Finding, FINDING_SEVERITIES

ENGINE_TYPES = (
    ('json', 'json'),
    ('nessus', 'Nessus'),
)


def validate_file_extension(value):
    ext = os.path.splitext(value.name)[1]
    valid_extensions = ['.xml', '.nessus', '.json']
    if ext not in valid_extensions:
        raise ValidationError(u'File not supported!')


class ImportFindingsForm(forms.Form):
    class Meta:
        fields = ['engine', 'min_level', 'file']

    engine = forms.CharField(widget=forms.Select(
        attrs={'class': 'form-control form-control-sm'},
        choices=ENGINE_TYPES))
    min_level = forms.CharField(widget=forms.Select(
        attrs={'class': 'form-control form-control-sm'},
        choices=FINDING_SEVERITIES),
        label='Minimum severity')
    file = forms.FileField(widget=forms.FileInput(
        attrs={'accept': 'text/xml,application/json'}),
        validators=[validate_file_extension]
    )


class FindingForm(forms.ModelForm):
    class Meta:
        model = Finding
        fields = [
            'title', 'type', 'severity', 'status', 'description', 'tags',
            'solution', 'risk_info', 'vuln_refs', 'links', 'comments', 'asset'
        ]
        widgets = {
            'description': forms.Textarea(
                attrs={'class': 'form-control form-control-sm'}),
            'solution': forms.Textarea(
                attrs={'class': 'form-control form-control-sm'}),
            'tags': forms.Textarea(
                attrs={'class': 'form-control form-control-sm'}),
            'risk_info': forms.Textarea(
                attrs={'class': 'form-control form-control-sm'}),
            'title': forms.TextInput(
                attrs={'class': 'form-control form-control-sm'}),
            'vuln_refs': forms.Textarea(
                attrs={'class': 'form-control form-control-sm'}),
            'links': forms.Textarea(
                attrs={'class': 'form-control form-control-sm'}),
            'type': forms.TextInput(
                attrs={'class': 'form-control form-control-sm'}),
            'severity': forms.Select(
                attrs={'class': 'form-control form-control-sm'}),
            'comments': forms.Textarea(
                attrs={'class': 'form-control form-control-sm'}),
            'status': forms.Select(
                attrs={'class': 'form-control form-control-sm'}),
            'asset': forms.Select(
                attrs={'class': 'form-control form-control-sm'})
        }

        #tags = forms.CharField(widget=forms.TextInput(attrs={"data-role": "tagsinput"}))
