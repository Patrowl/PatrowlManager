from django import forms
from .models import Finding, RawFinding


class ImportFindingsForm(forms.Form):
    class Meta:
        fields = ['file']

    file = forms.FileField()
