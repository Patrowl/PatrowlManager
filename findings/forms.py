from django import forms
from .models import Finding, RawFinding, FINDING_SEVERITIES

ENGINE_TYPES = (
    ('json', 'json'),
    ('nessus', 'Nessus'),
)

class ImportFindingsForm(forms.Form):
    class Meta:
        fields = ['engine', 'min_level', 'file']

    engine = forms.CharField(widget=forms.Select(attrs={
    	'class': 'form-control form-control-sm'
    	}, choices=ENGINE_TYPES))
    min_level = forms.CharField(widget=forms.Select(attrs={
    	'class': 'form-control form-control-sm'
    	}, choices=FINDING_SEVERITIES), label='Minium severity')
    file = forms.FileField()

class FindingForm(forms.ModelForm):
	class Meta:
		model = Finding
		fields = ['title', 'asset', 'type', 'confidence', 'severity', 'status',
				 'description', 'solution', 'risk_info', 'vuln_refs', 'links', 'tags', 
				 'found_at', 'comments', 'owner', 'scan']
		widgets = {
			'owner_id': forms.HiddenInput(),
			'description': forms.Textarea(attrs={'class': 'form-control form-control-sm'}),
			'solution': forms.Textarea(attrs={'class': 'form-control form-control-sm'}),
			'risk_info': forms.Textarea(attrs={'class': 'form-control form-control-sm'}),
			'title': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
			'vuln_refs': forms.Textarea(attrs={'class': 'form-control form-control-sm'}),
			'links': forms.Textarea(attrs={'class': 'form-control form-control-sm'}),
			'asset': forms.Select(attrs={'class': 'form-control form-control-sm'}),
			'type': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
			'confidence': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
			'severity': forms.Select(attrs={'class': 'form-control form-control-sm'}),
			'scan': forms.Select(attrs={'class': 'form-control form-control-sm'}),
			'owner': forms.Select(attrs={'class': 'form-control form-control-sm'}),
			'status': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
			'found_at': forms.DateTimeInput(attrs={'class': 'form-control form-control-sm'})
		}

	tags = forms.CharField(widget=forms.TextInput(attrs={"data-role": "tagsinput"}))