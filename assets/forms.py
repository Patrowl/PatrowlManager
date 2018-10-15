from django import forms
from .models import Asset, AssetGroup, AssetOwner, AssetOwnerContact, AssetOwnerDocument, AssetCategory
from .models import TLP_COLORS, ASSET_TYPES, ASSET_CRITICITIES

assets = []


def get_child_dict_recursive(elem):
    if not elem.is_leaf_node():
        children = AssetCategory.objects.filter(parent=elem)
        child_dict = dict()
        for child in children:
            child_dict[child.id] = get_child_dict_recursive(child)
        return child_dict
    return elem.value


def recursive_dict_to_tuple(dict_obj):
    items = list()
    if isinstance(dict_obj, dict):
        for dict_obj_key,dict_item in dict_obj.items():
            tuple_item = tuple()
            if isinstance(dict_item, dict):
                tuple_item = tuple(((key, recursive_dict_to_tuple(value)) for key,value in dict_item.items()))
                tuple_item = ((dict_obj_key, dict_obj_key), ) + tuple_item
                items.append((dict_obj_key, tuple_item))
            else:
                items.append((dict_item, dict_item))
    else:
        return dict_obj
    return tuple(items)


class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ['id', 'value', 'name', 'type', 'description', 'criticity', 'categories']
        widgets = {
            'id': forms.HiddenInput(),
            'value': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'name': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-sm', 'rows': '4'}),
            'categories': forms.SelectMultiple(attrs={'class': 'form-control form-control-sm', 'size': '10'})
        }

    type = forms.CharField(widget=forms.Select(choices=ASSET_TYPES, attrs={'class': 'form-control form-control-sm'}))
    criticity = forms.CharField(widget=forms.Select(choices=ASSET_CRITICITIES, attrs={'class': 'form-control form-control-sm'}))

    def __init__(self, *args, **kwargs):
        super(AssetForm, self).__init__(*args, **kwargs)

        roots = AssetCategory.objects.filter(parent=None)
        tree = dict()
        for root in roots:
            tree[root.value] = get_child_dict_recursive(root)

        self.fields['categories'].widget.choices = recursive_dict_to_tuple(tree)

        # disable the value update (/!\ still bypassable)
        if self.initial != {} and 'value' in self.initial.keys():
            self.fields['value'].widget.attrs['readonly'] = True


class AssetBulkForm(forms.Form):
    owner_id = forms.HiddenInput()
    file = forms.CharField(widget=forms.FileInput())


class AssetGroupForm(forms.ModelForm):
    class Meta:
        model = AssetGroup
        fields = ['id', 'name', 'description', 'criticity', 'assets', 'categories']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control form-control-sm'}),
            'description': forms.Textarea(attrs={'class': 'form-control form-control-sm', 'rows': '4'}),
            'categories': forms.SelectMultiple(attrs={'class': 'form-control form-control-sm'}),
        }

    criticity = forms.CharField(widget=forms.Select(choices=ASSET_CRITICITIES, attrs={'class': 'form-control form-control-sm'}))

    def __init__(self, *args, **kwargs):
        super(AssetGroupForm, self).__init__(*args, **kwargs)

        assets = [(asset.id, asset.value) for asset in Asset.objects.all()]
        self.fields['assets'].widget = forms.CheckboxSelectMultiple(choices=assets)


class AssetOwnerForm(forms.ModelForm):
    class Meta:
        model = AssetOwner
        fields = ['name', 'assets', 'comments', 'url']
        widgets = {
            'comments': forms.Textarea
        }

    url = forms.URLField(required=False)

    def __init__(self, *args, **kwargs):
        super(AssetOwnerForm, self).__init__(*args, **kwargs)

        assets = [(asset.id, asset.value) for asset in Asset.objects.all()]
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
                  'address', 'url' , 'comments']
        widgets = {
            'comments': forms.Textarea
        }
        priority = forms.CharField(widget=forms.Select(choices=((1,1), (2,2))))

    def __init__(self, *args, **kwargs):
        super(AssetOwnerContactForm, self).__init__(*args, **kwargs)
