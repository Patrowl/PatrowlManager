from django import template
from django.utils import timezone
import hashlib
from assets.models import Asset, AssetGroup
from settings.models import Setting

register = template.Library()


@register.filter
def hash(value):
    """Return a 6-chars hash from input."""
    return hashlib.md5(value).hexdigest()[:6]


@register.filter
def keyvalue(dict, key):
    """Return the value in a dict using supplied key."""
    if key not in dict.keys():
        return None
    return dict[key]


@register.filter
def perc(nb, total):
    """Return a percentage."""
    if not str(nb).isdigit():
        return 0
    if total > 0:
        return nb*100/float(total)
    else:
        return 0


@register.filter
def smartdate(date):
    """Return a formated datetime."""
    if date.date() == timezone.now().date():
        return timezone.localtime(date).strftime("%H:%M:%S")
    else:
        return date.date().isoformat()


@register.filter
def sort_by(queryset, order_args):
    """Return a queryset sorted by supplied args."""
    if isinstance(queryset, set):
        return sorted(queryset)
    if order_args is None:
        return queryset
    orders = [arg.strip() for arg in order_args.split(',')]
    return queryset.order_by(*orders)


@register.filter
def joinby(value, arg):
    """Return the joined strings."""
    return arg.join(value)


@register.filter
def get_time_diff(finish_at, started_at):
    """Return the timedelta betweed 2 dates."""
    if finish_at is None or started_at is None:
        return "-"

    return finish_at - started_at


@register.filter
def risk_score(asset):
    """Return the risk score of an asset."""
    if type(asset) in [Asset, AssetGroup]:
        return asset.get_risk_score()
    else:
        return 0


@register.filter
def get_class(value):
    """Return the class name of input."""
    return value.__class__.__name__


@register.filter
def ref_url(ref, typeref):
    """Return the URL CVE and CWE items found."""
    if typeref == "CVE":
        # CVE-Search links:
        cvesearch_url = ""
        cvesearch_setting_enabled = Setting.objects.filter(
            key="resources.endpoint.cve_search.enable")
        if cvesearch_setting_enabled.count() > 0 and cvesearch_setting_enabled[0].value in [1, "1", "true", "True"]:
            cvesearch_setting_url = Setting.objects.filter(
                key="resources.endpoint.cve_search.baseurl")
            if cvesearch_setting_url.count() > 0:
                cvesearch_url = cvesearch_setting_url[0].value

        if cvesearch_setting_enabled and cvesearch_url != "":
            return "{}{}".format(cvesearch_url, ref)
        else:
            return "https://cve.circl.lu/cve/{}".format(ref)
            # return "https://nvd.nist.gov/vuln/detail/{}".format(ref)

    if typeref == "CWE":
        if ref.startswith("CWE-"):
            cwe_id = ref[len("CWE-"):]
        else:
            cwe_id = ref
        return "https://cwe.mitre.org/data/definitions/{}.html".format(cwe_id)

    if typeref == "CPE":
        return "https://nvd.nist.gov/vuln/search/results?adv_search=true&cpe={}".format(ref)

    return "#"
