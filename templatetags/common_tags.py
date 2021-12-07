from django import template
from django.utils import timezone
from django.contrib.auth import get_user_model
from assets.models import Asset, AssetGroup
from settings.models import Setting
import hashlib

register = template.Library()


@register.filter
def hash(value):
    """Return a 6-chars hash from input."""
    return hashlib.md5(str(value).encode('utf-8')).hexdigest()[:6]


@register.filter
def keyvalue(dict, key):
    """Return the value in a dict using supplied key."""
    if key not in dict.keys():
        return None
    return dict[key]


@register.filter
def attr(objs, attrib):
    """Return the attribute value for an array of object."""
    vals = []
    for obj in objs:
        if hasattr(obj, attrib):
            vals.append(getattr(obj, attrib))
    return vals


@register.filter
def perc(nb, total):
    """Return a percentage."""
    if not str(nb).isdigit():
        return 0
    if total > 0:
        return nb * 100 / float(total)
    else:
        return 0


@register.filter
def smartdate(mydate):
    """Return a formated datetime."""
    if mydate is None:
        return None
    if mydate.date() == timezone.now().date():
        return timezone.localtime(mydate).strftime("%H:%M:%S")
    else:
        return mydate.date().isoformat()


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
    if value:
        return arg.join(value)
    else:
        return ""


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
def nb_private_assets(u):
    """Return the number of private assets (not in team)."""
    if type(u) in [get_user_model()]:
        return Asset.objects.filter(owner=u, teams__isnull=True).count()
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


@register.filter(name='proper_paginate')
def proper_paginate(paginator, current_page, neighbors=8):
    if paginator.num_pages > 2 * neighbors:
        start_index = max(1, current_page - neighbors)
        end_index = min(paginator.num_pages, current_page + neighbors)
        if end_index < start_index + 2 * neighbors:
            end_index = start_index + 2 * neighbors
        elif start_index > end_index - 2 * neighbors:
            start_index = end_index - 2 * neighbors
        if start_index < 1:
            end_index -= start_index
            start_index = 1
        elif end_index > paginator.num_pages:
            start_index -= (end_index - paginator.num_pages)
            end_index = paginator.num_pages
        page_list = [f for f in range(start_index, end_index + 1)]
        return page_list[:(2 * neighbors + 1)]
    return paginator.page_range


@register.filter
def has_role(user, rolename):
    from django.conf import settings

    if settings.PRO_EDITION is False:
        return True

    if user.userrole.role == 1 and rolename.upper() == "MANAGER":
        return True
    elif user.userrole.role == 2 and rolename.upper() == "ANALYST":
        return True
    elif user.userrole.role == 3 and rolename.upper() == "AUDITOR":
        return True

    return False


@register.filter
def is_team_admin(user):
    from django.conf import settings
    if settings.PRO_EDITION is False:
        return True

    from users.models import Team
    is_team_admin = False
    for team in Team.objects.all():
        if team.is_admin(user):
            is_team_admin = True
            break

    return is_team_admin
