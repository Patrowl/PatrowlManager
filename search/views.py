# -*- coding: utf-8 -*-

from django.shortcuts import render
from django.db.models import Q
from assets.models import Asset, AssetGroup, AssetOwner, AssetOwnerContact, AssetOwnerDocument
from engines.models import Engine, EnginePolicy
from scans.models import ScanDefinition
from findings.models import Finding


def _search(kw):
    results = []

    # search by asset value or description
    for asset in Asset.objects.filter(
        Q(value__icontains=kw) | Q(description__icontains=kw) | Q(name__icontains=kw) | Q(categories__value__icontains=kw)):
        results.append({"type": "asset", "value": asset.value, "id": asset.id, "link": "/assets/details/"+str(asset.id)})

    # search by asset group name or description
    for asset_group in AssetGroup.objects.filter(
        Q(description__icontains=kw) | Q(name__icontains=kw) | Q(categories__value__icontains=kw)):
        results.append({"type": "asset_group", "value": asset_group.name, "id": asset_group.id, "link": "/assets/groups/details/"+str(asset_group.id)})

    # search by asset owner name, url or comments
    for asset_owner in AssetOwner.objects.filter(Q(name__icontains=kw) | Q(url__icontains=kw) | Q(comments__icontains=kw)):
        results.append({"type": "asset_owner", "value": asset_owner.name, "id": asset_owner.id, "link": "/assets/owners/details/"+str(asset_owner.id)})

    # search by asset owner contacts name, info
    for asset_owner_contact in AssetOwnerContact.objects.filter(
        Q(name__icontains=kw) | Q(department__icontains=kw) | Q(title__icontains=kw) | Q(url__icontains=kw) | Q(comments__icontains=kw)):
        results.append({"type": "asset_owner_contact", "value": asset_owner_contact.name, "id": asset_owner_contact.id, "link": "/assets/owners/list"})

    # search by asset document doctitle or comments
    for asset_owner_doc in AssetOwnerDocument.objects.filter(Q(doctitle__icontains=kw) | Q(comments__icontains=kw)):
        results.append({"type": "asset_owner_doc", "value": asset_owner_doc.name, "id": asset_owner_doc.id})

    # search by engine name or description
    for engine in Engine.objects.filter(Q(name__icontains=kw) | Q(description__icontains=kw)):
        results.append({"type": "engine", "value": engine.name, "id": engine.id, "link": "/engines/edit/"+str(engine.id)})

    # search by engine policy name or description
    for engine_policy in EnginePolicy.objects.filter(
        Q(name__icontains=kw) | Q(description__icontains=kw) | Q(options__icontains=kw)):# | Q(engine__name__icontains=kw) | Q(scopes__name__icontains=kw)):
        results.append({"type": "engine_policy", "value": engine_policy.name, "id": engine_policy.id, "link": "/engines/policies/edit/"+str(engine_policy.id)})

    # search on scan name or description
    for scan in ScanDefinition.objects.filter(
        Q(title__icontains=kw) | Q(description__icontains=kw)):
        results.append({"type": "scan_definition", "value": scan.title, "id": scan.id, "link": "/scans/defs/details/"+str(scan.id)})

    # search on findings title, type, references
    for finding in Finding.objects.filter(
        Q(title__icontains=kw) | Q(description__icontains=kw) | Q(type__icontains=kw) | Q(solution__icontains=kw) | Q(vuln_refs__icontains=kw) | Q(links__icontains=kw) | Q(tags__icontains=kw)):
        results.append({"type": "finding", "value": finding.title, "id": finding.id, "link": "/findings/details/"+str(finding.id)})

    return results


def search_view(request):
    kw = request.GET.get('srch-term', None)

    if not kw:
        return render(request, 'search-results.html', {'results': []})

    results = _search(kw)
    return render(request, 'search-results.html', {'results': results, 'search_term': kw})
