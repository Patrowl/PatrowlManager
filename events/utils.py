from .models import Alert
from findings.models import Finding
from assets.models import Asset


def new_finding_alert(finding_id, scan_id, severity="info"):
    finding = Finding.objects.filter(id=finding_id, status="new").first()
    if finding is None:
        return None

    # Set default severity
    if severity not in ['info', 'low', 'medium', 'high', 'critical']:
        severity = 'info'

    asset_id = None
    asset = Asset.objects.filter(value=finding.asset_name).first()
    if asset is not None:
        asset_id = asset.id

    alert = Alert.objects.create(
        message="New finding",
        status='new',
        severity=severity,
        metadata={
            "finding_id": finding.id,
            "finding_title": finding.title,
            "scan_id": scan_id,
            "asset_name": finding.asset_name,
            "asset_id": asset_id
        },
        owner=finding.owner
    )
    if finding.asset.teams.count() > 0:
        for team in finding.asset.teams.all():
            alert.teams.add(team)
        alert.save()

    return alert


def missing_finding_alert(finding_id, scan_id, severity="info"):
    finding = Finding.objects.filter(id=finding_id).first()
    if finding is None:
        return None

    # Set default severity
    if severity not in ['info', 'low', 'medium', 'high', 'critical']:
        severity = 'info'

    asset_id = None
    asset = Asset.objects.filter(value=finding.asset_name).first()
    if asset is not None:
        asset_id = asset.id

    alert = Alert.objects.create(
        message="Missing finding",
        status='new',
        severity=severity,
        metadata={
            "finding_id": finding.id,
            "finding_title": finding.title,
            "scan_id": scan_id,
            "asset_name": finding.asset_name,
            "asset_id": asset_id
        },
        owner=finding.owner
    )
    if finding.asset.teams.count() > 0:
        for team in finding.asset.teams.all():
            alert.teams.add(team)
        alert.save()
    return alert


def reopened_finding_alert(finding_id, scan_id, severity="info"):
    finding = Finding.objects.filter(id=finding_id).first()
    if finding is None:
        return None

    # Set default severity
    if severity not in ['info', 'low', 'medium', 'high', 'critical']:
        severity = 'info'

    asset_id = None
    asset = Asset.objects.filter(value=finding.asset_name).first()
    if asset is not None:
        asset_id = asset.id

    alert = Alert.objects.create(
        message="Finding reopened. Considered as closed but a recent scan found it again",
        status='new',
        severity=severity,
        metadata={
            "finding_id": finding.id,
            "finding_title": finding.title,
            "scan_id": scan_id,
            "asset_name": finding.asset_name,
            "asset_id": asset_id
        },
        owner=finding.owner
    )
    if finding.asset.teams.count() > 0:
        for team in finding.asset.teams.all():
            alert.teams.add(team)
        alert.save()
    return alert
