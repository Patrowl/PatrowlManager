# -*- coding: utf-8 -*-
"""Views for alerting rules."""

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.forms.models import model_to_dict
from django.contrib import messages
from rest_framework.decorators import api_view
from events.models import AuditLog
from .models import Rule
import json


@api_view(['GET'])
def list_alerting_rules_api(request):
    """API: List alerting rules."""
    rules = []
    for rule in Rule.objects.all():
        rules.append(model_to_dict(rule))
    return JsonResponse(rules, safe=False)


@api_view(['GET'])
def get_alerting_rule_api(request, rule_id):
    """API: Return alerting rule."""
    rule = get_object_or_404(Rule, id=rule_id)
    return JsonResponse(model_to_dict(rule), safe=False)


@api_view(['POST'])
def delete_rules_api(request):
    """API: Delete alerting rules."""
    rules_to_delete = request.data
    for rule_id in rules_to_delete:
        rule = get_object_or_404(Rule, id=json.loads(rule_id)[0])
        rule.delete()
        messages.success(request, 'Rule successfully deleted')
    return JsonResponse({'status': 'deleted'})


@api_view(['DELETE'])
def delete_rule_api(request, rule_id):
    """API: Delete alerting rule."""
    rule = get_object_or_404(Rule, id=rule_id)
    rule.delete()
    return JsonResponse({'status': 'deleted'})


@api_view(['POST'])
def add_rule_api(request):
    """API: Add an alerting rule."""
    params = request.data

    if params["condition"] == "custom":
        cond = str(params["criteria"])
    else:
        cond = {params["condition"]:params["criteria"]}

    new_rule_args = {
        "title": params["title"],
        "scope": params["scope"],
        "scope_attr": params["scope_attr"],
        "condition": cond,
        "enabled": params["enable"] == "enabled",
        "severity": params["severity"],
        "trigger": params["trigger"],
        "target": params["target"],
        "owner": request.user
    }
    new_rule = Rule.objects.create(**new_rule_args)
    new_rule.save()
    return JsonResponse({'status': 'success'})


@api_view(['GET'])
def toggle_rule_status_api(request, rule_id):
    """API: Change status of an alerting rule."""
    rule = get_object_or_404(Rule, id=rule_id)
    rule.enabled = not rule.enabled
    rule.save()
    AuditLog.objects.create(
        message="Rule '{}' status toggled to '{}'".format(rule, rule.enabled),
        scope='rule', type='rule_toggle_status', owner=request.user,
        context=request)
    return JsonResponse({'status': 'success'})


@api_view(['GET'])
def duplicate_rule_api(request, rule_id):
    """API: Duplicate an alerting rule."""
    new_rule = get_object_or_404(Rule, id=rule_id)
    new_rule.title = new_rule.title + " (copy)"
    new_rule.pk = None
    new_rule.save()
    return JsonResponse({'status': 'success', 'id': new_rule.id})


# @api_view(['GET'])
# def send_slack_message_api(request):  # test purposes
#     """API: Send a Slack message."""
#     slack_url = get_object_or_404(Setting, key="alerts.endpoint.slack.webhook")
#     alert_message = "[Alert] This is a test message"
#
#     requests.post(
#         slack_url.value,
#         data=json.dumps({'text': alert_message}),
#         headers={'content-type': 'application/json'})
#     return JsonResponse({'status': 'success'})
