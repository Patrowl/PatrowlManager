# -*- coding: utf-8 -*-
"""Views for alerting rules."""

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view

from .models import Rule
import json


@api_view(['GET'])
def list_rules_api(request):
    """API: List alerting rules."""
    # rules = Rule.objects.all()

    return JsonResponse('todo')


@api_view(['POST'])
def delete_rules_api(request):
    """API: Delete alerting rules."""
    rules_to_delete = request.data
    for rule_id in rules_to_delete:
        rule = get_object_or_404(Rule, id=json.loads(rule_id)[0])
        rule.delete()
        messages.success(request, 'Rule successfully deleted')

    return JsonResponse(
        {'status': 'success'},
        json_dumps_params={'indent': 2}
    )


@api_view(['POST'])
def add_rule_api(request):
    """API: Add an alerting rule."""
    params = request.data
    new_rule_args = {
        "title": params["title"],
        "scope": params["scope"],
        "scope_attr": params["scope_attr"],
        "condition": {params["condition"]: params["criteria"]},
        "enabled": params["enable"] == "enabled",
        "trigger": params["trigger"],
        "target": params["target"],
        "owner": request.user
    }
    new_rule = Rule.objects.create(**new_rule_args)
    new_rule.save()
    messages.success(request, 'Rule successfuly added')

    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


@api_view(['GET'])
def toggle_rule_status_api(request, rule_id):
    """API: Change status of an alerting rule."""
    rule = get_object_or_404(Rule, id=rule_id)
    rule.enabled = not rule.enabled
    rule.save()
    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


@api_view(['GET'])
def duplicate_rule_api(request, rule_id):
    """API: Duplicate an alerting rule."""
    new_rule = get_object_or_404(Rule, id=rule_id)
    new_rule.title = new_rule.title + " (copy)"
    new_rule.pk = None
    new_rule.save()
    return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})


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
#     return JsonResponse({'status': 'success'}, json_dumps_params={'indent': 2})
