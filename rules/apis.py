# -*- coding: utf-8 -*-
"""Views for alerting rules."""

from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.forms.models import model_to_dict
from django.contrib import messages
from rest_framework.decorators import api_view
from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from events.models import AuditLog
from common.utils.pagination import StandardResultsSetPagination
from rest_framework_datatables.pagination import DatatablesPageNumberPagination
from rest_framework_datatables.pagination import DatatablesLimitOffsetPagination
from rest_framework_datatables.filters import DatatablesFilterBackend
from .models import Rule, AlertRule
from .serializers import AlertRuleSerializer
import json


class AlertRuleSet(viewsets.ModelViewSet):
    """API endpoint that allows engines to be viewed or edited."""

    serializer_class = AlertRuleSerializer
    queryset = AlertRule.objects.all().order_by('title')
    pagination_class = StandardResultsSetPagination
    # pagination_class = DatatablesPageNumberPagination
    # pagination_class = DatatablesLimitOffsetPagination
    filter_backends = [DatatablesFilterBackend]
    permission_classes = [IsAuthenticated]

    def list(self, request, *args, **kwargs):
        if 'iDisplayLength' in request.GET:
            if not request.GET._mutable:
                request.GET._mutable = True
            request.GET['limit'] = request.GET['iDisplayLength']
            request.GET['page'] = int(request.GET.get('iDisplayStart', 0))+1
        return super().list(request, *args, **kwargs)  # you should return them

    def enable(self, *args, **kwargs):
        instance = self.get_object()
        instance.enabled = True
        instance.save()
        response = Response()
        response['status'] = "success"
        return response

    def disable(self, *args, **kwargs):
        instance = self.get_object()
        instance.enabled = False
        instance.save()
        response = Response()
        response['status'] = "success"
        return response

    def duplicate(self, *args, **kwargs):
        new_rule = get_object_or_404(AlertRule, id=self.get_object().id)
        new_rule.title = new_rule.title + " (copy)"
        new_rule.pk = None
        new_rule.save()
        response = Response()
        response['status'] = "success"
        response['data'] = {
            "id": new_rule.id
        }
        return response


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
    new_rule_args = {
        "title": params["title"],
        "scope": params["scope"],
        "scope_attr": params["scope_attr"],
        "condition": {params["condition"]: params["criteria"]},
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
