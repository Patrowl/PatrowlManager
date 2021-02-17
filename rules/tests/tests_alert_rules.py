import json

from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse
from rules.models import AlertRule


class AlertRuleTestCreation(TestCase):
    @classmethod
    def setUp(self):
        self.user = get_user_model().objects.create(
            username='test-alert-rules', email='test-alert-rules@patrowl.io')
        self.client = Client()
        self.listAlertRulesUrl = reverse('alertrule-list')
        self.data = {
            "title": "testAlertRule",
            "comments": "Description for test AlertRule",
            "filters": {"test-filter": 1},
            "actions": {"test-action": 1}
        }

    def test_alertrule_creation(self):
        self.client.force_login(user=self.user)
        response = self.client.post(self.listAlertRulesUrl, json.dumps(
            self.data), content_type='application/json')
        self.assertEqual(response.status_code, 201)

    def test_alertrule_list_json(self):
        self.client.force_login(user=self.user)
        response = self.client.get(self.listAlertRulesUrl, content_type='application/json')
        self.assertEqual(response.status_code, 200)

    def test_alertrule_list_datatables(self):
        self.client.force_login(user=self.user)
        response = self.client.get(self.listAlertRulesUrl+"?format=datatables", content_type='application/json')
        self.assertEqual(response.status_code, 200)


class AlertRuleTestDelete(TestCase):
    @classmethod
    def setUp(self):
        self.user = get_user_model().objects.create(
            username='test-alert-rules', email='test-alert-rules@patrowl.io')
        self.client = Client()
        self.alertrule = AlertRule.objects.create(
            title="test title",
            comments="test comments"
        )
        self.detailAlertRuleUrl = reverse(
            'alertrule-detail', kwargs={'pk': self.alertrule.id})

    def test_alertrule_delete(self):
        self.client.force_login(user=self.user)
        response = self.client.delete(self.detailAlertRuleUrl)
        self.assertEqual(response.status_code, 204)


class AlertRuleTestDuplicate(TestCase):
    @classmethod
    def setUp(self):
        self.user = get_user_model().objects.create(
            username='test-alert-rules', email='test-alert-rules@patrowl.io')
        self.client = Client()
        self.alertrule = AlertRule.objects.create(
            title="test title",
            comments="test comments"
        )
        self.duplicateAlertRuleUrl = reverse(
            'alertrule-duplicate', kwargs={'pk': self.alertrule.id})

    def test_alertrule_duplicate(self):
        self.client.force_login(user=self.user)
        response = self.client.get(self.duplicateAlertRuleUrl)
        self.assertEqual(response.status_code, 200)


class AlertRuleTestDisableAndEnable(TestCase):
    @classmethod
    def setUp(self):
        self.user = get_user_model().objects.create(
            username='test-alert-rules', email='test-alert-rules@patrowl.io')
        self.client = Client()
        self.alertrule = AlertRule.objects.create(
            title="test title",
            comments="test comments",
            enabled=True
        )
        self.disableAlertRuleUrl = reverse(
            'alertrule-disable', kwargs={'pk': self.alertrule.id})
        self.enableAlertRuleUrl = reverse(
            'alertrule-enable', kwargs={'pk': self.alertrule.id})

    def test_engine_instance_disable_and_enable(self):
        alertrule_id = self.alertrule.id
        self.client.force_login(user=self.user)
        response = self.client.get(self.disableAlertRuleUrl)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(AlertRule.objects.get(id=alertrule_id).enabled, False)
        response = self.client.get(self.enableAlertRuleUrl)
        self.assertEqual(AlertRule.objects.get(id=alertrule_id).enabled, True)
