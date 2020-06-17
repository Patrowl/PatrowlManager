# -*- coding: utf-8 -*-

from django.test import TestCase, Client


class FindingTestCase(TestCase):
    # fixtures = ['tmp/db.json']

    def add_finding_test(self):
        print("TEST CASE: add_finding_test")
        c = Client()

        print("TEST CASE: testing with GET method")
        r = c.get('http://127.0.0.1:8000/findings/add?title=testing')
        print(r.json())


        print("TEST CASE: testing with POST method")
        r = c.post('http://127.0.0.1:8000/findings/add', {
            "asset_id": "1",
            "title": "Open port TCP/80",
            "type": "open_ports",
            "confidence": "certain",
            "severity": "info",
            "status": "new",
            "engine_type": "nmap"
        })
        print(r.json())
