from django.test import TestCase, Client
from .models import Engine,EngineInstance
import json

class EngineTestCase(TestCase):
    fixtures = ['tmp/db.json']

    def test_scan_nmap(self):
        print("TEST CASE: test_scan_nmap")
        c = Client()
        post_data = {
            "assets": {
                "addr": "8.8.8.8,8.8.4.4",          # required
                "addr_type": "ipv4",        # optional
                "ports": "53,80,443",       # required
                "ports_type": "None",       # optional
                "base_url": "None"          # optional
            },
            "options": ["no_ping", "no_dns"]       # optional
        }
        c.get('http://localhost:8000/assets/add?value=8.8.8.8')
        c.get('http://localhost:8000/assets/add?value=8.8.4.4')
        r = c.post('http://127.0.0.1:8000/engines/2/startscan',
                   data=json.dumps(post_data),
                   content_type='application/json')

        print(r.json())

    def test_scan_nmap2(self):
        print("TEST CASE: test_scan_nmap2")
        import time, requests

        post_data = {
            "assets": {
                "addr": "8.8.8.8,8.8.4.4",  # required
                "addr_type": "ipv4",        # optional
                "ports": "53,56,80,443",    # required
                "ports_type": "None",           # optional
                "base_url": "None"              # optional
            },
            "options": ["no_ping", "no_dns"]       # optional
        }

        #print(json.dumps(post_data, indent=4, sort_keys=True))

        r = requests.post(url='http://127.0.0.1:5001/engines/nmap/startscan',
                   data=json.dumps(post_data),
                   headers = {'Content-type': 'application/json', 'Accept': 'application/json'})
        print(r.json())
        print(r.json()['details'])
