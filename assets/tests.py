from django.test import TestCase, Client


class AssetTestCase(TestCase):

    def add_asset_test(self):
        print("TEST CASE: add_asset_test")
        c = Client()

        print("TEST CASE: testing with GET method")
        r = c.get('http://127.0.0.1:8000/assets/add?value=testingasset')
        print(r.json())

        print("TEST CASE: testing with POST method")
        r = c.post('http://127.0.0.1:8000/assets/add', {
            "value": "8.8.8.8",
            "name": "DNS Google (A)",
            "type": "ipv4",
            "owner": "nicolas",
            "description": "Google DNS Server",
            "status": "up"
        })
        print(r.json())
