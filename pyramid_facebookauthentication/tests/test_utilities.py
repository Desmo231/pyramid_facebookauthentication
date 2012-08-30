# test_utilities.py
import unittest, re
from ludibrio import Stub
import simplejson as json
from pyramid_facebookauthentication import FacebookAuthenticationPolicy
from StringIO import StringIO

class UtilityTests(unittest.TestCase):
    def setUp(self):
        client_id = ""
        client_secret = ""
        app_url = ""
        self.policy = FacebookAuthenticationPolicy(client_id, client_secret, app_url)
        pass

    def test_good_graph_call(self):
        with Stub() as urllib:
            from urllib import urlopen
            urlopen.__call__("https://graph.facebook.com/me", "x=y") >> StringIO("{\"a\": \"b\"}")
        response = self.policy.fbuser._make_graph_call("/me", {"x":"y"})
        self.assertTrue(response['a'] == 'b')

    def test_good_graph_call_no_params(self):
        with Stub() as urllib:
            from urllib import urlopen
            urlopen.__call__("https://graph.facebook.com/me", "") >> StringIO("{\"a\": \"b\"}")
        response = self.policy.fbuser._make_graph_call("/me")
        self.assertTrue(response['a'] == 'b')

    def test_bad_graph_call(self):
        with Stub() as urllib:
            from urllib import urlopen
            urlopen.__call__("https://graph.facebook.com/me", {}) >> StringIO("Bad JSON")
        response = self.policy.fbuser._make_graph_call("/me", {})
        self.assertTrue(response == None)