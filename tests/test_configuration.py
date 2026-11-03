import os
import unittest
from unittest.mock import patch

import requests
from aws_requests_auth.aws_auth import AWSRequestsAuth

from httpie_hmac import HmacPlugin


class ConfigurationTests(unittest.TestCase):
    def configure(self, raw_auth='', env=None):
        with patch.dict(os.environ, env or {}, clear=True):
            plugin = HmacPlugin()
            plugin.raw_auth = raw_auth
            return plugin.get_auth()

    def test_default_and_explicit_simple(self):
        for setting in ['secret:dummy', 'secret:dummy,format:simple']:
            with self.subTest(setting=setting):
                auth = self.configure(setting)
                self.assertEqual(auth.formatter.__name__, 'Simple')
                self.assertIsNone(auth.access_id)
                self.assertEqual(auth.secret_key, 'dummy')

    def test_environment_configuration(self):
        auth = self.configure(env={
            'HTTPIE_HMAC_SECRET': 'environment-secret',
            'HTTPIE_HMAC_ACCESS_ID': 'environment-id',
            'HTTPIE_HMAC_FORMAT': 'aws4',
            'HTTPIE_HMAC_REGION': 'eu-west-2',
            'UNRELATED': 'ignored',
        })
        self.assertEqual(auth.secret_key, 'environment-secret')
        self.assertEqual(auth.access_id, 'environment-id')
        self.assertEqual(auth.formatter.__name__, 'AWS4')
        self.assertEqual(auth.raw_settings['region'], 'eu-west-2')
        self.assertNotIn('unrelated', auth.raw_settings)

    def test_cli_overrides_environment_and_trims_whitespace(self):
        auth = self.configure(
            ' secret : cli-secret , access_id : cli-id , format : simple ,'
            ' region : us-east-1 , custom : value ',
            {'HTTPIE_HMAC_SECRET': 'env-secret',
             'HTTPIE_HMAC_ACCESS_ID': 'env-id',
             'HTTPIE_HMAC_FORMAT': 'aws4',
             'HTTPIE_HMAC_REGION': 'eu-west-2'},
        )
        self.assertEqual(auth.secret_key, 'cli-secret')
        self.assertEqual(auth.access_id, 'cli-id')
        self.assertEqual(auth.formatter.__name__, 'Simple')
        self.assertEqual(auth.raw_settings['region'], 'us-east-1')
        self.assertEqual(auth.raw_settings['custom'], 'value')

    def test_missing_and_empty_secrets(self):
        for raw_auth, env in [('', {}), ('secret:', {}),
                              ('', {'HTTPIE_HMAC_SECRET': ''}),
                              ('secret:', {'HTTPIE_HMAC_SECRET': 'env'})]:
            with self.subTest(raw_auth=raw_auth, env=env):
                with self.assertRaisesRegex(ValueError, 'secret.*empty'):
                    self.configure(raw_auth, env)

    def test_malformed_settings_are_rejected(self):
        for raw_auth in ['secret', 'secret:dummy,']:
            with self.subTest(raw_auth=raw_auth):
                with self.assertRaises(ValueError):
                    self.configure(raw_auth)

    def test_colons_are_preserved_in_setting_values(self):
        auth = self.configure(
            ' secret : dummy:extra , custom : urn:example:value ',
            {'HTTPIE_HMAC_SECRET': 'env-secret',
             'HTTPIE_HMAC_CUSTOM': 'env-value'},
        )
        self.assertEqual(auth.secret_key, 'dummy:extra')
        self.assertEqual(auth.raw_settings['secret'], 'dummy:extra')
        self.assertEqual(auth.raw_settings['custom'], 'urn:example:value')

    def test_host_with_port_reaches_aws_signer(self):
        auth = self.configure(
            'secret:dummy,access_id:EXAMPLE,format:aws4,'
            'host:localhost:9000,region:eu-west-2,service:es',
            {'HTTPIE_HMAC_HOST': 'environment.example:8000'},
        )
        with patch('httpie_hmac.httpie_hmac.AWSRequestsAuth',
                   wraps=AWSRequestsAuth) as signer:
            request = requests.Request(
                'GET', 'http://localhost:9000/file.txt', auth=auth,
            ).prepare()
        self.assertEqual(signer.call_args.kwargs['aws_host'], 'localhost:9000')
        self.assertIn('/eu-west-2/es/aws4_request',
                      request.headers['Authorization'])

    def test_unknown_format_is_rejected(self):
        with self.assertRaises(KeyError):
            self.configure('secret:dummy,format:unknown')
