import os
import unittest
from unittest.mock import patch

import requests

from httpie_hmac import HmacPlugin


class AWSSessionTokenTests(unittest.TestCase):
    def sign(self, raw_auth, env=None):
        with patch.dict(os.environ, env or {}, clear=True):
            plugin = HmacPlugin()
            plugin.raw_auth = raw_auth
            auth = plugin.get_auth()
        return requests.Request(
            'GET',
            'https://example-bucket.s3.eu-west-2.amazonaws.com/file.txt',
            auth=auth,
        ).prepare()

    def assert_signed_token(self, request, token):
        self.assertEqual(request.headers['X-Amz-Security-Token'], token)
        self.assertIn('x-amz-security-token',
                      request.headers['Authorization'].split('Signature=')[0])

    def test_cli_session_token_is_signed(self):
        request = self.sign(
            'format:aws4,access_id:EXAMPLE,secret:dummy-secret,'
            'session_token:dummy-token+/='
        )
        self.assert_signed_token(request, 'dummy-token+/=')

    def test_environment_session_token_is_signed(self):
        request = self.sign('', {
            'HTTPIE_HMAC_FORMAT': 'aws4',
            'HTTPIE_HMAC_ACCESS_ID': 'EXAMPLE',
            'HTTPIE_HMAC_SECRET': 'dummy-secret',
            'HTTPIE_HMAC_SESSION_TOKEN': 'environment-token',
        })
        self.assert_signed_token(request, 'environment-token')

    def test_cli_session_token_overrides_environment(self):
        request = self.sign(
            'format:aws4,access_id:EXAMPLE,secret:dummy-secret,'
            'session_token:cli-token',
            {'HTTPIE_HMAC_SESSION_TOKEN': 'environment-token'},
        )
        self.assert_signed_token(request, 'cli-token')

    def test_long_lived_credentials_need_no_token(self):
        request = self.sign(
            'format:aws4,access_id:EXAMPLE,secret:dummy-secret'
        )
        self.assertNotIn('X-Amz-Security-Token', request.headers)
        self.assertTrue(request.headers['Authorization'].startswith(
            'AWS4-HMAC-SHA256 Credential=EXAMPLE/'
        ))


if __name__ == '__main__':
    unittest.main()
