import datetime
import unittest
from unittest.mock import patch

import requests

from httpie_hmac import HmacAuth


class AWSSignatureTests(unittest.TestCase):
    def test_fixed_iam_signature(self):
        # Fixture: empty GET /, sorted Action/Version query, host and amz-date
        # canonical headers only; scope 20150830/us-east-1/iam/aws4_request.
        # Digest calculated independently from that canonical request.
        with patch('aws_requests_auth.aws_auth.datetime') as clock:
            clock.datetime.utcnow.return_value = datetime.datetime(
                2015, 8, 30, 12, 36, 0)
            request = requests.Request(
                'GET', 'https://iam.amazonaws.com/'
                '?Version=2010-05-08&Action=ListUsers',
                headers={'Date': 'Sun, 30 Aug 2015 12:36:00 GMT'},
                auth=HmacAuth(
                    'AKIDEXAMPLE',
                    'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY', 'aws4',
                    {'region': 'us-east-1', 'service': 'iam'},
                ),
            ).prepare()
        self.assertEqual(request.headers['x-amz-date'], '20150830T123600Z')
        self.assertEqual(
            request.headers['Authorization'],
            'AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/'
            '20150830/us-east-1/iam/aws4_request, '
            'SignedHeaders=host;x-amz-date, Signature='
            'b2e4af44cfad96d9ffa3c5653674a927b9b0995c33de22e1f843745ce37c1d5e',
        )

    def test_host_override_reaches_signer(self):
        from aws_requests_auth.aws_auth import AWSRequestsAuth
        from httpie_hmac._s3_auth import _S3RequestsAuth

        for service, auth_class in [('s3', _S3RequestsAuth),
                                    ('es', AWSRequestsAuth)]:
            with self.subTest(service=service), patch(
                'httpie_hmac.httpie_hmac.' + auth_class.__name__,
                wraps=auth_class,
            ) as signer:
                requests.Request(
                    'GET', f'https://{service}.eu-west-2.amazonaws.com'
                    '/file.txt',
                    auth=HmacAuth('EXAMPLE', 'dummy', 'aws4',
                                  {'host': 'custom.example.com'}),
                ).prepare()
                self.assertEqual(signer.call_args.kwargs['aws_host'],
                                 'custom.example.com')
