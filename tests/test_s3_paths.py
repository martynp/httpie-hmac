import datetime
import unittest
from unittest.mock import patch

import requests
from aws_requests_auth.aws_auth import AWSRequestsAuth

from httpie_hmac import HmacAuth


class S3PathTests(unittest.TestCase):
    fixed_time = datetime.datetime(2015, 8, 30, 12, 36)
    date = 'Sun, 30 Aug 2015 12:36:00 GMT'

    def sign(self, path, service='s3', body=None, settings=None):
        settings = settings or {}
        host = ('bucket.s3' if service == 's3' else service)
        with patch('httpie_hmac._s3_auth.datetime.datetime') as s3_clock, \
                patch('aws_requests_auth.aws_auth.datetime') as aws_clock:
            s3_clock.now.return_value = self.fixed_time
            aws_clock.datetime.utcnow.return_value = self.fixed_time
            return requests.Request(
                'GET', f'https://{host}.eu-west-2.amazonaws.com{path}',
                headers={'Date': self.date}, data=body,
                auth=HmacAuth('EXAMPLE', 'dummy-secret', 'aws4', settings),
            ).prepare()

    def test_s3_fixed_signatures_preserve_prepared_paths(self):
        # Literal vectors calculated independently from canonical requests:
        # GET, stated URI, empty query/body, host and x-amz-date headers,
        # timestamp 20150830T123600Z, scope 20150830/eu-west-2/s3/aws4_request.
        vectors = [
            ('/hello world.txt', '/hello%20world.txt',
             '8de24110875cdcb18d502b04c162252af'
             '26e2091f3f8b2b25487e1688b9fe6e9'),
            ('/hello%20world.txt', '/hello%20world.txt',
             '8de24110875cdcb18d502b04c162252af'
             '26e2091f3f8b2b25487e1688b9fe6e9'),
            ('/100%.txt', '/100%25.txt',
             'cbf9e9267c6d793888da4aa0a90e6282'
             '24ea69d5993e913ef3b2850d8b2053ea'),
            ('/literal%252F.txt', '/literal%252F.txt',
             'f221b6bbbef644062882877d0f8e1047'
             'ebef51b6c01f6de35ae40c207a9180ee'),
            ('/folder/part%2Fname.txt', '/folder/part%2Fname.txt',
             '3efcd0a53d78ce2a2efe5e57dab3e8a9'
             'b7ef6e26af55dac0fce3d192f68e9337'),
            ('/caf\u00e9.txt', '/caf%C3%A9.txt',
             'da7466e34a5e36db52e28110df3a0258b'
             '04223761f95ec0502b7105bc97dc8c7'),
            ('/folder//file.txt', '/folder//file.txt',
             'f607bbeb47961f38a5d8674a2c257988'
             'dd526c4c154ee3201497382551273478'),
            ('', '/',
             '339bc07dcfe52e81bddf0be21e680f7e'
             'f951b011745006032c0d6b31e90d512e'),
        ]
        for path, prepared_path, signature in vectors:
            with self.subTest(path=path):
                request = self.sign(path)
                self.assertEqual(
                    request.url,
                    'https://bucket.s3.eu-west-2.amazonaws.com'
                    + prepared_path,
                )
                self.assertEqual(
                    request.headers['Authorization'],
                    'AWS4-HMAC-SHA256 Credential=EXAMPLE/'
                    '20150830/eu-west-2/s3/aws4_request, '
                    'SignedHeaders=host;x-amz-date, Signature=' + signature,
                )

    def test_s3_reserved_path_characters_have_fixed_signatures(self):
        # The literal canonical URIs below encode reserved characters that
        # Requests leaves in prepared paths. Signature fixtures use the same
        # fixed headers/scope as above, calculated from those literal URIs.
        vectors = [
            ('/a+b.txt', '/a%2Bb.txt',
             '235706d9811912b85ca27b5a38fbd0eb'
             '7af071e21b7ba5e9efdf59b9280adfe4'),
            ('/a:b.txt', '/a%3Ab.txt',
             '0d96adfa44dc2e00cec6af069f745b0d4'
             'd41e4f8d8e66e6b1628d1dcbaa6be72'),
            ('/a@b.txt', '/a%40b.txt',
             '02093e798edf419c015eb5c7e6a0fd26'
             'a7b264f58bfd37b8040b7efd8edce5ea'),
            ("/a!$&'()*+,;=:@b.txt",
             '/a%21%24%26%27%28%29%2A%2B%2C%3B%3D%3A%40b.txt',
             'a3c16e1b5af54017e9c514b1d4e0437e'
             '8e5d23294035ab5082c6e1d24d933142'),
        ]
        for literal_path, encoded_path, signature in vectors:
            for path in [literal_path, encoded_path]:
                with self.subTest(path=path):
                    request = self.sign(path)
                    self.assertEqual(
                        request.url,
                        'https://bucket.s3.eu-west-2.amazonaws.com' + path,
                    )
                    self.assertEqual(
                        request.headers['Authorization'],
                        'AWS4-HMAC-SHA256 Credential=EXAMPLE/'
                        '20150830/eu-west-2/s3/aws4_request, '
                        'SignedHeaders=host;x-amz-date, Signature='
                        + signature,
                    )

    def test_empty_prepared_path_signs_as_root(self):
        # PreparedRequest normally supplies '/'; custom callers may omit it.
        request = requests.Request(
            'GET', 'https://bucket.s3.eu-west-2.amazonaws.com',
            headers={'Date': self.date},
        ).prepare()
        request.url = 'https://bucket.s3.eu-west-2.amazonaws.com'
        with patch('httpie_hmac._s3_auth.datetime.datetime') as clock:
            clock.now.return_value = self.fixed_time
            signed = HmacAuth('EXAMPLE', 'dummy-secret', 'aws4', {})(request)
        self.assertTrue(signed.headers['Authorization'].endswith(
            '339bc07dcfe52e81bddf0be21e680f7ef951b011745006032c0d6b31e90d512e'
        ))
        self.assertEqual(signed.url, request.url)

    def test_s3_body_query_and_token_preserve_existing_signing(self):
        request = self.sign('/plain.txt?z=2&a=1', body=b'hello',
                            settings={'session_token': 'dummy-token'})
        comparison = request.copy()
        with patch('aws_requests_auth.aws_auth.datetime') as clock:
            clock.datetime.utcnow.return_value = self.fixed_time
            AWSRequestsAuth(
                'EXAMPLE', 'dummy-secret',
                'bucket.s3.eu-west-2.amazonaws.com', 'eu-west-2', 's3',
                aws_token='dummy-token',
            )(comparison)
        self.assertEqual(request.headers, comparison.headers)

    def test_non_s3_signing_retains_second_encoding(self):
        request = self.sign('/hello%20world.txt', service='es')
        self.assertEqual(
            request.url,
            'https://es.eu-west-2.amazonaws.com/hello%20world.txt',
        )
        self.assertTrue(request.headers['Authorization'].endswith(
            'fde14d2b7540c3d0321c381bb442b6aab7fca79d37faa9f493820afbba8676e0'
        ))
