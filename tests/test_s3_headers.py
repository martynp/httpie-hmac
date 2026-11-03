import datetime
import unittest
from unittest.mock import patch

import requests

from httpie_hmac import HmacAuth


class S3HeaderTests(unittest.TestCase):
    fixed_time = datetime.datetime(2015, 8, 30, 12, 36)
    payload_hash = (
        '2cf24dba5fb0a30e26e83b2ac5b9e29e'
        '1b161e5c1fa7425e73043362938b9824'
    )
    required_headers = {
        'Content-MD5': 'XUFAKrxLKna5cZ2REBfFkg==',
        'x-amz-acl': 'private',
        'x-amz-meta-example': 'hello world',
        'x-amz-server-side-encryption': 'AES256',
        'x-amz-storage-class': 'STANDARD_IA',
    }
    signed_headers = (
        'content-md5;host;x-amz-acl;x-amz-date;x-amz-meta-example;'
        'x-amz-server-side-encryption;x-amz-storage-class'
    )

    def sign(self, headers, body=b'hello', settings=None, method='PUT'):
        headers = dict(headers)
        headers['Date'] = 'Sun, 30 Aug 2015 12:36:00 GMT'
        with patch('httpie_hmac._s3_auth.datetime.datetime') as clock:
            clock.now.return_value = self.fixed_time
            return requests.Request(
                method, 'https://bucket.s3.eu-west-2.amazonaws.com/key',
                headers=headers, data=body,
                auth=HmacAuth('EXAMPLE', 'dummy-secret', 'aws4',
                              settings or {}),
            ).prepare()

    def assert_authorization(self, request, signed_headers, signature):
        self.assertEqual(
            request.headers['Authorization'],
            'AWS4-HMAC-SHA256 Credential=EXAMPLE/'
            '20150830/eu-west-2/s3/aws4_request, '
            f'SignedHeaders={signed_headers}, Signature={signature}',
        )

    def test_required_s3_headers_have_fixed_signature(self):
        # Fixture canonical headers are the sorted required_headers above,
        # plus host:bucket.s3.eu-west-2.amazonaws.com and the fixed amz-date.
        # Canonical request: PUT /key, empty query, SHA256('hello') payload.
        # Expected signatures calculated independently from literal canonical
        # request strings, not through the production signing helpers.
        request = self.sign(self.required_headers)
        self.assert_authorization(
            request, self.signed_headers,
            'a3f123d7707590b3353e05e113d2f5f92'
            'fddbc92990c659ff4702aeeeedd6136',
        )
        for name, value in self.required_headers.items():
            self.assertEqual(request.headers[name], value)

    def test_header_case_bytes_and_whitespace_are_canonicalized(self):
        headers = {name.upper(): value.encode('utf-8')
                   for name, value in self.required_headers.items()}
        headers['X-AMZ-META-EXAMPLE'] = b'hello  \tworld  '
        request = self.sign(headers)
        self.assert_authorization(
            request, self.signed_headers,
            'a3f123d7707590b3353e05e113d2f5f92'
            'fddbc92990c659ff4702aeeeedd6136',
        )
        # Only canonicalization changes whitespace, not the outgoing value.
        self.assertEqual(request.headers['x-amz-meta-example'],
                         b'hello  \tworld  ')

    def test_changing_metadata_changes_signature(self):
        first = self.sign(self.required_headers)
        changed = {**self.required_headers, 'x-amz-meta-example': 'other'}
        second = self.sign(changed)
        self.assertNotEqual(first.headers['Authorization'],
                            second.headers['Authorization'])

    def test_generated_md5_is_signed(self):
        request = self.sign({'Content-Type': 'text/plain'})
        self.assertEqual(request.headers['Content-MD5'],
                         'XUFAKrxLKna5cZ2REBfFkg==')
        self.assert_authorization(
            request, 'content-md5;host;x-amz-date',
            'bfe868f08830ae3fed2810fabf073c5b16'
            'b06d6ec60a4b41d57ca47dd7d986a6',
        )

    def test_generated_values_replace_stale_signing_headers(self):
        request = self.sign({
            'X-AMZ-DATE': b'20000101T000000Z',
            'X-Amz-Security-Token': b'stale-token',
            'X-Amz-Content-Sha256': 'stale-hash',
            'Authorization': 'stale-authorization',
        }, body=None, method='GET',
            settings={'session_token': 'credential-token'})
        self.assert_authorization(
            request, 'host;x-amz-date;x-amz-security-token',
            'd47081b5f6fc5ed517affdf3d0320f1c5'
            '360191c6518c0909100fdffbf8bb5bf',
        )
        self.assertEqual(request.headers['x-amz-date'], '20150830T123600Z')
        self.assertEqual(request.headers['x-amz-security-token'],
                         'credential-token')
        self.assertEqual(
            request.headers['x-amz-content-sha256'],
            'e3b0c44298fc1c149afbf4c8996fb92427'
            'ae41e4649b934ca495991b7852b855',
        )

    def test_supplied_token_is_signed_without_configured_token(self):
        request = self.sign({'x-amz-security-token': b'credential-token'},
                            body=None, method='GET')
        self.assert_authorization(
            request, 'host;x-amz-date;x-amz-security-token',
            'd47081b5f6fc5ed517affdf3d0320f1c5'
            '360191c6518c0909100fdffbf8bb5bf',
        )

    def test_payload_hash_is_generated_but_not_a_canonical_header(self):
        request = self.sign({'x-amz-content-sha256': 'stale-hash'})
        self.assertEqual(request.headers['x-amz-content-sha256'],
                         self.payload_hash)
        signed = request.headers['Authorization'].split('SignedHeaders=')[1]
        self.assertEqual(signed.split(',')[0], 'host;x-amz-date')
