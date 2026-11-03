import base64
import hashlib
import itertools
import unittest
from email.utils import parsedate_to_datetime

import requests

from httpie_hmac import HmacAuth


class HeaderTypeTests(unittest.TestCase):
    headers = {
        'Content-Type': 'application/json',
        'Content-MD5': '1B2M2Y8AsgTpgAmY7PhCfg==',
        'Date': 'Tue, 03 Nov 2026 12:00:00 GMT',
    }

    def sign(self, formatter, headers, body=b'hello'):
        return requests.Request(
            'POST', 'https://s3.eu-west-2.amazonaws.com/file.txt',
            headers=headers, data=body,
            auth=HmacAuth('EXAMPLE', 'dummy-secret', formatter, {}),
        ).prepare()

    def test_existing_headers_accept_mixed_strings_and_bytes(self):
        for formatter in ['simple', 'aws4']:
            for as_bytes in itertools.product([False, True], repeat=3):
                headers = {
                    name: value.encode('utf-8') if encode else value
                    for (name, value), encode in zip(
                        self.headers.items(), as_bytes
                    )
                }
                with self.subTest(formatter=formatter, as_bytes=as_bytes):
                    request = self.sign(formatter, headers)
                    for name, value in headers.items():
                        self.assertEqual(request.headers[name], value)
                    if formatter == 'simple':
                        # Fixed signature covers the supplied MD5, type, date,
                        # method and path, independently of header value types.
                        self.assertEqual(
                            request.headers['Authorization'],
                            'HMAC EXAMPLE:'
                            '4ZbBLv6CK748Yw+HLpK2+1kYQoW9WJNik+JbZCdz3es=',
                        )
                    else:
                        self.assertTrue(
                            request.headers['Authorization'].startswith(
                                'AWS4-HMAC-SHA256 Credential=EXAMPLE/'
                            )
                        )
                        self.assertEqual(
                            request.headers['x-amz-content-sha256'],
                            hashlib.sha256(b'hello').hexdigest(),
                        )

    def test_missing_md5_is_generated_with_either_content_type(self):
        for formatter in ['simple', 'aws4']:
            for content_type in ['application/json', b'application/json']:
                with self.subTest(formatter=formatter, value=content_type):
                    request = self.sign(
                        formatter, {'Content-Type': content_type}
                    )
                    expected_md5 = base64.b64encode(
                        hashlib.md5(b'hello').digest()
                    ).decode('utf-8')
                    self.assertEqual(
                        request.headers['Content-MD5'], expected_md5
                    )
                    self.assertIsNotNone(
                        parsedate_to_datetime(request.headers['Date']).tzinfo
                    )

    def test_absent_content_type_and_md5_remain_absent(self):
        for formatter in ['simple', 'aws4']:
            with self.subTest(formatter=formatter):
                request = self.sign(formatter, {}, body=None)
                self.assertNotIn('Content-Type', request.headers)
                self.assertNotIn('Content-MD5', request.headers)
                self.assertIsNotNone(
                    parsedate_to_datetime(request.headers['Date']).tzinfo
                )
                self.assertIn('Authorization', request.headers)


if __name__ == '__main__':
    unittest.main()
