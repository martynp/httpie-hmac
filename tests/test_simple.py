import datetime
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests

from httpie_hmac import HmacAuth


class SimpleSigningTests(unittest.TestCase):
    date = 'Tue, 03 Nov 2026 12:00:00 GMT'
    signature = 'SHf/C6vMFCl3QHXymJlpu9uysznqveMux9amdt50V2U='

    def sign(self, access_id=None, method='GET', path='/file.txt',
             body=None, headers=None):
        return requests.Request(
            method, 'https://example.com' + path, data=body,
            headers=headers if headers is not None else {'Date': self.date},
            auth=HmacAuth(access_id, 'dummy-secret', None, {}),
        ).prepare()

    def test_fixed_signature_with_and_without_access_id(self):
        # Fixed vectors for GET\n\n\nTue, 03 Nov 2026 12:00:00 GMT\n/file.txt.
        for access_id, prefix in [(None, 'HMAC '), ('', 'HMAC '),
                                  ('EXAMPLE', 'HMAC EXAMPLE:')]:
            with self.subTest(access_id=access_id):
                self.assertEqual(self.sign(access_id).headers['Authorization'],
                                 prefix + self.signature)

    def test_method_and_path_affect_signature(self):
        for method, path, signature in [
            ('POST', '/file.txt',
             'BtIT7Jro/rE+0wIwFPzg+roj/a0eO2gbY7q+uQ4+0kI='),
            ('GET', '/other',
             'qCxvnLczk4WYX8T9L3nDdLHt8VMqRjD8r645eaJIdXM='),
        ]:
            with self.subTest(method=method, path=path):
                self.assertEqual(
                    self.sign(method=method, path=path)
                    .headers['Authorization'],
                    'HMAC ' + signature,
                )

    def test_query_is_not_part_of_simple_string_to_sign(self):
        request = self.sign(path='/file.txt?version=2')
        self.assertEqual(request.headers['Authorization'],
                         'HMAC ' + self.signature)

    def test_body_changes_md5_and_signature(self):
        headers = {'Content-Type': 'text/plain', 'Date': self.date}
        first = self.sign(body=b'hello', headers=headers)
        second = self.sign(body=b'world', headers=headers)
        self.assertEqual(first.headers['Content-MD5'],
                         'XUFAKrxLKna5cZ2REBfFkg==')
        self.assertEqual(second.headers['Content-MD5'],
                         'fXkwN6B2AYZXSwKC8vQ15w==')
        self.assertNotEqual(first.headers['Authorization'],
                            second.headers['Authorization'])

    def test_buffered_upload_remains_readable_until_caller_closes_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'body.txt'
            path.write_bytes(b'hello')
            with path.open('rb') as body:
                request = self.sign(
                    method='POST', body=body,
                    headers={'Content-Type': 'text/plain', 'Date': self.date},
                )
                self.assertEqual(request.body.read(), b'hello')
                self.assertFalse(body.closed)
        self.assertEqual(request.headers['Content-MD5'],
                         'XUFAKrxLKna5cZ2REBfFkg==')
        self.assertEqual(request.headers['Content-Length'], '5')

    def test_empty_body_does_not_generate_md5(self):
        request = self.sign(body=b'', headers={'Content-Type': 'text/plain',
                                               'Date': self.date})
        self.assertNotIn('Content-MD5', request.headers)

    def test_generated_date_uses_utc_http_format(self):
        with patch('httpie_hmac.httpie_hmac.datetime') as clock:
            clock.datetime.utcnow.return_value = datetime.datetime(
                2026, 11, 3, 12, 0, 0)
            request = self.sign(headers={})
        self.assertEqual(request.headers['Date'], self.date)
        self.assertEqual(request.headers['Authorization'],
                         'HMAC ' + self.signature)
