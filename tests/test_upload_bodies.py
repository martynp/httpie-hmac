import base64
import datetime
import hashlib
import hmac
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import requests
from httpie.context import Environment
from httpie.core import main

from httpie_hmac import HmacAuth


class NonseekableBody:
    def __init__(self, content):
        self.content = content
        self.reads = 0
        self.position = 0

    def read(self, size):
        self.reads += 1
        chunk = self.content[self.position:self.position + size]
        self.position += len(chunk)
        return chunk


class UploadBodyTests(unittest.TestCase):
    date = 'Sun, 30 Aug 2015 12:36:00 GMT'

    def sign(self, body, formatter, headers=None):
        request = requests.Request(
            'POST', 'https://s3.eu-west-2.amazonaws.com/key',
            headers=headers if headers is not None else {
                'Date': self.date, 'Content-Type': 'text/plain',
            },
        ).prepare()
        request.body = body
        fixed_time = datetime.datetime(2015, 8, 30, 12, 36)
        with patch('httpie_hmac._s3_auth.datetime.datetime') as clock:
            clock.now.return_value = fixed_time
            return HmacAuth('EXAMPLE', 'dummy', formatter, {})(request)

    def test_supported_body_types_sign_the_same_bytes(self):
        payload = 'caf\u00e9'.encode('utf-8')
        factories = [
            lambda: 'caf\u00e9', lambda: payload,
            lambda: bytearray(payload), lambda: memoryview(payload),
            lambda: io.BytesIO(payload), lambda: io.StringIO('caf\u00e9'),
            lambda: NonseekableBody(payload),
            lambda: iter([b'caf', '\u00e9']),
        ]
        for formatter in ['simple', 'aws4']:
            baseline = self.sign(payload, formatter)
            for factory in factories:
                with self.subTest(formatter=formatter, factory=factory):
                    body = factory()
                    signed = self.sign(body, formatter)
                    actual = (signed.body.read()
                              if hasattr(signed.body, 'read') else signed.body)
                    self.assertEqual(actual, payload)
                    self.assertEqual(signed.headers, baseline.headers)
                    if isinstance(body, NonseekableBody):
                        self.assertEqual(body.position, len(payload))

    def test_body_buffering_does_not_depend_on_content_type_or_md5(self):
        for headers in [{'Date': self.date},
                        {'Date': self.date, 'Content-MD5': 'supplied'}]:
            with self.subTest(headers=headers):
                request = self.sign(NonseekableBody(b'hello'), 'aws4', headers)
                self.assertEqual(request.body, b'hello')
                self.assertEqual(request.headers['x-amz-content-sha256'],
                                 hashlib.sha256(b'hello').hexdigest())
                self.assertEqual(request.headers.get('Content-MD5'),
                                 headers.get('Content-MD5'))

    def test_file_is_read_from_current_position(self):
        body = io.BytesIO(b'prefixhello')
        body.seek(6)
        signed = self.sign(body, 'simple')
        self.assertEqual(signed.body.read(), b'hello')
        self.assertEqual(signed.headers['Content-MD5'],
                         'XUFAKrxLKna5cZ2REBfFkg==')
        self.assertEqual(signed._body_position, 0)

    def test_empty_stream_has_empty_payload_hash(self):
        signed = self.sign(iter([]), 'aws4')
        self.assertEqual(signed.body, b'')
        self.assertNotIn('Content-MD5', signed.headers)
        self.assertEqual(signed.headers['x-amz-content-sha256'],
                         hashlib.sha256(b'').hexdigest())

    def test_requests_preserves_chunked_framing_and_replayable_body(self):
        request = requests.Request(
            'POST', 'https://s3.eu-west-2.amazonaws.com/key',
            data=iter([b'he', b'llo']),
            headers={'Content-Type': 'text/plain'},
            auth=HmacAuth('EXAMPLE', 'dummy', 'aws4', {}),
        ).prepare()
        self.assertEqual(request.headers['Transfer-Encoding'], 'chunked')
        self.assertNotIn('Content-Length', request.headers)
        self.assertEqual(b''.join(request.body), b'hello')
        self.assertEqual(b''.join(request.body), b'hello')
        self.assertEqual(request.headers['Content-MD5'],
                         'XUFAKrxLKna5cZ2REBfFkg==')

    def test_transfer_encoding_tokens_are_case_insensitive_and_trimmed(self):
        request = requests.Request(
            'POST', 'https://s3.eu-west-2.amazonaws.com/key',
            data=b'hello',
            headers={'Transfer-Encoding': 'gzip, Chunked'},
            auth=HmacAuth('EXAMPLE', 'dummy', 'simple', {}),
        ).prepare()
        self.assertNotIn('Content-Length', request.headers)
        self.assertEqual(b''.join(request.body), b'hello')

    def test_requests_recomputes_utf8_content_length(self):
        request = requests.Request(
            'POST', 'https://s3.eu-west-2.amazonaws.com/key',
            data='caf\u00e9', headers={'Content-Type': 'text/plain'},
            auth=HmacAuth('EXAMPLE', 'dummy', 'simple', {}),
        ).prepare()
        self.assertEqual(request.body, 'caf\u00e9'.encode('utf-8'))
        self.assertEqual(request.headers['Content-Length'], '5')


class HTTPieUploadTests(unittest.TestCase):
    def prepare_upload(self, formatter, flags):
        captured = []

        def send(request, **kwargs):
            captured.append(request)
            response = requests.Response()
            response.status_code = 200
            response._content = b''
            response.url = request.url
            response.request = request
            return response

        with tempfile.TemporaryDirectory() as directory:
            env = Environment(
                config_dir=Path(directory), stdin=io.StringIO(),
                stdout=io.StringIO(), stderr=io.StringIO(),
            )
            with patch.dict(os.environ, {}, clear=True), \
                    patch('httpie.core.write_message'), \
                    patch('requests.Session.send', side_effect=send) as mocked:
                status = main([
                    'http', '--ignore-stdin', '--pretty=none',
                    '--auth-type=hmac',
                    '--auth=secret:dummy,access_id:EXAMPLE,format:'
                    + formatter,
                    *flags, 'POST',
                    'https://s3.eu-west-2.amazonaws.com/key', 'message=hello',
                ], env=env)
            self.assertEqual(status, 0, env.stderr.getvalue())
            mocked.assert_called_once()
        return captured[0]

    def test_normal_httpie_uploads_sign_actual_payload(self):
        # No --offline: HTTPie retains stream wrappers during preparation.
        # The patched send captures the final request without network access.
        for formatter in ['simple', 'aws4']:
            for flags in [['--multipart'], ['--chunked'],
                          ['--multipart', '--chunked']]:
                with self.subTest(formatter=formatter, flags=flags):
                    request = self.prepare_upload(formatter, flags)
                    chunked = '--chunked' in flags
                    body = b''.join(request.body) if chunked else request.body
                    if '--multipart' in flags:
                        self.assertIn(b'name="message"', body)
                        self.assertIn(b'\r\nhello\r\n', body)
                    else:
                        self.assertEqual(body, b'{"message": "hello"}')
                    if chunked:
                        self.assertIn('Transfer-Encoding', request.headers)
                        self.assertNotIn('Content-Length', request.headers)
                        self.assertEqual(b''.join(request.body), body)
                    else:
                        self.assertEqual(
                            int(request.headers['Content-Length']), len(body),
                        )
                    md5 = base64.b64encode(
                        hashlib.md5(body).digest()).decode('ascii')
                    self.assertEqual(request.headers['Content-MD5'], md5)
                    if formatter == 'aws4':
                        self.assertEqual(
                            request.headers['x-amz-content-sha256'],
                            hashlib.sha256(body).hexdigest(),
                        )
                    else:
                        content_type = request.headers['Content-Type']
                        if isinstance(content_type, bytes):
                            content_type = content_type.decode('utf-8')
                        string_to_sign = '\n'.join([
                            'POST', md5, content_type,
                            request.headers['Date'], '/key',
                        ])
                        signature = base64.b64encode(hmac.new(
                            b'dummy', string_to_sign.encode(), hashlib.sha256,
                        ).digest()).decode('ascii')
                        self.assertEqual(request.headers['Authorization'],
                                         'HMAC EXAMPLE:' + signature)
