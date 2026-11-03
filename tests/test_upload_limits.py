import array
import base64
import datetime
import hashlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests
from requests.hooks import dispatch_hook
from httpie.context import Environment
from httpie.core import main

from httpie_hmac import HmacAuth, HmacPlugin
from httpie_hmac._body import CHUNK_SIZE, prepare_body


class BoundedReader:
    """An unknown-length input that rejects unbounded reads."""
    def __init__(self, size):
        self.remaining = size
        self.read_sizes = []

    def read(self, size):
        if size < 0 or size > CHUNK_SIZE:
            raise AssertionError('unbounded upload read')
        self.read_sizes.append(size)
        chunk = b'x' * min(size, self.remaining)
        self.remaining -= len(chunk)
        return chunk


class UploadLimitTests(unittest.TestCase):
    def setUp(self):
        self.spools = []
        factory = tempfile.SpooledTemporaryFile

        def spool(*args, **kwargs):
            result = factory(*args, **kwargs)
            result.write = Mock(wraps=result.write)
            result.rollover = Mock(wraps=result.rollover)
            self.spools.append(result)
            self.addCleanup(result.close)
            return result

        self.spool_patch = patch(
            'httpie_hmac._body.tempfile.SpooledTemporaryFile', spool)
        self.spool_patch.start()
        self.addCleanup(self.spool_patch.stop)

    def test_byte_limit_below_at_and_above(self):
        for size in [4, 5]:
            with self.subTest(size=size):
                body, length, _, digest = prepare_body(b'x' * size, 5)
                self.assertEqual(length, size)
                self.assertEqual(body, b'x' * size)
                self.assertEqual(digest, hashlib.sha256(body).hexdigest())
        with self.assertRaisesRegex(ValueError, 'max_body_size.*5 bytes'):
            prepare_body(b'xxxxxx', 5)

    def test_unknown_length_limit_checks_actual_bytes(self):
        source = BoundedReader(6)
        with self.assertRaisesRegex(ValueError, 'max_body_size'):
            prepare_body(source, 5)
        self.assertLessEqual(sum(source.read_sizes), 6)
        self.assertTrue(all(spool.closed for spool in self.spools))

    def test_exact_limit_stream_does_not_require_declared_length(self):
        source = BoundedReader(5)
        body, size, _, _ = prepare_body(source, 5)
        self.assertEqual(body, b'xxxxx')
        self.assertEqual(size, 5)
        self.assertEqual(source.read_sizes, [6, 1])

    def test_utf8_limit_counts_encoded_bytes(self):
        self.assertEqual(prepare_body('\u00e9\u00e9', 4)[1], 4)
        with self.assertRaisesRegex(ValueError, 'max_body_size'):
            prepare_body('\u00e9\u00e9\u00e9', 4)
        self.assertTrue(all(spool.closed for spool in self.spools))

    def test_large_yielded_chunk_is_rejected_before_spooling(self):
        with self.assertRaisesRegex(ValueError, 'max_body_size'):
            prepare_body(iter([bytearray(1024)]), 8)
        self.assertEqual(self.spools, [])

    def test_unknown_iterable_stops_at_limit(self):
        consumed = []

        def chunks():
            while True:
                consumed.append(1)
                yield b'xx'

        with self.assertRaisesRegex(ValueError, 'max_body_size'):
            prepare_body(chunks(), 5)
        self.assertEqual(len(consumed), 3)
        writes = self.spools[0].write.call_args_list
        self.assertEqual(sum(len(call.args[0]) for call in writes), 4)
        self.assertTrue(self.spools[0].closed)

    def test_memoryview_limit_counts_bytes_not_elements(self):
        body = memoryview(array.array('I', [1, 2]))
        with self.assertRaisesRegex(ValueError, 'max_body_size'):
            prepare_body(body, body.nbytes - 1)
        actual, size, _, digest = prepare_body(body, body.nbytes)
        self.assertEqual(actual, body.tobytes())
        self.assertEqual(size, body.nbytes)
        self.assertEqual(digest, hashlib.sha256(body).hexdigest())

    def test_noncontiguous_memoryview_is_rejected(self):
        with self.assertRaises(TypeError):
            prepare_body(memoryview(b'abcdef')[::2], 8)

    def test_seekable_file_is_hashed_in_chunks_and_rewound_without_spool(self):
        class Seekable(io.BytesIO):
            def read(self, size=-1):
                if size < 0 or size > CHUNK_SIZE:
                    raise AssertionError('unbounded read')
                return super().read(size)

        source = Seekable(b'prefix' + b'x' * (CHUNK_SIZE + 1))
        source.seek(6)
        body, size, _, _ = prepare_body(source, CHUNK_SIZE + 1)
        self.assertEqual(self.spools, [])
        self.assertEqual(source.tell(), 6)
        self.assertEqual(size, CHUNK_SIZE + 1)
        self.assertEqual(body.read(1), b'x')
        body.close()
        self.assertFalse(source.closed)

    def test_seekable_file_position_restored_on_limit_error(self):
        source = io.BytesIO(b'prefix' + b'xxxxxx')
        source.seek(6)
        with self.assertRaisesRegex(ValueError, 'max_body_size'):
            prepare_body(source, 5)
        self.assertEqual(source.tell(), 6)
        self.assertFalse(source.closed)

    def test_spool_rolls_over_with_bounded_writes(self):
        with patch('httpie_hmac._body.SPOOL_MEMORY_SIZE', 16):
            body, size, _, digest = prepare_body(BoundedReader(100), 100)
        self.assertEqual(size, 100)
        self.assertEqual(digest, hashlib.sha256(b'x' * 100).hexdigest())
        self.assertTrue(self.spools[0].rollover.called)
        self.assertTrue(all(len(call.args[0]) <= CHUNK_SIZE
                            for call in self.spools[0].write.call_args_list))
        self.assertEqual(body.read(), b'x' * 100)
        body.close()
        self.assertTrue(self.spools[0].closed)

    def test_read_error_closes_spool(self):
        class Broken:
            calls = 0

            def read(self, size):
                self.calls += 1
                if self.calls == 2:
                    raise OSError('input failed')
                return b'hello'

        with self.assertRaisesRegex(OSError, 'input failed'):
            prepare_body(Broken(), 100)
        self.assertTrue(self.spools[0].closed)

    def sign_stream(self, formatter='simple', source=None, settings=None):
        request = requests.Request(
            'POST', 'https://s3.eu-west-2.amazonaws.com/key',
            headers={'Content-Type': 'text/plain',
                     'Date': 'Sun, 30 Aug 2015 12:36:00 GMT'},
        ).prepare()
        request.body = source if source is not None else BoundedReader(32)
        auth = HmacAuth('EXAMPLE', 'dummy', formatter, settings or {})
        return request, auth

    def test_signing_error_closes_spool(self):
        class BrokenFormatter:
            def generate(request):
                raise RuntimeError('signing failed')

        request, auth = self.sign_stream()
        auth.formatter = BrokenFormatter
        with patch('httpie_hmac._body.SPOOL_MEMORY_SIZE', 16):
            with self.assertRaisesRegex(RuntimeError, 'signing failed'):
                auth(request)
        self.assertTrue(self.spools[0].closed)

    def test_final_response_closes_spool_but_redirect_keeps_replay(self):
        request, auth = self.sign_stream()
        with patch('httpie_hmac._body.SPOOL_MEMORY_SIZE', 16):
            signed = auth(request)
        redirect = requests.Response()
        redirect.status_code = 307
        redirect.headers['Location'] = 'https://example.com/next'
        dispatch_hook('response', signed.hooks, redirect)
        self.assertFalse(self.spools[0].closed)
        self.assertEqual(signed.body.read(), b'x' * 32)
        signed.body.seek(0)
        self.assertEqual(signed.body.read(), b'x' * 32)
        final = requests.Response()
        final.status_code = 200
        dispatch_hook('response', signed.hooks, final)
        self.assertTrue(self.spools[0].closed)

    def test_final_response_never_closes_caller_file(self):
        source = io.BytesIO(b'hello')
        request, auth = self.sign_stream(source=source)
        signed = auth(request)
        response = requests.Response()
        response.status_code = 200
        dispatch_hook('response', signed.hooks, response)
        self.assertFalse(source.closed)
        source.seek(0)
        self.assertEqual(source.read(), b'hello')

    def test_content_length_cannot_bypass_limit(self):
        request, auth = self.sign_stream(settings={'max_body_size': 4})
        request.headers['Content-Length'] = '1'
        with self.assertRaisesRegex(ValueError, 'max_body_size'):
            auth(request)

    def test_generic_aws_stream_signature_matches_bytes(self):
        fixed_time = datetime.datetime(2015, 8, 30, 12, 36)
        headers = {'Content-Type': 'text/plain',
                   'Date': 'Sun, 30 Aug 2015 12:36:00 GMT'}
        with patch('httpie_hmac._s3_auth.datetime.datetime') as stream_clock, \
                patch('aws_requests_auth.aws_auth.datetime') as byte_clock:
            stream_clock.now.return_value = fixed_time
            byte_clock.datetime.utcnow.return_value = fixed_time
            signed = []
            for body in [b'hello', io.BytesIO(b'hello')]:
                signed.append(requests.Request(
                    'POST', 'https://es.eu-west-2.amazonaws.com/space%20key',
                    headers=headers, data=body,
                    auth=HmacAuth('EXAMPLE', 'dummy', 'aws4', {}),
                ).prepare())
        self.assertEqual(signed[0].headers, signed[1].headers)
        self.assertEqual(signed[1].body.read(), b'hello')

    def test_normal_httpie_disk_spooled_uploads_and_final_cleanup(self):
        for formatter in ['simple', 'aws4']:
            for flags in [['--multipart'], ['--chunked'],
                          ['--multipart', '--chunked']]:
                with self.subTest(formatter=formatter, flags=flags):
                    captured = []

                    def send(request, **kwargs):
                        body = request.body
                        payload = (body.read() if hasattr(body, 'read')
                                   else b''.join(body))
                        self.assertIn(b'hello', payload)
                        self.assertEqual(
                            request.headers['Content-MD5'],
                            base64.b64encode(
                                hashlib.md5(payload).digest()).decode('ascii'),
                        )
                        if formatter == 'aws4':
                            self.assertEqual(
                                request.headers['x-amz-content-sha256'],
                                hashlib.sha256(payload).hexdigest(),
                            )
                        if '--chunked' in flags:
                            self.assertNotIn('Content-Length', request.headers)
                            self.assertEqual(b''.join(body), payload)
                        else:
                            self.assertEqual(
                                int(request.headers['Content-Length']),
                                len(payload),
                            )
                            body.seek(0)
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
                                patch('httpie_hmac._body.SPOOL_MEMORY_SIZE',
                                      16), \
                                patch('requests.adapters.HTTPAdapter.send',
                                      side_effect=send) as adapter:
                            status = main([
                                'http', '--ignore-stdin', '--pretty=none',
                                '--auth-type=hmac',
                                '--auth=secret:dummy,access_id:EXAMPLE,format:'
                                + formatter,
                                *flags, 'POST',
                                'https://s3.eu-west-2.amazonaws.com/key',
                                'message=hello',
                            ], env=env)
                        self.assertEqual(status, 0, env.stderr.getvalue())
                        adapter.assert_called_once()
                    self.assertEqual(len(captured), 1)
                    self.assertTrue(all(spool.closed for spool in self.spools))

    def test_normal_httpie_limit_error_prevents_network(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Environment(config_dir=Path(directory), stdin=io.StringIO(),
                              stdout=io.StringIO(), stderr=io.StringIO())
            with patch.dict(os.environ, {}, clear=True), \
                    patch('requests.Session.send') as send:
                status = main([
                    'http', '--ignore-stdin', '--auth-type=hmac',
                    '--auth=secret:dummy,max_body_size:4', '--chunked',
                    'POST', 'https://s3.eu-west-2.amazonaws.com/key',
                    'message=hello',
                ], env=env)
            self.assertNotEqual(status, 0)
            self.assertIn('max_body_size', env.stderr.getvalue())
            send.assert_not_called()


class UploadLimitConfigurationTests(unittest.TestCase):
    def configure(self, raw_auth, env=None):
        with patch.dict(os.environ, env or {}, clear=True):
            plugin = HmacPlugin()
            plugin.raw_auth = raw_auth
            return plugin.get_auth()

    def test_default_and_cli_environment_precedence(self):
        self.assertEqual(self.configure('secret:dummy').max_body_size,
                         100 * 1024 * 1024)
        self.assertEqual(self.configure('secret:dummy', {
            'HTTPIE_HMAC_MAX_BODY_SIZE': '16',
        }).max_body_size, 16)
        self.assertEqual(self.configure('secret:dummy,max_body_size:32', {
            'HTTPIE_HMAC_MAX_BODY_SIZE': '16',
        }).max_body_size, 32)

    def test_invalid_limits_are_rejected(self):
        for value in ['', '0', '-1', '1.5', 'unlimited', None, True]:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError,
                                            'max_body_size.*positive integer'):
                    HmacAuth(None, 'dummy', 'simple', {'max_body_size': value})
