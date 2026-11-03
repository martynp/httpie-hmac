import base64
import hashlib
import hmac
import io
import os
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

from httpie.context import Environment
from httpie.core import main


class CompressionLimitationTests(unittest.TestCase):
    def setUp(self):
        # Setup errors must remain errors, not be hidden by expectedFailure.
        # Capture requests after HTTPie's real transformation pipeline, at the
        # point where they would be displayed. Offline mode prohibits sending.
        self.requests = {}
        for formatter in ['simple', 'aws4']:
            with tempfile.TemporaryDirectory() as directory:
                env = Environment(
                    config_dir=Path(directory), stdin=io.StringIO(),
                    stdout=io.StringIO(), stderr=io.StringIO(),
                )
                captured = []

                def capture_message(**kwargs):
                    captured.append(kwargs['requests_message'])

                with patch.dict(os.environ, {}, clear=True), \
                        patch('httpie.core.write_message', capture_message), \
                        patch('requests.Session.send') as send:
                    status = main([
                        'http', '--offline', '--ignore-stdin', '--pretty=none',
                        '--compress', '--compress', '--auth-type=hmac',
                        '--auth=secret:dummy,access_id:EXAMPLE,format:'
                        + formatter,
                        'POST', 'https://s3.eu-west-2.amazonaws.com/key',
                        'message=hello',
                    ], env=env)
                self.assertEqual(status, 0, env.stderr.getvalue())
                send.assert_not_called()
                self.assertEqual(len(captured), 1)
                request = captured[0]
                self.assertEqual(request.headers['Content-Encoding'],
                                 'deflate')
                self.assertEqual(zlib.decompress(request.body),
                                 b'{"message": "hello"}')
                self.assertIn('Authorization', request.headers)
                if formatter == 'aws4':
                    self.assertIn('x-amz-content-sha256', request.headers)
                self.requests[formatter] = request

    @unittest.expectedFailure
    def test_simple_checksum_and_signature_match_final_compressed_body(self):
        # HTTPie currently compresses after signing, leaving both values stale.
        request = self.requests['simple']
        final_md5 = base64.b64encode(
            hashlib.md5(request.body).digest()).decode('ascii')
        string_to_sign = '\n'.join([
            request.method, final_md5, 'application/json',
            request.headers['Date'], '/key',
        ])
        signature = base64.b64encode(hmac.new(
            b'dummy', string_to_sign.encode(), hashlib.sha256,
        ).digest()).decode('ascii')
        self.assertEqual(
            (request.headers['Content-MD5'], request.headers['Authorization']),
            (final_md5, 'HMAC EXAMPLE:' + signature),
        )

    @unittest.expectedFailure
    def test_aws_checksums_match_final_compressed_body(self):
        # Both generated checksums currently describe the uncompressed JSON.
        request = self.requests['aws4']
        self.assertEqual(
            (request.headers['Content-MD5'],
             request.headers['x-amz-content-sha256']),
            (base64.b64encode(hashlib.md5(request.body).digest())
             .decode('ascii'), hashlib.sha256(request.body).hexdigest()),
        )
