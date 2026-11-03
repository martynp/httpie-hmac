import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


class HTTPieCLITests(unittest.TestCase):
    def run_httpie(self, auth, env=None, url='https://example.com/file.txt',
                   headers=()):
        # A separate working/config directory ensures entry-point discovery
        # uses the installed package and ignores local HTTPie sessions/config.
        with tempfile.TemporaryDirectory() as directory:
            cli_env = {key: value for key, value in os.environ.items()
                       if not key.startswith(('HTTPIE_', 'AWS_'))
                       and key != 'PYTHONPATH'}
            cli_env.update({
                'HTTPIE_CONFIG_DIR': str(Path(directory) / 'config'),
                'NETRC': str(Path(directory) / 'absent-netrc'),
                'NO_COLOR': '1',
            })
            cli_env.update(env or {})
            return subprocess.run(
                [sys.executable, '-m', 'httpie', '--offline', '--ignore-stdin',
                 '--pretty=none', '--print=H', '--auth-type=hmac',
                 '--auth=' + auth, 'GET', url, *headers],
                cwd=directory, env=cli_env, capture_output=True, text=True,
                timeout=30,
            )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('GET /file.txt HTTP/', result.stdout)

    def test_simple_plugin_is_discovered_and_signs(self):
        result = self.run_httpie(
            'secret:dummy-secret,access_id:EXAMPLE',
            headers=('Date:Tue, 03 Nov 2026 12:00:00 GMT',),
        )
        self.assert_success(result)
        self.assertIn('Authorization: HMAC EXAMPLE:'
                      'SHf/C6vMFCl3QHXymJlpu9uysznqveMux9amdt50V2U=',
                      result.stdout)

    def test_aws4_plugin_signs_with_session_token(self):
        result = self.run_httpie(
            'secret:dummy,access_id:EXAMPLE,format:aws4,session_token:token',
            url='https://bucket.s3.eu-west-2.amazonaws.com/file.txt',
        )
        self.assert_success(result)
        output = result.stdout.lower()
        self.assertIn('authorization: aws4-hmac-sha256 credential=example/',
                      output)
        self.assertIn('/eu-west-2/s3/aws4_request', output)
        self.assertIn('x-amz-security-token: token', output)

    def test_environment_configuration(self):
        result = self.run_httpie('', env={
            'HTTPIE_HMAC_SECRET': 'dummy-secret',
            'HTTPIE_HMAC_ACCESS_ID': 'ENVIRONMENT',
            'HTTPIE_HMAC_FORMAT': 'simple',
        })
        self.assert_success(result)
        self.assertIn('Authorization: HMAC ENVIRONMENT:', result.stdout)

    def test_aws_host_with_port_is_accepted(self):
        result = self.run_httpie(
            'secret:dummy,access_id:EXAMPLE,format:aws4,'
            'host:localhost:9000,region:eu-west-2,service:es',
            url='http://localhost:9000/file.txt',
        )
        self.assert_success(result)
        self.assertIn('/eu-west-2/es/aws4_request', result.stdout)
        self.assertIn('Host: localhost:9000', result.stdout)

    def test_invalid_configuration_returns_error(self):
        result = self.run_httpie('format:aws4')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('HMAC secret key cannot be empty', result.stderr)
