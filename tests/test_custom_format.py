import tempfile
import textwrap
import unittest
from pathlib import Path

import requests

from httpie_hmac import HmacAuth


class CustomFormatTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / 'formatter.py'

    def test_custom_formatter_receives_request_data(self):
        self.path.write_text(textwrap.dedent('''\
            from httpie_hmac import HmacGenerate

            class HmacAuthCustom(HmacGenerate):
                def generate(request):
                    request.inner.headers['Authorization'] = 'Custom token'
                    request.inner.captured = request
                    return request.inner
        '''), encoding='utf-8')
        settings = {'custom': 'value'}
        auth = HmacAuth('EXAMPLE', 'dummy', str(self.path), settings)
        request = requests.Request(
            'POST', 'https://example.com/path?query=value', data=b'hello',
            headers={'Content-Type': 'text/plain',
                     'Date': 'Tue, 03 Nov 2026 12:00:00 GMT'},
            auth=auth,
        ).prepare()
        captured = request.captured
        self.assertIs(captured.inner, request)
        self.assertEqual(captured.access_id, 'EXAMPLE')
        self.assertEqual(captured.secret_key, 'dummy')
        self.assertEqual(captured.method, 'POST')
        self.assertEqual(captured.path, '/path')
        self.assertEqual(captured.content_type, 'text/plain')
        self.assertEqual(captured.content_md5, 'XUFAKrxLKna5cZ2REBfFkg==')
        self.assertEqual(captured.http_date,
                         'Tue, 03 Nov 2026 12:00:00 GMT')
        self.assertEqual(captured.raw_settings, settings)
        self.assertEqual(request.headers['Authorization'], 'Custom token')

    def test_invalid_subclass_is_rejected(self):
        self.path.write_text('class HmacAuthCustom: pass\n', encoding='utf-8')
        with self.assertRaisesRegex(TypeError, 'must inherit'):
            HmacAuth(None, 'dummy', str(self.path), {})

    def test_missing_formatter_file_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            HmacAuth(None, 'dummy', str(self.path), {})

    def test_missing_formatter_class_is_rejected(self):
        self.path.write_text('value = 1\n', encoding='utf-8')
        with self.assertRaises(AttributeError):
            HmacAuth(None, 'dummy', str(self.path), {})
