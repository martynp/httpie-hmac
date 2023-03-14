"""
HMAC Auth (the second) plugin for HTTPie.

Original Author: Nick Satterly (https://github.com/guardian/httpie-hmac-auth)
Extended by: Martyn Pittuck-Schols

"""
import datetime
import base64
import hashlib
import hmac

import types
import importlib.machinery

from httpie.plugins import AuthPlugin

from urllib.parse import urlparse


class HmacGenerate:
    def generate(access_key,
                 secret_key,
                 method,
                 content_type,
                 content_md5,
                 http_date,
                 path,
                 r):
        pass


class Simple(HmacGenerate):
    def generate(access_key,
                 secret_key,
                 method,
                 content_type,
                 content_md5,
                 http_date,
                 path,
                 r):

        string_to_sign = '\n'.join(
            [method, content_md5, content_type, http_date, path]).encode()
        digest = hmac.new(secret_key, string_to_sign,
                          hashlib.sha256).digest()
        signature = base64.b64encode(digest).rstrip().decode('utf-8')

        if access_key is None or access_key == '':
            r.headers['Authorization'] = f"HMAC {signature}"
        elif secret_key == '':
            raise ValueError('HMAC secret key cannot be empty.')
        else:
            r.headers['Authorization'] = f"HMAC {access_key}:{signature}"

        return r


generators = {
    'simple': Simple,
}


class HmacAuth:
    def __init__(self, access_key, secret_key, format):
        self.access_key = access_key
        self.secret_key = secret_key
        self.secret_key_bytes = bytes(secret_key, 'UTF-8')
        self.use_custom = False
        self.formatter = None

        if format is not None:

            # Attempt to load a custom processor
            if format.endswith(".py"):
                loader = importlib.machinery.SourceFileLoader(
                    'HmacAuthCustom', format)
                mod = types.ModuleType(loader.name)
                loader.exec_module(mod)
                if issubclass(mod.HmacAuthCustom, HmacGenerate) is False:
                    raise TypeError(
                        "Custom generator must inherit "
                        "httpie_hmac.HmacGenerate")
                self.formatter = mod.HmacAuthCustom
            else:
                self.formatter = generators[format]

        else:
            self.formatter = Simple

    def __call__(self, r):

        # Method (GET, POST etc)
        method = r.method

        # Content type (e.g. application-json)
        content_type = r.headers.get('content-type')
        if not content_type:
            content_type = ''

        # If content-md5 is already given, use it, otherwise calculate
        # it ourselves and add it to the headers
        content_md5 = r.headers.get('content-md5')
        if not content_md5:
            if content_type:
                m = hashlib.md5()
                m.update(r.body)
                content_md5 = base64.b64encode(m.digest()).rstrip()
                r.headers['Content-MD5'] = content_md5
            else:
                content_md5 = ''

        # If date is given already, use it - otherwise generate it
        # ourselves and add it to the headers
        http_date = r.headers.get('date')
        if not http_date:
            now = datetime.datetime.utcnow()
            http_date = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
            r.headers['Date'] = http_date

        # Get the path from the UL
        url = urlparse(r.url)
        path = url.path

        # Call the formatter to add the required headers and return r
        return self.formatter.generate(self.access_key,
                                       self.secret_key_bytes,
                                       method,
                                       content_type,
                                       content_md5,
                                       http_date,
                                       path,
                                       r)


class HmacPlugin(AuthPlugin):

    name = 'HMAC Auth PLugin'
    auth_type = 'hmac'
    description = 'Generic HMAC plugin with customizable format'
    auth_parse = False

    def get_auth(self, username=None, password=None):
        '''
        This method is called by the auth plugin manager, by setting auth_parse
        to False the --auth argument is not parsed and is available in raw_auth


        '''
        split = self.raw_auth.split(",")

        access = None
        secret = None
        format = None

        for entry in split:
            key, value = entry.strip().split(":")
            key = key.strip()
            value = value.strip()
            if key == "access":
                access = value
            elif key == "secret":
                secret = value
            elif key == "format":
                format = value

        return HmacAuth(access, secret, format)
