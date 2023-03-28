"""
HMAC Auth (the second) plugin for HTTPie.

Original Author: Nick Satterly (https://github.com/guardian/httpie-hmac-auth)
Extended by: Martyn Pittuck-Schols

"""
import base64
import datetime
import hashlib
import hmac
import importlib.machinery
import os
import requests
import types

from aws_requests_auth.aws_auth import AWSRequestsAuth
from dataclasses import dataclass
from urllib.parse import urlparse

from httpie.plugins import AuthPlugin


@dataclass
class RequestData:
    access_id: str
    secret_key: str
    method: str
    content_type: str
    content_md5: str
    http_date: str
    path: str
    raw_settings: dict
    inner: requests.models.PreparedRequest


class HmacGenerate:
    def generate(request: RequestData):
        pass


class Simple(HmacGenerate):
    def generate(request):

        string_to_sign = '\n'.join(
            [request.method, request.content_md5, request.content_type,
             request.http_date, request.path]).encode()
        digest = hmac.new(bytes(request.secret_key, 'UTF-8'), string_to_sign,
                          hashlib.sha256).digest()
        signature = base64.b64encode(digest).rstrip().decode('utf-8')

        if request.access_id is None or request.access_id == '':
            request.inner.headers['Authorization'] = f"HMAC {signature}"
        else:
            request.inner.headers['Authorization'] = \
                f"HMAC {request.access_id}:{signature}"

        return request.inner


class AWS4(HmacGenerate):
    def generate(request):

        url = urlparse(request.inner.url).netloc

        host = url
        region = None
        service = None

        # Only try and get the rest of the parts if we know the domain
        # is correct
        url_parts = url.split(".")
        if ".".join(url_parts[-2:]) == "amazonaws.com" and len(url_parts) >= 4:
            region = url_parts[-3]
            service = url_parts[-4]

        # Allow overrides
        if "host" in request.raw_settings:
            host = request.raw_settings["host"]
        if region is None:
            if "region" not in request.raw_settings:
                raise ValueError("AWS region could not be inferred so must be "
                                 "set manually (e.g. eu-west-2)")
            else:
                region = request.raw_settings["region"]
        if service is None:
            if "service" not in request.raw_settings:
                raise ValueError("AWS service could not be inferred so must "
                                 "be set manually (e.g. s3)")
            else:
                service = request.raw_settings["service"]

        auth = AWSRequestsAuth(
            aws_access_key=request.access_id,
            aws_secret_access_key=request.secret_key,
            aws_host=host,
            aws_region=region,
            aws_service=service,
        )

        return auth.__call__(request.inner)


generators = {
    'aws4': AWS4,
    'simple': Simple,
}


class HmacAuth:
    def __init__(self, access_id, secret_key, format, raw_settings):
        self.access_id = access_id
        self.secret_key = secret_key
        self.use_custom = False
        self.formatter = None
        self.raw_settings = raw_settings

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
            if content_type and r.body:
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
        return self.formatter.generate(
            RequestData(self.access_id, self.secret_key,
                        method, content_type, content_md5, http_date, path,
                        self.raw_settings, r)
        )


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

        settings = {}

        # If env settings exist set them as default, auth settings will
        # override
        for setting in os.environ.items():
            if setting[0].startswith("HTTPIE_HMAC_"):
                key = setting[0].split("HTTPIE_HMAC_")[1].lower()
                settings[key] = setting[1]

        access_id = settings.get("access_id", None)
        secret = settings.get("secret", None)
        format = settings.get("format", None)

        if len(self.raw_auth) > 0:
            split = self.raw_auth.split(",")
            for entry in split:
                key, value = entry.strip().split(":")
                key = key.strip()
                value = value.strip()
                if key == "access_id":
                    access_id = value
                elif key == "secret":
                    secret = value
                elif key == "format":
                    format = value
                settings[key] = value

        if secret is None or secret == '':
            raise ValueError('HMAC secret key cannot be empty.')

        return HmacAuth(access_id, secret, format, settings)
