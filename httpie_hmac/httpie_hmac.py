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

from ._s3_auth import _S3RequestsAuth, _StreamingAWSRequestsAuth
from ._body import (
    ChunkedBody,
    DEFAULT_MAX_BODY_SIZE,
    _BodyStream,
    body_size_limit,
    prepare_body,
)


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
    def _is_region(region):
        """Recognize region shapes such as eu-west-2 and us-gov-west-1.

        Require a two-letter prefix, alphabetic middle parts, and a numeric
        suffix. This heuristic does not check whether the region exists.
        """
        parts = region.split('-')
        return (len(parts) >= 3 and len(parts[0]) == 2
                and parts[0].isalpha()
                and all(part.isalpha() for part in parts[1:-1])
                and parts[-1].isdigit())

    def _infer_endpoint(hostname):
        """Return (region, service), or (None, None) for unknown layouts.

        Recognize service.region.amazonaws.com, regional S3 bucket endpoints,
        and api-id.execute-api.region.amazonaws.com. Also handle OpenSearch
        (search-example.eu-west-2.es.amazonaws.com -> ('eu-west-2', 'es'))
        and S3 dualstack (bucket.s3.dualstack.eu-west-2.amazonaws.com
        -> ('eu-west-2', 's3'), with or without a bucket prefix).
        """
        parts = (hostname or '').split('.')
        if parts[-2:] != ['amazonaws', 'com']:
            return None, None

        labels = parts[:-2]
        # OpenSearch domain endpoints put the region before the service.
        if (len(labels) == 3 and labels[-1] == 'es'
                and AWS4._is_region(labels[-2])):
            return labels[-2], 'es'

        if len(labels) < 2 or not AWS4._is_region(labels[-1]):
            return None, None

        region = labels[-1]
        if len(labels) >= 3 and labels[-3:-1] == ['s3', 'dualstack']:
            return region, 's3'
        service = labels[-2]
        if (service != 'dualstack' and
                (len(labels) == 2 or service == 's3' or
                 (len(labels) == 3 and service == 'execute-api'))):
            return region, service
        return None, None

    def generate(request):

        url = urlparse(request.inner.url)
        host = url.netloc
        region, service = AWS4._infer_endpoint(url.hostname)

        # Allow overrides
        if "host" in request.raw_settings:
            host = request.raw_settings["host"]
        region = request.raw_settings.get('region', region)
        service = request.raw_settings.get('service', service)
        if region is None:
            raise ValueError("AWS region could not be inferred so must be "
                             "set manually (e.g. eu-west-2)")
        if service is None:
            raise ValueError("AWS service could not be inferred so must "
                             "be set manually (e.g. s3)")

        auth_class = _S3RequestsAuth if service == 's3' else AWSRequestsAuth
        if service != 's3' and isinstance(request.inner.body, _BodyStream):
            auth_class = _StreamingAWSRequestsAuth
        auth = auth_class(
            aws_access_key=request.access_id,
            aws_secret_access_key=request.secret_key,
            aws_host=host,
            aws_region=region,
            aws_service=service,
            aws_token=request.raw_settings.get('session_token'),
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
        self.max_body_size = body_size_limit(
            raw_settings.get('max_body_size', DEFAULT_MAX_BODY_SIZE))

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
        body, size, md5, sha256 = prepare_body(r.body, self.max_body_size)
        r.body = body
        r._hmac_payload_sha256 = sha256
        r._body_position = 0 if isinstance(body, _BodyStream) else None
        try:
            return self._sign(r, size, md5)
        except BaseException:
            if isinstance(body, _BodyStream):
                body.close()
            raise

    def _sign(self, r, body_size, body_md5):

        # Method (GET, POST etc)
        method = r.method

        # Content type (e.g. application-json)
        content_type = r.headers.get('content-type')
        if not content_type:
            content_type = ''
        elif isinstance(content_type, bytes):
            content_type = content_type.decode('utf-8')

        # If content-md5 is already given, use it, otherwise calculate
        # it ourselves and add it to the headers
        content_md5 = r.headers.get('content-md5')
        if not content_md5:
            if content_type and body_size:
                content_md5 = body_md5
                r.headers['Content-MD5'] = content_md5
            else:
                content_md5 = ''
        elif isinstance(content_md5, bytes):
            content_md5 = content_md5.decode('utf-8')

        # If date is given already, use it - otherwise generate it
        # ourselves and add it to the headers
        http_date = r.headers.get('date')
        if not http_date:
            now = datetime.datetime.utcnow()
            http_date = now.strftime('%a, %d %b %Y %H:%M:%S GMT')
            r.headers['Date'] = http_date
        elif isinstance(http_date, bytes):
            http_date = http_date.decode('utf-8')

        # Get the path from the UL
        url = urlparse(r.url)
        path = url.path

        # Call the formatter to add the required headers and return r
        signed = self.formatter.generate(
            RequestData(self.access_id, self.secret_key,
                        method, content_type, content_md5, http_date, path,
                        self.raw_settings, r)
        )
        if isinstance(r.body, _BodyStream):
            signed.register_hook('response', r.body.close_after_response)
        transfer_encoding = signed.headers.get('Transfer-Encoding', '')
        if isinstance(transfer_encoding, bytes):
            transfer_encoding = transfer_encoding.decode('ascii')
        if any(token.strip() == 'chunked'
               for token in transfer_encoding.lower().split(',')):
            signed.headers.pop('Content-Length', None)
            signed.body = ChunkedBody(signed.body)
            signed._body_position = None
        return signed


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
                key, value = entry.strip().split(":", 1)
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
