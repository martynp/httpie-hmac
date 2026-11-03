"""S3 adaptation of aws-requests-auth's signing orchestration.

Copyright (c) David Muller.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification,
are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    3. The names of its contributors may not be used to endorse or promote
       products derived from this software without specific prior written
       permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""
import datetime
import hashlib
import hmac
from urllib.parse import quote, urlsplit

from aws_requests_auth.aws_auth import AWSRequestsAuth, getSignatureKey


class _S3RequestsAuth(AWSRequestsAuth):
    def _canonical_path(self, request):
        """Encode literal reserved characters, preserving prepared escapes.

        Requests leaves characters such as '+' and ':' literal in paths. S3
        requires '/a+b.txt' to sign as '/a%2Bb.txt', while '/a%2Bb.txt' must
        remain unchanged. Keep '%' and '/' safe to avoid double encoding or
        changing object-key separators; quote keeps unreserved bytes safe.
        """
        return quote(urlsplit(request.url).path or '/', safe='/%')

    def _headers_to_sign(self, request, generated):
        signing_headers = {}
        for name, value in request.headers.items():
            name = name.lower()
            if name == 'content-md5' or (
                name.startswith('x-amz-') and name != 'x-amz-content-sha256'
            ):
                signing_headers[name] = value
        signing_headers.update({name.lower(): value
                                for name, value in generated.items()})
        signing_headers['host'] = self.aws_host
        return signing_headers

    def get_aws_request_headers(self, r, aws_access_key,
                                aws_secret_access_key, aws_token):
        """Sign S3's prepared path and required request headers.

        Upstream calls AWSRequestsAuth.get_canonical_path explicitly, so a
        path-method override alone cannot change its signing behavior. Keep
        the orchestration here to avoid modifying the request or global state.
        S3 preserves escapes and repeated slashes in the prepared URL:
        /hello%20world.txt stays /hello%20world.txt, not /hello%2520world.txt.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        amzdate = now.strftime('%Y%m%dT%H%M%SZ')
        datestamp = now.strftime('%Y%m%d')
        headers = {'x-amz-date': amzdate}
        if aws_token:
            headers['X-Amz-Security-Token'] = aws_token

        # S3 requires Content-MD5 and supplied x-amz-* headers to be signed.
        # The payload hash is already bound below, so x-amz-content-sha256
        # can be omitted here. Generated date/token values replace stale ones.
        signing_headers = self._headers_to_sign(r, headers)
        names = sorted(signing_headers)
        canonical_headers = ''
        for name in names:
            value = signing_headers[name]
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            # Trim ends and collapse spaces/tabs, e.g. 'a  b\t c' -> 'a b c'.
            canonical_headers += f"{name}:{' '.join(value.split())}\n"
        signed_headers = ';'.join(names)

        payload_hash = getattr(r, '_hmac_payload_sha256', None)
        if payload_hash is None:
            body = r.body or b''
            if isinstance(body, str):
                body = body.encode('utf-8')
            payload_hash = hashlib.sha256(body).hexdigest()
        canonical_request = '\n'.join([
            r.method, self._canonical_path(r),
            self.get_canonical_querystring(r), canonical_headers,
            signed_headers, payload_hash,
        ])
        scope = f'{datestamp}/{self.aws_region}/{self.service}/aws4_request'
        string_to_sign = '\n'.join([
            'AWS4-HMAC-SHA256', amzdate, scope,
            hashlib.sha256(canonical_request.encode('utf-8')).hexdigest(),
        ])
        key = getSignatureKey(aws_secret_access_key, datestamp,
                              self.aws_region, self.service)
        signature = hmac.new(key, string_to_sign.encode('utf-8'),
                             hashlib.sha256).hexdigest()
        headers['Authorization'] = (
            f'AWS4-HMAC-SHA256 Credential={aws_access_key}/{scope}, '
            f'SignedHeaders={signed_headers}, Signature={signature}'
        )
        headers['x-amz-content-sha256'] = payload_hash
        return headers


class _StreamingAWSRequestsAuth(_S3RequestsAuth):
    """Use the precomputed stream hash with generic aws-requests-auth rules.

    The dependency hashes only in-memory bodies. Reuse the signing steps above
    while keeping its generic path and minimal header selection unchanged.
    """
    def _canonical_path(self, request):
        return AWSRequestsAuth.get_canonical_path(request)

    def _headers_to_sign(self, request, generated):
        headers = {'host': self.aws_host}
        headers.update({
            name.lower(): value for name, value in generated.items()
        })
        return headers
