# HTTPIE HMAC

For upgrades from version 1.x to 2.0.0, follow the [migration guide](MIGRATION.md).

This plugin is borrows heavily from the original work by Nick Statterly (https://github.com/guardian/httpie-hmac-auth) - that project was archived in May 2022.

This plugin extends the functionality to allow different HMAC patterns to be defined in the library and by a user provided script - thereby avoiding any requirement to create a new plugin to support a different pattern.

The httpie auth should be set to ``hmac`` and the ``--auth`` field contains key-value pairs to configure the plugin, the keys are:

* ``secret`` - base64 encoded secret to be used in the HMAC
* ``access_id`` - (Optional) String access token / id used to identify the user depending on the schema
* ``format`` - (Optional) Sets a pre-defined format or a python file to process the headers
* ``session_token`` - (Optional, AWS4 only) Session token for temporary AWS credentials
* ``max_body_size`` - (Optional) Maximum upload size in bytes; defaults to 104857600 (100 MiB)

Key-value pairs can also be set using environment variables starting with `HTTPIE_HMAC_`.

The first colon separates each key from its value; additional colons are kept
in the value, so `host:localhost:9000` is supported. Commas separate settings.

For example:

``` bash
http --auth-type=hmac --auth="secret:some_secret" GET http://localhost:8000
http --auth-type=hmac --auth="secret:7Ez...wVA,access_id:AK...6R,format:aws4" GET https://my_bucket.s3.eu-west-2.amazonaws.com/file.txt

export HTTPIE_HMAC_SECRET=7Ez...wVA
export HTTPIE_HMAC_ACCESS_ID=AK...6R
export HTTPIE_HMAC_FORMAT=aws4
httpie --auth-type=hmac --auth="" GET https://my_bucket.s3.eu-west-2.amazonaws.com/file.txt
```

## Supported Formats

### AWS4 (aws4)

AWS4 uses the `AWSRequestsAuth` library to generate the required AWS auth header. It will attempt to get the required information from the provided URL, however the host, region and service fields can be set manually.

Explicit `region` and `service` settings each override the inferred value.
Inference supports `service.region.amazonaws.com`, regional S3 bucket endpoints
(including dualstack), API Gateway API endpoints, and OpenSearch domain
endpoints. Other layouts require explicit `region` and `service` settings.
Hostname service names that differ from the AWS signing service name also need
an explicit `service` setting. The `host` setting overrides the signing host;
inference still uses the request URL.

For example:

```
http --auth-type=hmac --auth="secret:7Ez...wVA,access_id:AK...6R,host:my_bucket.s3.eu-west-2.amazonaws.com,service:s3,region:eu-west-2,format:aws4" GET https://my_bucket.s3.eu-west-2.amazonaws.com/file.txt
```

For temporary AWS credentials (such as credentials obtained through STS or an
assumed role), supply the session token alongside the matching access key ID and
secret access key. The AWS4 signer includes it as `X-Amz-Security-Token`:

``` bash
export HTTPIE_HMAC_ACCESS_ID="$AWS_ACCESS_KEY_ID"
export HTTPIE_HMAC_SECRET="$AWS_SECRET_ACCESS_KEY"
export HTTPIE_HMAC_SESSION_TOKEN="$AWS_SESSION_TOKEN"
http --auth-type=hmac --auth="format:aws4" GET https://my-bucket.s3.eu-west-2.amazonaws.com/file.txt
```

You can also pass `session_token:YOUR_SESSION_TOKEN` in the comma-separated
`--auth` settings. Command-line settings override the corresponding
`HTTPIE_HMAC_` environment variables. Supply the AWS secret access key as issued,
without decoding it. Credentials must be supplied explicitly; this plugin does
not discover AWS profiles or refresh expired credentials. When switching to
long-lived credentials, unset `HTTPIE_HMAC_SESSION_TOKEN`.

### Simple (simple)

The string_to_sign consists of the HTTP method, content_md5, content_type, http_date and path:

```
[method]\n
[content_md5]\n
[content_type]\n
[http_date]\n
[path]
```

This string is signed using the sha256 HMAC. The resulting signature is placed in the "Authorization" header in the format:

```
Authorization: HMAC [signature]
Authorization: HMAC [access_id]:[signature]
```

## Custom Format

A custom python file can be passed to the plug and used to generate bespoke formats, the following example implements the Simple formatter using a custom file:

```
import hmac
import hashlib
import base64

from httpie_hmac import HmacGenerate

class HmacAuthCustom(HmacGenerate):

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
```

Note that the ``request.inner.headers`` dictionary will contain `content_type`, `content_md5` and `date` fields if they were not previously set. If they are not required they need to be removed from the list.

Additional data could be passed to the custom formatter using environment variables if needed.

## Upload preparation and limits

Uploads are hashed before transmission, including multipart and chunked bodies.
Seekable binary inputs are read in 64 KiB chunks and rewound to their original
position. Nonseekable and text inputs use a temporary spool, which holds up to
1 MiB of payload in memory before rolling over to disk. Chunked framing is
preserved.

Every body has a default maximum of **100 MiB** (104857600 bytes). Set
`max_body_size:209715200` in `--auth`, or export
`HTTPIE_HMAC_MAX_BODY_SIZE=209715200`, to allow up to 200 MiB. CLI settings take
precedence. The limit must be a positive integer; unlimited values are not
accepted. It counts actual payload bytes, including UTF-8 encoding, independently
of a supplied `Content-Length`. Preparation stops with an error when the limit
is exceeded, before transmission. This counts payload bytes, excluding wire
chunk-framing overhead, and bounds spool disk usage per request. Concurrent
uploads have separate limits. It does not bound allocations made by HTTPie or a
custom input producer before this plugin receives the body, or time spent
waiting for a blocked input source.

Custom formatters should support a seekable file-like `request.inner.body` as
well as bytes. Reading it must preserve/restore its position before returning.
Small nonseekable inputs are converted to bytes; larger spools remain file-like.
Caller-owned streams are never closed by the plugin.

Temporary files close on preparation/signing errors and on the final HTTP
response; redirects retain the body for replay. Python callers should also close
a file-like prepared body in a `finally` block after sending or previewing it,
especially on network errors. HTTPie's auth API has no offline-completion or
network-error cleanup hook, so offline/abandoned requests additionally rely on
object cleanup to release their spool. A closed body cannot be replayed.
HTTPie's request-body output callbacks can run during preparation; spooled
uploads may not appear in verbose request-body output.

## Known limitations

Do not combine HMAC authentication with HTTPie's `--compress` option (including
repeated `--compress`). HTTPie applies request compression after this plugin
calculates its checksums and signature. If the body is compressed, the generated
`Content-MD5` no longer matches the payload; AWS4's `x-amz-content-sha256` and
signature also describe the original body. This affects Simple, AWS4, and custom
formats that sign the body or its checksums, including offline request previews.
The plugin does not detect or reject this combination. Omit `--compress` when
using HMAC authentication. Supporting it requires an HTTPie authentication hook
after request transformations and before preview or transmission.

## Testing

Install the package in a virtual environment before running the suite so HTTPie
can discover the authentication plugin through its installed entry point:

``` bash
python -m venv .venv
source .venv/bin/activate
python -m pip install .
python -m unittest discover -s tests -v
```

The tests use dummy credentials and run offline, including the HTTPie CLI tests.
They require no AWS account or secrets. CI runs the same suite on Python 3.11
and 3.13; the existing live AWS smoke test is a separate job.
Compression regression tests are marked as expected failures until HTTPie
provides the integration needed to sign the final payload.
