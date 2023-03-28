# HTTPIE HMAC

This plugin is borrows heavily from the original work by Nick Statterly (https://github.com/guardian/httpie-hmac-auth) - that project was archived in May 2022.

This plugin extends the functionality to allow different HMAC patterns to be defined in the library and by a user provided script - thereby avoiding any requirement to create a new plugin to support a different pattern.

The httpie auth should be set to ``hmac`` and the ``--auth`` field contains key-value pairs to configure the plugin, the keys are:

* ``secret`` - base64 encoded secret to be used in the HMAC
* ``access_id`` - (Optional) String access token / id used to identify the user depending on the schema
* ``format`` - (Optional) Sets a pre-defined format or a python file to process the headers

Key-value pairs can also be set using environment variables starting with `HTTPIE_HMAC_`.

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

AWS4 uses the `AWSRequestsAuth` library to generate the required AWS auth header. It will attempt to get the required information from the provided URL, however the host, region and service fields can be set manually:

```
http --auth-type=hmac --auth="secret:7Ez...wVA,access_id:AK...6R,host:my_bucket.s3.eu-west-2.amazonaws.com,service:s3,region:eu-west-2:format:aws4" GET https://my_bucket.s3.eu-west-2.amazonaws.com/file.txt
```

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