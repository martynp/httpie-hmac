# HTTPIE HMAC

This plugin is borrows heavily from the original work by Nick Statterly (https://github.com/guardian/httpie-hmac-auth) - that project was archived in May 2022.

This plugin extends the functionality to allow different HMAC patterns to be defined in the library and by a user provided script - thereby avoiding any requirement to create a new plugin to support a different pattern.

The httpie auth should be set to ``hmac`` and the ``--auth`` field contains key-value pairs to configure the plugin, the keys are:

* ``secret`` - base64 encoded secret to be used in the HMAC
* ``access`` - (Optional) String access token / id used to identify the user depending on the schema
* ``format`` - (Optional) Sets a pre-defined format or a python file to process the headers

For example:

```
http --auth-type=hmac --auth="secret:some_secret" GET http://localhost:8000
```

## Supported Formats

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
Authorization: HMAC [access]:[signature]
```

## Custom Format

A custom python file can be passed to the plug and used to generate bespoke formats, the following example implements the Simple formatter using a custom file:

```
import hmac
import hashlib
import base64

from httpie_hmac import HmacGenerate

class HmacAuthCustom(HmacGenerate):

    def generate(access_key, secret_key, method, content_type, content_md5, http_date, path, r):
        
        string_to_sign = '\n'.join(
            [method, content_md5, content_type, http_date, path]).encode()
        digest = hmac.new(secret_key, string_to_sign,
                          hashlib.sha256).digest()
        signature = base64.b64encode(digest).rstrip().decode('utf-8')

        if access_key == None or access_key == '':
            r.headers['Authorization'] = f"HMAC {signature}"
        else:
            r.headers['Authorization'] = f"HMAC {access_key}:{signature}"

        return r
```

Note that the ``r.headers`` dict will contain `content_type`, `content_md5` and `date` fields if they were not previously set. If they are not required they need to be removed from the list.

Additional data could be passed to the custom formatter using environment variables if needed.