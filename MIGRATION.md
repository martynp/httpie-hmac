# Migrate from version 1.x to 2.0.0

Version 2.0.0 changes upload limits and body handling for custom formatters.
Use these steps to update your configuration and code.

## 1. Install version 2.0.0

Install the package in the environment that contains HTTPie:

``` bash
python -m pip install --upgrade 'httpie-hmac==2.0.0'
```

## 2. Check your upload size

The default upload limit is now 100 MiB (104857600 bytes).
The plugin rejects larger uploads before transmission.
The limit includes multipart data and UTF-8 encoding.

For uploads up to 200 MiB, set this environment variable:

``` bash
export HTTPIE_HMAC_MAX_BODY_SIZE=209715200
```

You can also add `max_body_size:209715200` to your `--auth` settings.
Command-line settings override environment variables.
Use a positive integer in bytes. An unlimited setting is not available.

## 3. Update custom formatters

Do this step if your formatter reads `request.inner.body`.
The body can now be bytes, a seekable binary stream, or `None`.
Read streams in small blocks. Restore the stream position after reading.
Do not close the body or change its contents in the formatter.

This example calculates a SHA256 hash for each body type:

``` python
import hashlib


def body_sha256(body):
    digest = hashlib.sha256()
    if body is None:
        return digest.hexdigest()
    if isinstance(body, bytes):
        digest.update(body)
        return digest.hexdigest()

    position = body.tell()
    try:
        while True:
            block = body.read(64 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        body.seek(position)
    return digest.hexdigest()
```

## 4. Close prepared bodies in Python applications

Do this step if your code sends requests directly with Requests.
Close a file-like prepared body in a `finally` block after use.
For example, call `prepared.body.close()` if the body has a `close` method.
This is also necessary after a network error or an offline preview.
Do not replay a closed body.

The plugin closes temporary files after a final HTTP response.
It does not close caller-owned input streams.
Without a final response, HTTPie can depend on object cleanup to close files.

## 5. Check AWS settings and compression

Explicit `region` and `service` settings now override inferred values.
Check old overrides that were previously ignored.
Set both values for endpoint layouts that the plugin cannot identify.

Do not use HTTPie's `--compress` option with HMAC authentication.
Compression still occurs after signing and can make the signature invalid.
The plugin does not reject this combination.

For more information, see [upload limits and cleanup](README.md#upload-preparation-and-limits).
