"""Bounded upload preparation shared by the HMAC formatters."""
import base64
import hashlib
import tempfile


CHUNK_SIZE = 64 * 1024
SPOOL_MEMORY_SIZE = 1024 * 1024
DEFAULT_MAX_BODY_SIZE = 100 * 1024 * 1024


def body_size_limit(value=DEFAULT_MAX_BODY_SIZE):
    """Accept a positive integer byte limit; there is no unlimited sentinel."""
    if isinstance(value, bool):
        raise ValueError('max_body_size must be a positive integer in bytes')
    try:
        limit = int(value)
    except (TypeError, ValueError, OverflowError):
        limit = 0
    if limit <= 0 or str(limit) != str(value).strip():
        raise ValueError('max_body_size must be a positive integer in bytes')
    return limit


class _BodyStream:
    """A binary view beginning at the input's original position.

    Closing an owned spool releases its temporary file. Caller-owned files
    remain open. The view supplies Requests with its remaining byte length.
    """
    def __init__(self, source, start, size, owned=False):
        self.source = source
        self.start = start
        self.len = size
        self.owned = owned
        self.closed = False

    def read(self, size=-1):
        if self.closed:
            raise ValueError('upload body is closed')
        remaining = max(0, self.len - self.tell())
        amount = remaining if size < 0 else min(size, remaining)
        return self.source.read(amount)

    def tell(self):
        return self.source.tell() - self.start

    def seek(self, offset, whence=0):
        if self.closed:
            raise ValueError('upload body is closed')
        if whence == 1:
            offset += self.tell()
        elif whence == 2:
            offset += self.len
        elif whence != 0:
            raise ValueError('invalid seek mode')
        if offset < 0:
            raise ValueError('negative upload position')
        self.source.seek(self.start + offset)
        return self.tell()

    def close(self):
        if self.owned and not self.closed:
            self.source.close()
        self.closed = True

    def close_after_response(self, response, **kwargs):
        # Redirects may replay the same body. Keep it until the final response.
        if not response.is_redirect:
            self.close()
        return response

    def __del__(self):
        # Requests has no error/offline-completion hook. Explicit close and the
        # response hook cover normal use; abandoned requests need the fallback.
        self.close()


class ChunkedBody:
    """Replay a signed payload without exposing a length to Requests.

    A length here makes Requests add Content-Length after auth even though the
    request already has Transfer-Encoding: chunked.
    """
    def __init__(self, body):
        self.body = body

    def __iter__(self):
        if isinstance(self.body, _BodyStream):
            self.body.seek(0)
            while True:
                chunk = self.body.read(CHUNK_SIZE)
                if not chunk:
                    break
                yield chunk
        elif self.body:
            yield self.body

    def close(self):
        if isinstance(self.body, _BodyStream):
            self.body.close()


def prepare_body(body, limit):
    """Hash bounded chunks, rewind binary files, and spool other streams.

    Return (transmission body, size, base64 MD5, hex SHA256). Read from the
    current position; never close a file owned by the caller. Input sizes are
    measured while reading, independent of Content-Length or iterator hints.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    total = 0
    spool = None
    start = None
    source = None
    direct = isinstance(body, bytes) or body is None
    try:
        if isinstance(body, memoryview):
            body = body.cast('B')
        if direct:
            chunks = (memoryview(body or b'')[offset:offset + CHUNK_SIZE]
                      for offset in range(0, len(body or b''), CHUNK_SIZE))
            if len(body or b'') > limit:
                raise ValueError(
                    f'upload exceeds max_body_size ({limit} bytes)')
        elif isinstance(body, (str, bytearray, memoryview)):
            if len(body) > limit:
                raise ValueError(
                    f'upload exceeds max_body_size ({limit} bytes)')
            chunks = (body[offset:offset + CHUNK_SIZE]
                      for offset in range(0, len(body), CHUNK_SIZE))
        elif hasattr(body, 'read'):
            source = body
            try:
                start = body.tell()
                body.seek(start)
            except (AttributeError, OSError, ValueError):
                start = None

            def read_chunks():
                while True:
                    chunk = body.read(min(CHUNK_SIZE, limit - total + 1))
                    if chunk is None:
                        raise ValueError('upload read returned None; '
                                         'nonblocking inputs are unsupported')
                    if not chunk:
                        break
                    yield chunk

            chunks = read_chunks()
        else:
            chunks = iter(body)

        for chunk in chunks:
            if not isinstance(chunk, (str, bytes, bytearray, memoryview)):
                raise TypeError('upload chunks must be bytes or text')
            if isinstance(chunk, memoryview):
                chunk = chunk.cast('B')
            # Reject an oversized yielded chunk before encoding/copying it or
            # writing it to disk. UTF-8 needs at least one byte per character.
            if len(chunk) > limit - total:
                raise ValueError(
                    f'upload exceeds max_body_size ({limit} bytes)')
            # Iterate over large externally yielded chunks in bounded slices.
            for offset in range(0, len(chunk), CHUNK_SIZE):
                piece = chunk[offset:offset + CHUNK_SIZE]
                if isinstance(piece, str):
                    piece = piece.encode('utf-8')
                size = len(piece)
                if size > limit - total:
                    raise ValueError(
                        f'upload exceeds max_body_size ({limit} bytes)')
                if (isinstance(chunk, str) and source is not None
                        and start is not None and spool is None and total):
                    raise TypeError('seekable upload changed from bytes '
                                    'to text while reading')
                if not direct and (start is None or isinstance(chunk, str)
                                   or spool is not None):
                    if spool is None:
                        spool = tempfile.SpooledTemporaryFile(
                            max_size=SPOOL_MEMORY_SIZE, mode='w+b')
                    # Roll over before writing the threshold-crossing chunk.
                    if total + size > SPOOL_MEMORY_SIZE:
                        spool.rollover()
                    spool.write(piece)
                total += size
                md5.update(piece)
                sha256.update(piece)

        if spool is not None:
            spool.seek(0)
            if total <= SPOOL_MEMORY_SIZE:
                prepared = spool.read()
                spool.close()
            else:
                prepared = _BodyStream(spool, 0, total, owned=True)
                spool = None
        elif source is not None and start is not None and total:
            source.seek(start)
            prepared = _BodyStream(source, start, total)
        elif direct:
            prepared = body
        else:
            # Empty text/iterables need no spool or open temporary resource.
            prepared = b''
        encoded_md5 = base64.b64encode(md5.digest()).decode('ascii')
        return prepared, total, encoded_md5, sha256.hexdigest()
    except BaseException:
        if spool is not None:
            spool.close()
        raise
    finally:
        if source is not None and start is not None:
            source.seek(start)
