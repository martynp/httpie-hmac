# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.0] - 2026-11-03

### Added

- A [migration guide](MIGRATION.md) for upgrades from version 1.x.
- A configurable `max_body_size` / `HTTPIE_HMAC_MAX_BODY_SIZE` upload limit,
  defaulting to 100 MiB and enforced against actual payload bytes.
- Package functionality tests and offline HTTPie integration checks, with CI
  execution on Python 3.11 and 3.13.
- Support temporary AWS credentials in the AWS4 formatter through `session_token`
  or `HTTPIE_HMAC_SESSION_TOKEN`, including the token in signed requests.

### Changed

- **Breaking:** Uploads larger than 100 MiB now require an explicit
  `max_body_size` setting. There is no unlimited setting.
- **Breaking:** Custom formatters must accept seekable file-like bodies as
  well as bytes, and restore the position after reading a body. Stream-backed
  prepared bodies have explicit cleanup requirements; see the migration guide.
- Document unsupported HTTPie request compression with HMAC authentication and
  add expected-failure regressions for checksums and signatures calculated
  before the body is compressed. Compression support remains unresolved.

### Fixed

- Encode literal reserved characters such as `+` and `:` in S3 canonical paths
  while preserving existing percent escapes and path separators.
- Preserve colons within authentication setting values, including signing hosts
  with ports such as `host:localhost:9000`.
- Prepare text, file-like, and iterable uploads with incremental hashing and
  bounded-memory temporary spooling, supporting HTTPie multipart and chunked
  uploads while preserving chunked framing and caller-owned streams.
- Include Content-MD5 and required x-amz-* request headers in S3 AWS4 signatures,
  with canonical header ordering and whitespace handling.
- Preserve prepared S3 object paths during AWS4 signing instead of encoding
  percent escapes a second time, while retaining other services' signing rules.
- Honor explicit AWS region and service overrides independently of endpoint
  inference, correctly infer OpenSearch domain and S3 dualstack endpoints, and
  require explicit settings for unrecognized endpoint layouts.
- Accept both string and byte values for existing Content-Type, Content-MD5,
  and Date headers without failing before signing.
- Correct the separator before `format` in the README AWS4 override example
  so its authentication settings parse successfully.
