# nanos3reader

A minimal, **read-only S3 range reader** for C++. It opens `s3://bucket/key` (and any S3-compatible
store — MinIO, R2, …) as a **seekable, read-ahead-buffered `std::istream`** backed by libcurl range
`GET`s and AWS SigV4 signing — using nothing but **libcurl + a small SHA-256**. No AWS SDK.

It does one thing well: fetch byte ranges out of S3 objects, with the full AWS credential chain. It is
**read-only / `GET`-only** by design — no `PUT`, multipart, or `LIST`.

```cpp
#include "nanos3reader/s3_reader.h"

nanos3reader::S3MinStreamFactory factory;
auto stream = factory.open("s3://my-bucket/path/to/object", /*read_ahead=*/1 << 16);
if (!stream) { /* factory.error() explains why */ }

stream->seekg(1024);
char buf[4096];
stream->read(buf, sizeof buf);          // a range GET, served from a reused keep-alive connection
```

## Why

The AWS SDK for C++ is huge (100s of MB, deep dependency tree, slow builds). If all you need is to
*read* ranges from S3, nanos3reader is ~1k lines and two dependencies. It reuses one keep-alive
connection per object, so streaming many small ranges from a few objects is fast.

## Features

- Seekable `std::istream` over S3 range `GET`s, with read-ahead buffering and **one keep-alive
  connection reused per object**.
- **AWS SigV4** signing (validated against AWS's published test vectors — see `tests/sigv4_test.cpp`).
- **Full credential chain**, the way the AWS tools resolve it:
  environment → shared profile files (`~/.aws/credentials` + `~/.aws/config`, honoring `AWS_PROFILE`,
  **including a profile's `credential_process`** helper) → ECS/EKS container credentials → EC2 instance
  role (IMDSv2). Temporary credentials are refreshed before they expire. *(AWS SSO and assume-role
  profiles are not resolved — export creds to the environment for those.)*
- **Self-explaining failures**: when no credentials are found, the error names every source it tried and
  why.
- **S3-compatible stores**: set `AWS_ENDPOINT_URL` (e.g. `http://localhost:9000`) for path-style MinIO/etc.
- **Optional disk block cache**: persist fetched blocks to local disk so re-reads skip the network
  entirely (see *Disk block cache* below).

## Build & use

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build            # runs the SigV4 known-answer test (no network)
./build/s3cat s3://bucket/key | head -c 100 | xxd
```

The end-to-end read path (range GETs, read-ahead refetches, seeking, EOF, path-style addressing) is
covered by an integration test against a live S3-compatible store. CI runs it against MinIO; to run it
yourself, build with `-DNANOS3READER_BUILD_INTEGRATION_TESTS=ON` and point it at an object you've
uploaded:

```bash
cmake -S . -B build -DNANOS3READER_BUILD_INTEGRATION_TESTS=ON && cmake --build build -j
AWS_ENDPOINT_URL=http://localhost:9000 \
NANOS3READER_IT_URI=s3://bucket/key NANOS3READER_IT_EXPECT=/path/to/local/copy \
  ctest --test-dir build -R minio_integration --output-on-failure
```

Without `NANOS3READER_IT_URI` / `NANOS3READER_IT_EXPECT` the test reports as *skipped*, so a plain
`ctest` never needs a network.

Consume it from your own CMake:

```cmake
find_package(nanos3reader REQUIRED)
target_link_libraries(your_app PRIVATE nanos3reader::nanos3reader)
```

### Configuration (environment)

| Variable | Purpose |
|---|---|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | Credentials via environment (highest precedence). |
| `AWS_PROFILE` / `AWS_DEFAULT_PROFILE` | Profile in `~/.aws/*` (`AWS_SHARED_CREDENTIALS_FILE` / `AWS_CONFIG_FILE` override paths). |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Region for virtual-hosted addressing (else the profile's `region`, else `us-east-1`). |
| `AWS_ENDPOINT_URL` | Custom endpoint (MinIO etc.); switches to path-style addressing. |
| `AWS_MAX_ATTEMPTS` | Tries per range GET (default 3; full-jitter backoff on transient failures). |

## Disk block cache

An optional, process-global **LRU cache on local disk**. When enabled, each fetched read-ahead-aligned
block is written to a flat file (`<uri-hash>_<offset>.blk`) under a cache directory; a later read of any
offset within a cached block is served from disk (sub-millisecond) instead of issuing a range `GET`. This
turns a repeated read of the same object — across `open()` calls or process runs — into local disk I/O.
It applies to `s3://` reads only and is **disabled by default**.

```cpp
#include "nanos3reader/s3_reader.h"

// Configure once before the first open(). max_blocks is the LRU capacity (clamped to 2..500);
// <= 0 disables the cache. Each block is one read-ahead window on disk.
nanos3reader::configure_disk_cache("/var/tmp/n3r-cache", /*max_blocks=*/100);

nanos3reader::S3MinStreamFactory factory;
auto stream = factory.open("s3://my-bucket/object", /*read_ahead=*/32 << 20);
// ... reads now populate (and on re-read, hit) the cache ...

std::uint64_t hits = 0, misses = 0;
nanos3reader::disk_cache_stats(&hits, &misses);
```

The LRU is mtime-based: a hit promotes its block, and a store evicts the oldest block once the directory
exceeds `max_blocks`. The cache directory is the caller's to manage (e.g. remove it on shutdown).

## SigV4 crypto backend

SigV4 needs only SHA-256. Pick the backend at configure time:

| `-DNANOS3READER_CRYPTO=` | SHA-256 from | Links |
|---|---|---|
| `openssl` (default) | OpenSSL `libcrypto` | `OpenSSL::Crypto` |
| `bundled` | compact in-tree SHA-256 | **no crypto library** |

Both produce byte-identical signatures (the test passes on both). `bundled` exists so the library links
no crypto of its own — the precondition for a small static build.

## Small static builds (mbedTLS)

In a normal build, `libcrypto` still arrives via **libcurl's TLS backend** (most distros build curl
against OpenSSL). For a small self-contained binary, build libcurl against **mbedTLS** and pair it with
`-DNANOS3READER_CRYPTO=bundled`. Measured (a static `s3cat`, glibc dynamic):

| Build | Stripped |
|---|---|
| mbedTLS curl + bundled SHA-256 | **~2.2 MB** |
| OpenSSL curl + OpenSSL SHA-256 | **~6.7 MB** |

curl's well-supported small TLS backends are **mbedTLS** and **wolfSSL** (not BearSSL). Note: a curl/TLS
stack you vendor statically is a stack whose CVEs you must track and re-release — prefer system libs by
default and use the static recipe only where you need the single-binary deployment.

## Scope & non-goals

Read-only, `GET`-only. No writes, no `LIST`, no SSO/assume-role credential resolution (export to env).
If you need a full S3 client, use the AWS SDK; nanos3reader is the small, focused reader.

## License

Apache-2.0 (`LICENSE`). Third-party attributions in `THIRD-PARTY-LICENSES.md`.
