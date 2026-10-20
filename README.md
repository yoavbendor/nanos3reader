# nanos3reader

A minimal, **read-only S3 range reader** for C++. It opens `s3://bucket/key` (and any S3-compatible
store — MinIO, R2, …) as a **seekable, read-ahead-buffered `std::istream`** backed by libcurl range
`GET`s and AWS SigV4 signing — using nothing but **libcurl + a small SHA-256**. No AWS SDK.

It does one thing well: fetch byte ranges out of S3 objects, with the full AWS credential chain. Beside the
stream, `S3Client` does `HEAD`, exact range reads, `ListObjectsV2` and a **single-request `PUT`** of a whole
object (up to 5 GiB, optionally conditional: create-only or compare-and-swap on the ETag), and streams files
and whole directory trees up with multipart uploads and parallel transfers (`put_file`, `put_directory`, and
the `s3put` command).

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
- **`S3Client`**: `head`, `read_range`, `list` and `put` (see *Object client* below), thread-safe, with
  retries on 5xx / 429 / transient transport errors.
- **Python bindings**: read/seek API and `Client` (`put`, `head`, `read_range`) with the same credential
  chain (see *Python* below).

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

## Object client

```cpp
#include "nanos3reader/s3_reader.h"

nanos3reader::S3Client client;  // or S3Client(ClientOptions{...}) for explicit keys / endpoint / region
std::string err, etag;
const std::string body = "hello";
if (!client.put("s3://my-bucket/greeting.txt", reinterpret_cast<const std::uint8_t*>(body.data()),
                body.size(), nanos3reader::PutOptions{}, &etag, err)) {
    /* err: "s3://my-bucket/greeting.txt: HTTP 403 AccessDenied", ... */
}

// Atomic create: fails with precondition_failed = true when the key already exists.
nanos3reader::PutOptions create;
create.if_none_match = true;
create.content_type = "application/json";
bool exists = false;
client.put("s3://my-bucket/v1.json", data, size, create, nullptr, err, &exists);

// Compare-and-swap: replace only the version whose ETag you read.
nanos3reader::PutOptions swap;
swap.if_match = etag;
```

Files and directories are streamed from disk, never read whole:

```cpp
nanos3reader::FileUploadOptions file;            // multipart from 64 MiB, 16 MiB parts, 4 parts at once
client.put_file("s3://my-bucket/run/out.bin", "/data/out.bin", file, &etag, err);

nanos3reader::DirectoryUploadOptions dir;        // 8 files at once, largest first
nanos3reader::DirectoryUploadStats stats;
client.put_directory("/data/results", "s3://my-bucket/run/stream/", dir,
                     [](const nanos3reader::FileUploadResult& r) { /* one call per file, serialized */ },
                     stats, err);                // false if any file failed; every file is attempted
```

`put_directory` maps each regular file to `<prefix>/<path relative to the directory>` ('/' separators),
following symlinks to files and not symlinked directories (as Python's `Path.rglob` walks). Bodies go as
`UNSIGNED-PAYLOAD` by default (no second read of each file; TLS protects the transfer); set
`sign_payload` to sign each file's SHA-256 instead. A failed multipart upload is aborted, so no parts are
left behind, and a file that changes size while it is sent fails rather than leaving a short object.

### `s3put`

The same as a command (built with the library; `NANOS3READER_BUILD_TOOLS`):

```bash
s3put results/ s3://my-bucket/session-run/IR_front_corner_right_83/   # a directory, recursively
s3put out.bin s3://my-bucket/run/                                      # -> s3://my-bucket/run/out.bin
s3put -j 16 --part-jobs 8 --multipart-threshold 128 --part-size 32 big/ s3://my-bucket/big/
```

It prints a line per file and a summary (files, bytes, seconds, Mbps). Exit status 0 when every file was
uploaded (a warning, still 0, when there was nothing to upload), 1 when any upload failed, 2 for a usage
error or a source that does not exist or cannot be listed. Credentials, region and endpoint come from the
environment chain above (`AWS_SESSION_TOKEN` included).

`put` sends the whole body in one signed request (its SHA-256 is part of the signature, so S3 rejects a
corrupted transfer). A conditional put that is retried after a lost response can report its own earlier
success as a failed precondition; callers that need exactly-once semantics should re-read the object then.

## Python

Python bindings wrap the same read/seek path and credential chain. Build from the repo root:

```bash
pip install -e ".[test]"
```

```python
from nanos3reader import Factory, open

# Simple read
with open("s3://my-bucket/object") as reader:
    data = reader.read()

# Factory for multiple opens
factory = Factory()
with factory.open("s3://my-bucket/object", read_ahead=4096) as reader:
    reader.seek(1024)
    chunk = reader.read(4096)
```

```python
from nanos3reader import Client, PreconditionFailed

client = Client()  # or Client(access_key_id=..., secret_access_key=..., region=..., endpoint=..., allow_http=...)
etag = client.put("s3://my-bucket/blob.bin", b"\x00" * 1024, content_type="application/octet-stream")
client.put("s3://my-bucket/v1.json", b'{"v": 1}', if_none_match=True)  # PreconditionFailed if it exists
client.put("s3://my-bucket/v1.json", b'{"v": 2}', if_match=etag_of_v1)  # PreconditionFailed if changed
size = client.head("s3://my-bucket/blob.bin")
first = client.read_range("s3://my-bucket/blob.bin", 0, 16)
```

Failures raise `nanos3reader.S3Error` (`PreconditionFailed` is a subclass). Requests release the GIL.

Example: `examples/s3cat.py` streams a byte range to stdout (the Python equivalent of `examples/s3cat.cpp`).
CI runs `tests/python/test_minio_integration.py` against an S3 server (moto) when `NANOS3READER_IT_URI` /
`NANOS3READER_IT_EXPECT` are set; the `put` tests also need `NANOS3READER_IT_PUT_PREFIX`, a prefix they may
write under.

| CMake option | Purpose |
|---|---|
| `NANOS3READER_BUILD_PYTHON_BINDINGS` | Build the `_nanos3reader` pybind11 module (off by default). |

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

## Prebuilt static binaries & CA certificates

CI builds a static package (`ci/build_static.sh`, in manylinux2014): `s3put`, `s3cat`, `libnanos3reader.a`
plus the static `libcurl.a`/`libssl.a`/`libcrypto.a`/`libz.a` it needs, and headers. Only glibc stays
shared (floor **GLIBC_2.17**); libstdc++/libgcc are linked in. It is tested in vanilla `ubuntu:18.04`,
`20.04`, `22.04` and `debian:12` images **with no `ca-certificates` installed** (`ci/test_static.sh`),
and the tarball is uploaded as the `static-linux-x86_64` workflow artifact.

A static OpenSSL only looks at compiled-in CA paths, so nanos3reader hands libcurl its CA certificates
explicitly, first match wins:

1. `AWS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `SSL_CERT_FILE` (PEM file), `SSL_CERT_DIR` (hashed directory)
2. the system bundle (`/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/tls/certs/ca-bundle.crt`, ...)
3. the bundle compiled in with `-DNANOS3READER_CA_BUNDLE=cacert.pem` (the static package embeds
   Mozilla's, from curl.se/ca)
4. libcurl's own default

`s3put --tls-info` (and `nanos3reader::tls_ca_source()`) says which one is in use; a certificate error
names the source and how to override it. Linking the library into another static binary:
`libnanos3reader.a libcurl.a libssl.a libcrypto.a libz.a -lpthread -ldl`.

## Scope & non-goals

Reads, listing, `PUT` and multipart uploads of files and directories. No `DELETE` (other than aborting a
failed multipart upload), no SSO/assume-role credential
resolution (export to env). If you need a full S3 client, use the AWS SDK; nanos3reader is the small,
focused one.

## License

Apache-2.0 (`LICENSE`). Third-party attributions in `THIRD-PARTY-LICENSES.md`.
