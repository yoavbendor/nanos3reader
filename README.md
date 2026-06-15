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
  connection reused per object**. During sequential streaming it also **prefetches the next window on a
  second connection** so transfer overlaps consumption (set `NANOS3READER_PREFETCH=0` to keep a single
  connection).
- **AWS SigV4** signing (validated against AWS's published test vectors — see `tests/sigv4_test.cpp`).
- **Full credential chain**, the way the AWS tools resolve it:
  environment → shared profile files (`~/.aws/credentials` + `~/.aws/config`, honoring `AWS_PROFILE`,
  **including a profile's `credential_process`** helper) → ECS/EKS container credentials → EC2 instance
  role (IMDSv2). Temporary credentials are refreshed before they expire. *(AWS SSO and assume-role
  profiles are not resolved — export creds to the environment for those.)*
- **Self-explaining failures**: when no credentials are found, the error names every source it tried and
  why.
- **S3-compatible stores**: set `AWS_ENDPOINT_URL` (e.g. `http://localhost:9000`) for path-style MinIO/etc.

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

## C / FFI API

For use from C — or any language that can call C (Python, Rust, Go, …) — there is a thin C wrapper in
`include/nanos3reader/nanos3reader.h` that mirrors the C++ factory+stream model. It's built into the same
library (toggle with `-DNANOS3READER_BUILD_C_API=ON|OFF`, default on):

```c
#include "nanos3reader/nanos3reader.h"

nanos3reader_factory* f = nanos3reader_factory_create();   /* resolves creds/region/endpoint once; reuse it */
nanos3reader_stream*  s = nanos3reader_open(f, "s3://bucket/key", 1 << 16);
if (!s) { /* nanos3reader_last_error() explains why */ }

char buf[65536];
int64_t n = nanos3reader_pread(s, buf, sizeof buf, 1024);  /* random access: seek+read; n<0 on error */

nanos3reader_close(s);
nanos3reader_factory_destroy(f);
```

`read`/`pread` return bytes read, `0` at end-of-object, `-1` on error; `nanos3reader_last_error()` returns
the reason (thread-local). A stream owns one keep-alive connection and is **not** safe to share across
threads — give each thread its own stream; the factory may be shared once its credentials are resolved.

`examples/s3cat_c.c` is the C counterpart of `s3cat` and a throughput probe — it streams an object to stdout
one chunk at a time and prints MiB/s, which is a quick way to confirm the C layer adds no overhead:

```bash
AWS_ENDPOINT_URL=http://localhost:9000 ./build/s3cat_c s3://bucket/key 1048576 > /dev/null
# stderr: read 1048576 bytes in 1048576-byte chunks in 0.0xx s (xxx.x MiB/s)
```

Binding from other languages is a direct FFI to those six functions — e.g. Python:

```python
import ctypes
lib = ctypes.CDLL("libnanos3reader.so")
lib.nanos3reader_open.restype  = ctypes.c_void_p
lib.nanos3reader_open.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
lib.nanos3reader_pread.restype  = ctypes.c_int64
lib.nanos3reader_pread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint64]
# nanos3reader_factory_create / _read / _seek / _tell / _close / _factory_destroy / _last_error similarly
```

### Configuration (environment)

| Variable | Purpose |
|---|---|
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` | Credentials via environment (highest precedence). |
| `AWS_PROFILE` / `AWS_DEFAULT_PROFILE` | Profile in `~/.aws/*` (`AWS_SHARED_CREDENTIALS_FILE` / `AWS_CONFIG_FILE` override paths). |
| `AWS_REGION` / `AWS_DEFAULT_REGION` | Region for virtual-hosted addressing (else the profile's `region`, else `us-east-1`). |
| `AWS_ENDPOINT_URL` | Custom endpoint (MinIO etc.); switches to path-style addressing. |
| `AWS_MAX_ATTEMPTS` | Tries per range GET (default 3; full-jitter backoff on transient failures). |
| `NANOS3READER_TRACE_CONN` | Set to `1` to log every connection open/reuse/close and a per-GET `new_connections` count to stderr — use it to confirm the keep-alive connection is reused across range GETs. |
| `NANOS3READER_PREFETCH` | Set to `0` to disable the background read-ahead prefetch (keeps one connection per object). On by default; engaged only during sequential streaming, so random access never issues a speculative GET. |

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
