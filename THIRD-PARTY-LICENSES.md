# Third-party licenses

nanos3reader itself is licensed under Apache-2.0 (see `LICENSE`). It links the following third-party
components at build time; all are permissive and compatible with Apache-2.0. When you redistribute a
binary that statically links these, include their license texts.

| Component | Used for | License | Notes |
|---|---|---|---|
| [libcurl](https://curl.se/) | HTTP/HTTPS range GETs | curl license (MIT/X-style) | Required. |
| [OpenSSL](https://www.openssl.org/) ≥ 3.0 | SHA-256 for SigV4 (default backend); also libcurl's TLS on most distros | Apache-2.0 | Optional for our code: build with `-DNANOS3READER_CRYPTO=bundled` to drop our direct dependency. Avoid OpenSSL ≤ 1.1.1 (old OpenSSL/SSLeay BSD-with-advertising license). |
| [mbedTLS](https://www.trustedfirmware.org/projects/mbed-tls/) | optional small TLS backend for a statically linked libcurl | Apache-2.0 | Only if you build libcurl against mbedTLS for a small static binary (see README). |

The bundled SHA-256 (`-DNANOS3READER_CRYPTO=bundled`) is original code under this project's Apache-2.0
license and adds no third-party obligation.
