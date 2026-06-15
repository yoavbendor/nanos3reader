// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// nanos3reader — a minimal, read-only S3 range reader. It opens s3:// objects as seekable,
// read-ahead-buffered std::istreams over HTTP(S) range GETs with AWS SigV4 signing, using nothing but
// libcurl + a small SHA-256 (OpenSSL or bundled) — no AWS SDK. Read/GET only, by design.
//
// The SigV4 signing primitives are declared here (not just in the .cpp) so they can be unit-tested against
// AWS's published signature test vectors with no network.

#ifndef NANOS3READER_S3_READER_H
#define NANOS3READER_S3_READER_H

#include <cstddef>
#include <istream>
#include <memory>
#include <string>
#include <vector>

namespace nanos3reader {

namespace s3detail {
struct Config;  // resolved-once S3 configuration (credentials, region, endpoint); defined in the .cpp
}

// --- AWS Signature Version 4 primitives ------------------------------------------------------------
namespace s3v4 {

// Lowercase hex of an arbitrary byte buffer.
std::string hex_encode(const unsigned char* data, std::size_t len);

// Hex SHA-256 of a payload.
std::string sha256_hex(const std::string& payload);

// HMAC-SHA256(key, msg) as raw bytes.
std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& key, const std::string& msg);

// AWS4 signing key: the HMAC chain over ("AWS4"+secret) -> date -> region -> service -> "aws4_request".
// `date` is the YYYYMMDD scope date.
std::vector<unsigned char> derive_signing_key(const std::string& secret, const std::string& date,
                                              const std::string& region, const std::string& service);

// One header for the canonical request. `name` must be lowercase; `value` is trimmed by the signer.
struct Header {
    std::string name;
    std::string value;
};

// A request to sign. `headers` need not be pre-sorted (the signer sorts by name). `payload_hash` is the
// hex SHA-256 of the body, or the literal "UNSIGNED-PAYLOAD".
struct CanonicalRequest {
    std::string method;  // e.g. "GET"
    std::string uri;     // percent-encoded path, e.g. "/my%20key"
    std::string query;   // canonical query string, "" when none
    std::vector<Header> headers;
    std::string payload_hash;
};

// Build the full `Authorization: AWS4-HMAC-SHA256 ...` header value for `req`. `amz_date` is the ISO8601
// basic timestamp (YYYYMMDDTHHMMSSZ); its leading date forms the credential scope. When `out_signed_headers`
// is non-null it receives the semicolon-joined signed-header list.
std::string build_authorization(const CanonicalRequest& req, const std::string& access_key,
                                const std::string& secret_key, const std::string& region,
                                const std::string& service, const std::string& amz_date,
                                std::string* out_signed_headers = nullptr);

}  // namespace s3v4

// Thread-local description of the most recent failed open()/read()/seek() on the calling thread, or "" if
// none. This is the same message S3MinStreamFactory::error() returns; exposed as a free function so the C
// API (and stream-level read/seek failures, which have no factory in hand) can surface it too.
std::string last_error();

// --- Stream factory --------------------------------------------------------------------------------

// Opens s3:// objects as seekable, read-ahead-buffered std::istreams backed by libcurl range GETs + SigV4.
// Credentials are resolved via the standard chain: environment (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY /
// AWS_SESSION_TOKEN) -> shared profile files (~/.aws/credentials + ~/.aws/config, honoring AWS_PROFILE) ->
// ECS/EKS container credentials -> EC2 instance role (IMDSv2); temporary creds are refreshed near expiry.
// Region comes from AWS_REGION / AWS_DEFAULT_REGION, else the profile, else "us-east-1". AWS_ENDPOINT_URL,
// when set, selects path-style addressing for S3-compatible stores (MinIO, etc.).
class S3MinStreamFactory {
public:
    S3MinStreamFactory();

    // Open `uri` ("s3://bucket/key") as a seekable stream whose buffer fetches `read_ahead_bytes` per range
    // GET. Returns nullptr on a configuration error (bad URI, missing credentials) — see error().
    std::unique_ptr<std::istream> open(const std::string& uri, std::size_t read_ahead_bytes);

    // Human-readable description of the most recent open() failure on the calling thread.
    std::string error() const;

private:
    std::shared_ptr<const s3detail::Config> config_;
};

}  // namespace nanos3reader

#endif  // NANOS3READER_S3_READER_H
