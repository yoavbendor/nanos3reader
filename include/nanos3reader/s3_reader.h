// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// nanos3reader — a minimal S3 client. It opens s3:// objects as seekable, read-ahead-buffered std::istreams
// over HTTP(S) range GETs with AWS SigV4 signing, using nothing but libcurl + a small SHA-256 (OpenSSL or
// bundled) — no AWS SDK. S3Client adds HEAD, range reads, listing, a single-request PUT (whole objects up to
// 5 GiB, optionally conditional) and streamed file / directory uploads with multipart and parallel transfers.
//
// The SigV4 signing primitives are declared here (not just in the .cpp) so they can be unit-tested against
// AWS's published signature test vectors with no network.

#ifndef NANOS3READER_S3_READER_H
#define NANOS3READER_S3_READER_H

// Version, exposed so consumers can feature-gate at compile time (e.g. the disk block cache below was
// added in 0.2.0). NANOS3READER_VERSION is a single comparable integer: MAJOR*10000 + MINOR*100 + PATCH.
#define NANOS3READER_VERSION_MAJOR 0
#define NANOS3READER_VERSION_MINOR 5
#define NANOS3READER_VERSION_PATCH 0
#define NANOS3READER_VERSION \
    (NANOS3READER_VERSION_MAJOR * 10000 + NANOS3READER_VERSION_MINOR * 100 + NANOS3READER_VERSION_PATCH)

#include <cstddef>
#include <cstdint>
#include <functional>
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
std::string sha256_hex(const unsigned char* data, std::size_t len);

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

// --- Object-store client (HEAD, range GET, ListObjectsV2, PUT) --------------------------------------

// Per-client settings. An empty string falls back to the environment chain used by S3MinStreamFactory
// (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN, shared profile files, ECS, IMDS;
// AWS_REGION; AWS_ENDPOINT_URL). access_key_id and secret_access_key must be given together.
struct ClientOptions {
    std::string access_key_id;
    std::string secret_access_key;
    std::string session_token;
    std::string region;
    std::string endpoint;        // e.g. "http://127.0.0.1:9000"; non-empty selects path-style addressing
    bool allow_http = false;     // an http:// endpoint (explicit or from AWS_ENDPOINT_URL) is refused unless set
};

// Options for S3Client::put. The conditional headers make a put an atomic create or compare-and-swap, as
// S3 implements them: if_none_match writes only when the key does not exist yet; if_match only when the
// object's current ETag equals it. A failed condition is reported through `precondition_failed`.
struct PutOptions {
    std::string content_type;    // empty: application/octet-stream
    bool if_none_match = false;  // send If-None-Match: * (create only)
    std::string if_match;        // non-empty: send If-Match: <etag> (replace only that version)
};

// Options for S3Client::put_file and put_directory.
struct FileUploadOptions {
    std::string content_type;  // empty: application/octet-stream
    // Sign each body's SHA-256 (reads every file twice: once to hash, once to send). Off by default: the
    // body goes as UNSIGNED-PAYLOAD, which S3 accepts, and TLS protects it in transit.
    bool sign_payload = false;
    // Files this large or larger go up as a multipart upload (required above 5 GiB): parts are retried
    // one by one and sent several at a time. Smaller files are one PUT.
    std::uint64_t multipart_threshold = std::uint64_t{64} << 20U;
    std::uint64_t part_size = std::uint64_t{16} << 20U;  // at least 5 MiB; raised to stay within 10,000 parts
    unsigned part_concurrency = 4;                       // parts of one file in flight
};

// What put_directory reports for each file, as it finishes.
struct FileUploadResult {
    std::string path;      // the local file
    std::string uri;       // where it went
    std::uint64_t bytes = 0;
    bool ok = false;
    std::string error;     // when !ok
    double seconds = 0.0;
};

struct DirectoryUploadOptions {
    FileUploadOptions file;
    unsigned concurrency = 8;  // files in flight
};

struct DirectoryUploadStats {
    std::uint64_t files = 0;   // uploaded
    std::uint64_t failed = 0;
    std::uint64_t bytes = 0;   // uploaded
    double seconds = 0.0;      // wall time of the whole upload
};

struct ObjectInfo {
    std::string key;             // full key inside the bucket (the listed prefix is included)
    std::uint64_t size = 0;
};

// Thread-safe client for s3:// objects. One instance may be shared by any number of threads; each thread
// reuses its own libcurl easy handle, so connections are kept alive across calls. Requests are signed with
// SigV4. 5xx responses, 429 and 503 SlowDown are retried up to 3 times with jittered backoff, as are transport
// errors libcurl marks retriable (timeouts, refused or reset connections); 4xx responses are never retried. Every failure is reported in `error` as "s3://bucket/key: ..." with the
// HTTP status (or the transport error) included.
class S3Client {
public:
    explicit S3Client(ClientOptions options = {});
    ~S3Client();
    S3Client(const S3Client&) = delete;
    S3Client& operator=(const S3Client&) = delete;
    S3Client(S3Client&&) noexcept;
    S3Client& operator=(S3Client&&) noexcept;

    // Object size via HEAD. Returns false with `error` set on failure (404 included).
    bool head(const std::string& uri, std::uint64_t& size, std::string& error);

    // Exactly `n` bytes at `offset` (one range GET). A body shorter than `n` (the object ends first) is an
    // error. n == 0 succeeds without a request.
    bool read_range(const std::string& uri, std::uint64_t offset, std::uint64_t n, std::uint8_t* dst,
                    std::string& error);

    // ListObjectsV2 under prefix_uri ("s3://bucket/prefix/"; an empty prefix lists the whole bucket), following
    // every continuation page. With a non-empty delimiter (normally "/") only the immediate children are
    // returned: objects in `objects`, sub-"directories" in `common_prefixes` (full prefixes, e.g. "p/sub/").
    // Without a delimiter every object under the prefix is returned and `common_prefixes` is left empty.
    bool list(const std::string& prefix_uri, const std::string& delimiter, std::vector<ObjectInfo>& objects,
              std::vector<std::string>& common_prefixes, std::string& error);

    // Write a whole object from memory in one signed PUT (S3 allows up to 5 GiB this way; larger objects
    // need a multipart upload, which this client does not do). The body's SHA-256 is signed, so S3 rejects a
    // corrupted transfer. On success `etag` (when non-null) receives the new object's ETag, quotes included.
    // Retries as every request does; note that a conditional put retried after a lost response can report
    // its own earlier success as a failed precondition. On a failed condition (HTTP 412) the call returns
    // false with `*precondition_failed` set (when non-null) and `error` naming it.
    bool put(const std::string& uri, const std::uint8_t* data, std::size_t size, const PutOptions& options,
             std::string* etag, std::string& error, bool* precondition_failed = nullptr);

    // Upload a local file to `uri`, streamed from disk (never held whole in memory): one PUT below
    // options.multipart_threshold, else a multipart upload (aborted on failure, so no parts are left
    // behind). `etag` receives the object's ETag when non-null. The file must not change while it is sent;
    // a file that shrinks mid-upload fails rather than leaving a short object.
    bool put_file(const std::string& uri, const std::string& path, const FileUploadOptions& options,
                  std::string* etag, std::string& error);

    // Upload every regular file under `dir` (recursively; symlinks to files are followed, symlinked
    // directories are not, as Python's Path.rglob does) to `prefix_uri` + its path relative to `dir`, with
    // '/' separators ("s3://bucket/run/" + "sub/a.bin"; a '/' is added after a non-empty prefix that lacks
    // one). Files go up options.concurrency at a time, largest first. Every file is attempted; `on_file`
    // (when set) is called once per file as it finishes, from the worker threads but never concurrently.
    // Returns false when `dir` cannot be listed or any file failed (`error` names the first failure and
    // the count); `stats` is filled either way.
    bool put_directory(const std::string& dir, const std::string& prefix_uri, const DirectoryUploadOptions& options,
                       const std::function<void(const FileUploadResult&)>& on_file, DirectoryUploadStats& stats,
                       std::string& error);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

// --- TLS ------------------------------------------------------------------------------------------

// Where HTTPS requests take their CA certificates from, as a sentence for diagnostics (decided once per
// process): AWS_CA_BUNDLE, CURL_CA_BUNDLE or SSL_CERT_FILE (a PEM file) and SSL_CERT_DIR (a directory),
// when set; else, on Linux, the first system bundle found at the usual distribution paths; else the bundle
// compiled in with the CMake option NANOS3READER_CA_BUNDLE; else libcurl's own default. Every request gets
// these explicitly, so a statically linked libcurl/OpenSSL does not depend on the paths compiled into it.
std::string tls_ca_source();

// --- Disk-resident LRU block cache -----------------------------------------------------------------

// Optional process-global cache that persists fetched, read-ahead-aligned blocks as flat files on local
// disk, so a re-read of any offset within a previously fetched block is served from disk (sub-millisecond)
// instead of issuing a fresh range GET. It applies only to s3:// reads; file:// streams don't go through
// this code. Disabled by default.
//
// Configure once before the first open(). cache_dir is created if absent. max_blocks is the LRU capacity,
// clamped to 2..500; max_blocks <= 0 disables the cache. Returns true on success (false only if cache_dir
// can't be created). Thread-safe.
bool configure_disk_cache(const std::string& cache_dir, int max_blocks);

// Cumulative block-level hit/miss counters since process start (pass nullptr to skip either).
void disk_cache_stats(std::uint64_t* out_hits, std::uint64_t* out_misses);

}  // namespace nanos3reader

#endif  // NANOS3READER_S3_READER_H
