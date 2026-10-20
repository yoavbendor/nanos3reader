// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#include "nanos3reader/s3_reader.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <streambuf>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <curl/curl.h>
// SigV4 needs only SHA-256 (HMAC is built generically on it below). Two backends, chosen at build time:
//   - default: OpenSSL libcrypto (just SHA256()).
//   - NANOS3READER_CRYPTO_BUNDLED: a small in-tree SHA-256, so the reader links no crypto library of its
//     own — handy for small static builds where libcurl already supplies TLS (mbedTLS/BearSSL/etc).
#if !defined(NANOS3READER_CRYPTO_BUNDLED)
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

namespace nanos3reader {

// The CA bundle compiled in with NANOS3READER_CA_BUNDLE (src/ca_bundle_none.cpp when there is none: size 0).
const char* embedded_ca_bundle();
std::size_t embedded_ca_bundle_size();

namespace s3v4 {

namespace {

const char* const kHexDigits = "0123456789abcdef";

std::string trim(const std::string& s) {
    const auto b = s.find_first_not_of(" \t");
    if (b == std::string::npos) {
        return "";
    }
    const auto e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

// --- SHA-256 + HMAC-SHA256 -------------------------------------------------------------------------
// One SHA-256 primitive (two backends); HMAC is the standard ipad/opad construction over it, so it needs
// no crypto library. The whole chain is verified end-to-end by the SigV4 known-answer tests (AWS vectors).

#if defined(NANOS3READER_CRYPTO_BUNDLED)
// Compact SHA-256 (FIPS 180-4), used only when no system crypto is linked.
struct Sha256 {
    std::uint32_t s[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
                          0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
    std::uint64_t total = 0;
    unsigned char buf[64] = {0};
    std::size_t n = 0;

    static std::uint32_t ror(std::uint32_t x, int c) { return (x >> c) | (x << (32 - c)); }

    void block(const unsigned char* p) {
        static const std::uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (std::uint32_t(p[4 * i]) << 24) | (std::uint32_t(p[4 * i + 1]) << 16) |
                   (std::uint32_t(p[4 * i + 2]) << 8) | std::uint32_t(p[4 * i + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = ror(w[i - 15], 7) ^ ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = ror(w[i - 2], 17) ^ ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4], f = s[5], g = s[6], h = s[7];
        for (int i = 0; i < 64; ++i) {
            const std::uint32_t S1 = ror(e, 6) ^ ror(e, 11) ^ ror(e, 25);
            const std::uint32_t ch = (e & f) ^ (~e & g);
            const std::uint32_t t1 = h + S1 + ch + K[i] + w[i];
            const std::uint32_t S0 = ror(a, 2) ^ ror(a, 13) ^ ror(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        s[0] += a; s[1] += b; s[2] += c; s[3] += d; s[4] += e; s[5] += f; s[6] += g; s[7] += h;
    }
    void update(const unsigned char* p, std::size_t len) {
        total += len;
        while (len > 0) {
            std::size_t take = 64 - n;
            if (take > len) take = len;
            std::memcpy(buf + n, p, take);
            n += take; p += take; len -= take;
            if (n == 64) { block(buf); n = 0; }
        }
    }
    void finish(unsigned char out[32]) {
        const std::uint64_t bits = total * 8;
        const unsigned char one = 0x80;
        update(&one, 1);
        const unsigned char zero = 0;
        while (n != 56) update(&zero, 1);
        unsigned char len[8];
        for (int i = 0; i < 8; ++i) len[i] = static_cast<unsigned char>(bits >> (56 - 8 * i));
        update(len, 8);
        for (int i = 0; i < 8; ++i) {
            out[4 * i] = static_cast<unsigned char>(s[i] >> 24);
            out[4 * i + 1] = static_cast<unsigned char>(s[i] >> 16);
            out[4 * i + 2] = static_cast<unsigned char>(s[i] >> 8);
            out[4 * i + 3] = static_cast<unsigned char>(s[i]);
        }
    }
};
void sha256_raw(const unsigned char* data, std::size_t len, unsigned char out[32]) {
    Sha256 h;
    h.update(data, len);
    h.finish(out);
}
#else
void sha256_raw(const unsigned char* data, std::size_t len, unsigned char out[32]) {
    SHA256(data, len, out);
}
#endif

// HMAC-SHA256 (RFC 2104) over sha256_raw — backend-independent, so it pulls in no crypto library either.
void hmac_sha256_raw(const unsigned char* key, std::size_t keylen, const unsigned char* msg,
                     std::size_t msglen, unsigned char out[32]) {
    unsigned char k[64] = {0};
    if (keylen > 64) {
        sha256_raw(key, keylen, k);  // keys longer than the block are hashed down first
    } else {
        std::memcpy(k, key, keylen);
    }
    unsigned char ipad[64];
    unsigned char opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }
    std::vector<unsigned char> inner;
    inner.reserve(64 + msglen);
    inner.insert(inner.end(), ipad, ipad + 64);
    inner.insert(inner.end(), msg, msg + msglen);
    unsigned char ih[32];
    sha256_raw(inner.data(), inner.size(), ih);
    unsigned char outer[96];
    std::memcpy(outer, opad, 64);
    std::memcpy(outer + 64, ih, 32);
    sha256_raw(outer, sizeof outer, out);
}

}  // namespace

std::string hex_encode(const unsigned char* data, std::size_t len) {
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = kHexDigits[data[i] >> 4];
        out[2 * i + 1] = kHexDigits[data[i] & 0x0F];
    }
    return out;
}

std::string sha256_hex(const std::string& payload) {
    return sha256_hex(reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
}

std::string sha256_hex(const unsigned char* data, std::size_t len) {
    unsigned char digest[32];
    static const unsigned char kEmpty = 0;
    sha256_raw(len == 0 ? &kEmpty : data, len, digest);
    return hex_encode(digest, sizeof digest);
}

// Hex SHA-256 of `len` bytes of `f` from `offset`, read in 1 MiB chunks (for a signed file upload).
// False when the file is shorter or cannot be read.
bool sha256_file_hex(std::FILE* f, std::uint64_t offset, std::uint64_t len, std::string& out) {
#if defined(_WIN32)
    if (_fseeki64(f, static_cast<__int64>(offset), SEEK_SET) != 0) return false;
#else
    if (fseeko(f, static_cast<off_t>(offset), SEEK_SET) != 0) return false;
#endif
    std::vector<unsigned char> buf(std::size_t{1} << 20U);
    unsigned char digest[32];
#if defined(NANOS3READER_CRYPTO_BUNDLED)
    Sha256 h;
#else
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx == nullptr || EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }
#endif
    bool ok = true;
    for (std::uint64_t left = len; left > 0;) {
        const auto n = static_cast<std::size_t>(std::min<std::uint64_t>(left, buf.size()));
        if (std::fread(buf.data(), 1, n, f) != n) {
            ok = false;
            break;
        }
#if defined(NANOS3READER_CRYPTO_BUNDLED)
        h.update(buf.data(), n);
#else
        if (EVP_DigestUpdate(ctx, buf.data(), n) != 1) {
            ok = false;
            break;
        }
#endif
        left -= n;
    }
#if defined(NANOS3READER_CRYPTO_BUNDLED)
    h.finish(digest);
#else
    unsigned int dlen = 0;
    ok = EVP_DigestFinal_ex(ctx, digest, &dlen) == 1 && ok;
    EVP_MD_CTX_free(ctx);
#endif
    if (ok) {
        out = hex_encode(digest, sizeof digest);
    }
    return ok;
}

std::vector<unsigned char> hmac_sha256(const std::vector<unsigned char>& key, const std::string& msg) {
    unsigned char out[32];
    hmac_sha256_raw(key.data(), key.size(), reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                    out);
    return std::vector<unsigned char>(out, out + 32);
}

std::vector<unsigned char> derive_signing_key(const std::string& secret, const std::string& date,
                                              const std::string& region, const std::string& service) {
    const std::string k0 = "AWS4" + secret;
    const std::vector<unsigned char> k_secret(k0.begin(), k0.end());
    const auto k_date = hmac_sha256(k_secret, date);
    const auto k_region = hmac_sha256(k_date, region);
    const auto k_service = hmac_sha256(k_region, service);
    return hmac_sha256(k_service, "aws4_request");
}

std::string build_authorization(const CanonicalRequest& req, const std::string& access_key,
                                const std::string& secret_key, const std::string& region,
                                const std::string& service, const std::string& amz_date,
                                std::string* out_signed_headers) {
    // Headers sorted by (lowercase) name for the canonical request and the signed-headers list.
    std::vector<Header> headers = req.headers;
    std::sort(headers.begin(), headers.end(),
              [](const Header& a, const Header& b) { return a.name < b.name; });

    std::string canonical_headers;
    std::string signed_headers;
    for (std::size_t i = 0; i < headers.size(); ++i) {
        canonical_headers += headers[i].name + ":" + trim(headers[i].value) + "\n";
        signed_headers += headers[i].name;
        if (i + 1 < headers.size()) {
            signed_headers += ";";
        }
    }

    const std::string canonical_request = req.method + "\n" + req.uri + "\n" + req.query + "\n" +
                                          canonical_headers + "\n" + signed_headers + "\n" + req.payload_hash;

    const std::string scope_date = amz_date.substr(0, 8);
    const std::string credential_scope = scope_date + "/" + region + "/" + service + "/aws4_request";
    const std::string string_to_sign = std::string("AWS4-HMAC-SHA256\n") + amz_date + "\n" + credential_scope +
                                        "\n" + sha256_hex(canonical_request);

    const auto signing_key = derive_signing_key(secret_key, scope_date, region, service);
    const auto sig_bytes = hmac_sha256(signing_key, string_to_sign);
    const std::string signature = hex_encode(sig_bytes.data(), sig_bytes.size());

    if (out_signed_headers != nullptr) {
        *out_signed_headers = signed_headers;
    }
    return "AWS4-HMAC-SHA256 Credential=" + access_key + "/" + credential_scope +
           ", SignedHeaders=" + signed_headers + ", Signature=" + signature;
}

}  // namespace s3v4

// --- factory + stream ------------------------------------------------------------------------------

namespace {

// Per-thread last-error, surfaced by S3MinStreamFactory::error(). Thread-local because the external-blob
// handle cache (the sole caller) is itself thread-local and lock-free. Cleared when a window loads cleanly
// or a logical seek begins, set when a GET ultimately fails — so the caller can read it after a failed
// seek/read to get the real S3 reason instead of a generic I/O error.
thread_local std::string g_last_error;

// Network tuning for the range GETs.
constexpr long kConnectTimeoutSec = 10;   // fail fast if the endpoint is unreachable
constexpr long kLowSpeedBytes = 1;        // treat <1 B/s ...
constexpr long kLowSpeedTimeSec = 60;     // ... for 60s as a stall and abort (instead of hanging forever)
constexpr long kBackoffBaseMs = 100;      // exponential backoff base
constexpr long kBackoffCapMs = 2000;      // and ceiling, with full jitter

// Metadata (IMDS/ECS) calls must fail fast on non-cloud hosts, not hang.
constexpr long kMetaConnectMs = 1000;
constexpr long kMetaTotalMs = 2000;

std::string env_or(const char* name, const std::string& fallback) {
    const char* v = std::getenv(name);
    return (v != nullptr && v[0] != '\0') ? std::string(v) : fallback;
}

// --- TLS trust anchors -------------------------------------------------------------------------------
// Where the CA certificates come from, decided once per process and handed to libcurl explicitly, so a
// statically linked libcurl/OpenSSL does not depend on the CA paths compiled into it (which a vanilla image
// may not have). In order: AWS_CA_BUNDLE, CURL_CA_BUNDLE, SSL_CERT_FILE (a PEM file) and SSL_CERT_DIR (a
// hashed directory); else, on Linux, the first non-empty system bundle at the usual distribution paths;
// else the bundle compiled in with NANOS3READER_CA_BUNDLE (when there is one); else libcurl's own default.
struct CaConfig {
    std::string file;
    std::string dir;
    bool embedded = false;
    std::string source;  // for diagnostics
};

bool non_empty_file(const std::string& path) {
    std::error_code ec;
    return std::filesystem::is_regular_file(path, ec) && std::filesystem::file_size(path, ec) > 0 && !ec;
}

const CaConfig& ca_config() {
    static const CaConfig config = [] {
        CaConfig c;
        for (const char* var : {"AWS_CA_BUNDLE", "CURL_CA_BUNDLE", "SSL_CERT_FILE"}) {
            const std::string v = env_or(var, "");
            if (!v.empty()) {
                c.file = v;
                c.source = std::string(var) + "=" + v;
                break;
            }
        }
        const std::string dir = env_or("SSL_CERT_DIR", "");
        if (!dir.empty()) {
            c.dir = dir;
            c.source += (c.source.empty() ? "" : ", ") + std::string("SSL_CERT_DIR=") + dir;
        }
        if (!c.source.empty()) {
            return c;
        }
#if defined(__linux__)
        for (const char* path : {"/etc/ssl/certs/ca-certificates.crt",                // Debian, Ubuntu, Arch, Gentoo
                                 "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",  // RHEL / Fedora 7+
                                 "/etc/pki/tls/certs/ca-bundle.crt",                   // RHEL / Fedora 6
                                 "/etc/ssl/ca-bundle.pem",                             // openSUSE
                                 "/etc/ssl/cert.pem",                                  // Alpine
                                 "/etc/pki/tls/cacert.pem"}) {                         // OpenELEC
            if (non_empty_file(path)) {
                c.file = path;
                c.source = std::string("system bundle ") + path;
                return c;
            }
        }
#endif
        if (embedded_ca_bundle_size() != 0) {
            c.embedded = true;
            c.source = "the bundle compiled in (NANOS3READER_CA_BUNDLE)";
            return c;
        }
        c.source = "libcurl's built-in default (none of the variables or system bundles was found)";
        return c;
    }();
    return config;
}

// The compiled-in bundle as a file, for a libcurl without CURLOPT_CAINFO_BLOB (before 7.77, or a TLS backend
// without it): written once per process to a private temporary file. Empty when it cannot be written.
const std::string& embedded_ca_file() {
    static const std::string path = []() -> std::string {
        std::error_code ec;
        const auto dir = std::filesystem::temp_directory_path(ec);
        if (ec) {
            return "";
        }
        const auto file = dir / ("nanos3reader-ca-" + std::to_string(embedded_ca_bundle_size()) + "-" +
                                 std::to_string(static_cast<unsigned long long>(
                                     std::chrono::steady_clock::now().time_since_epoch().count())) + ".pem");
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out.write(embedded_ca_bundle(), static_cast<std::streamsize>(embedded_ca_bundle_size()));
        out.close();
        return out ? file.string() : std::string();
    }();
    return path;
}

// Point `h` at the CA certificates (after every curl_easy_reset, which clears them).
void apply_tls_options(CURL* h) {
    const CaConfig& c = ca_config();
    if (!c.file.empty()) {
        curl_easy_setopt(h, CURLOPT_CAINFO, c.file.c_str());
    }
    if (!c.dir.empty()) {
        curl_easy_setopt(h, CURLOPT_CAPATH, c.dir.c_str());
    }
    if (c.embedded) {
        bool set = false;
#if LIBCURL_VERSION_NUM >= 0x074D00  // CURLOPT_CAINFO_BLOB: curl 7.77.0
        curl_blob blob;
        blob.data = const_cast<char*>(embedded_ca_bundle());
        blob.len = embedded_ca_bundle_size();
        blob.flags = CURL_BLOB_NOCOPY;  // static storage: no copy per request
        set = curl_easy_setopt(h, CURLOPT_CAINFO_BLOB, &blob) == CURLE_OK;
#endif
        if (!set && !embedded_ca_file().empty()) {
            curl_easy_setopt(h, CURLOPT_CAINFO, embedded_ca_file().c_str());
        }
    }
}

// libcurl's message for `rc`, with where the CA certificates came from when TLS verification failed.
std::string curl_error_text(CURLcode rc) {
    std::string msg = curl_easy_strerror(rc);
    if (rc == CURLE_PEER_FAILED_VERIFICATION || rc == CURLE_SSL_CACERT_BADFILE) {
        msg += " (CA certificates: " + ca_config().source +
               "; set SSL_CERT_FILE or AWS_CA_BUNDLE to a PEM bundle, or install ca-certificates)";
    }
    return msg;
}

std::string trim_ws(const std::string& s) {
    const auto b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) {
        return "";
    }
    const auto e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

void ensure_curl_global_init() {
    static std::once_flag once;
    std::call_once(once, [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
}

// RFC 3986 percent-encoding of a path, preserving '/' between segments (S3 does not double-encode).
std::string uri_encode_path(const std::string& path) {
    std::string out;
    out.reserve(path.size());
    for (unsigned char c : path) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                                c == '-' || c == '_' || c == '.' || c == '~' || c == '/';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back("0123456789ABCDEF"[c >> 4]);
            out.push_back("0123456789ABCDEF"[c & 0x0F]);
        }
    }
    return out;
}

std::string amz_now() {
    std::time_t t = std::time(nullptr);
    std::tm tm_utc{};
#if defined(_WIN32)
    gmtime_s(&tm_utc, &t);
#else
    gmtime_r(&t, &tm_utc);
#endif
    char buf[20];
    std::strftime(buf, sizeof buf, "%Y%m%dT%H%M%SZ", &tm_utc);
    return std::string(buf);
}

std::size_t write_to_vector(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    const std::size_t n = size * nmemb;
    auto* out = static_cast<std::vector<char>*>(userdata);
    out->insert(out->end(), ptr, ptr + n);
    return n;
}

std::size_t write_to_string(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    const std::size_t n = size * nmemb;
    static_cast<std::string*>(userdata)->append(ptr, n);
    return n;
}

// --- credential resolution (env -> shared profile files -> ECS -> EC2 IMDSv2) ----------------------

struct Credentials {
    std::string access_key;
    std::string secret_key;
    std::string session_token;
    // When set, the creds are temporary and must be refreshed near this instant; nullopt means static.
    std::optional<std::chrono::system_clock::time_point> expiry;
    bool valid() const { return !access_key.empty() && !secret_key.empty(); }
};

std::string aws_profile() {
    return env_or("AWS_PROFILE", env_or("AWS_DEFAULT_PROFILE", "default"));
}

// Read the [section] key/value pairs from an AWS INI file (credentials or config). Comments (# / ;) and
// blank lines are ignored.
std::map<std::string, std::string> parse_ini_section(const std::string& path, const std::string& section) {
    std::map<std::string, std::string> kv;
    std::ifstream f(path);
    if (!f) {
        return kv;
    }
    std::string line;
    std::string current;
    while (std::getline(f, line)) {
        const std::string s = trim_ws(line);
        if (s.empty() || s[0] == '#' || s[0] == ';') {
            continue;
        }
        if (s.front() == '[' && s.back() == ']') {
            current = trim_ws(s.substr(1, s.size() - 2));
            continue;
        }
        if (current != section) {
            continue;
        }
        const auto eq = s.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        kv[trim_ws(s.substr(0, eq))] = trim_ws(s.substr(eq + 1));
    }
    return kv;
}

// Static creds (+ region) for `profile` from ~/.aws/credentials and ~/.aws/config. The credentials file
// uses [profile]; the config file uses [profile <name>] (or [default]). Credentials file wins.
void load_profile(const std::string& profile, Credentials& cred, std::string& region_out) {
    const std::string home = env_or("HOME", "");
    const std::string cred_path =
        env_or("AWS_SHARED_CREDENTIALS_FILE", home.empty() ? "" : home + "/.aws/credentials");
    const std::string conf_path = env_or("AWS_CONFIG_FILE", home.empty() ? "" : home + "/.aws/config");

    if (!cred_path.empty()) {
        const auto kv = parse_ini_section(cred_path, profile);
        if (auto it = kv.find("aws_access_key_id"); it != kv.end()) cred.access_key = it->second;
        if (auto it = kv.find("aws_secret_access_key"); it != kv.end()) cred.secret_key = it->second;
        if (auto it = kv.find("aws_session_token"); it != kv.end()) cred.session_token = it->second;
        if (auto it = kv.find("region"); it != kv.end()) region_out = it->second;
    }
    if (!conf_path.empty()) {
        const std::string section = (profile == "default") ? "default" : ("profile " + profile);
        const auto kv = parse_ini_section(conf_path, section);
        if (cred.access_key.empty())
            if (auto it = kv.find("aws_access_key_id"); it != kv.end()) cred.access_key = it->second;
        if (cred.secret_key.empty())
            if (auto it = kv.find("aws_secret_access_key"); it != kv.end()) cred.secret_key = it->second;
        if (cred.session_token.empty())
            if (auto it = kv.find("aws_session_token"); it != kv.end()) cred.session_token = it->second;
        if (region_out.empty())
            if (auto it = kv.find("region"); it != kv.end()) region_out = it->second;
    }
}

// Minimal HTTP for the metadata endpoints. Returns true on a 2xx; body is the response.
bool http_metadata(const std::string& url, const std::vector<std::string>& headers, bool put,
                   std::string& out) {
    CURL* c = curl_easy_init();
    if (c == nullptr) {
        return false;
    }
    out.clear();
    curl_slist* hdr = nullptr;
    for (const auto& h : headers) {
        hdr = curl_slist_append(hdr, h.c_str());
    }
    curl_easy_setopt(c, CURLOPT_URL, url.c_str());
    apply_tls_options(c);
    if (put) {
        curl_easy_setopt(c, CURLOPT_CUSTOMREQUEST, "PUT");
    }
    if (hdr != nullptr) {
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdr);
    }
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, &write_to_string);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &out);
    curl_easy_setopt(c, CURLOPT_CONNECTTIMEOUT_MS, kMetaConnectMs);
    curl_easy_setopt(c, CURLOPT_TIMEOUT_MS, kMetaTotalMs);
    curl_easy_setopt(c, CURLOPT_NOSIGNAL, 1L);
    const CURLcode rc = curl_easy_perform(c);
    long code = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &code);
    if (hdr != nullptr) {
        curl_slist_free_all(hdr);
    }
    curl_easy_cleanup(c);
    return rc == CURLE_OK && code >= 200 && code < 300;
}

// Extract a string value for "key" from a flat AWS JSON metadata response (no nesting/escaping in these).
std::string json_field(const std::string& body, const char* key) {
    const std::string needle = std::string("\"") + key + "\"";
    auto p = body.find(needle);
    if (p == std::string::npos) {
        return "";
    }
    p = body.find(':', p + needle.size());
    if (p == std::string::npos) {
        return "";
    }
    ++p;
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) {
        ++p;
    }
    if (p >= body.size() || body[p] != '"') {
        return "";
    }
    ++p;
    const auto e = body.find('"', p);
    return e == std::string::npos ? "" : body.substr(p, e - p);
}

std::optional<std::chrono::system_clock::time_point> parse_iso8601(const std::string& s) {
    if (s.empty()) {
        return std::nullopt;
    }
    std::tm tm{};
    if (strptime(s.c_str(), "%Y-%m-%dT%H:%M:%S", &tm) == nullptr) {
        return std::nullopt;
    }
    return std::chrono::system_clock::from_time_t(timegm(&tm));
}

void fill_creds_from_json(const std::string& body, Credentials& cred) {
    cred.access_key = json_field(body, "AccessKeyId");
    cred.secret_key = json_field(body, "SecretAccessKey");
    cred.session_token = json_field(body, "Token");
    cred.expiry = parse_iso8601(json_field(body, "Expiration"));
}

// The `credential_process` command configured for `profile`, if any (credentials file wins over config).
std::string profile_credential_process(const std::string& profile) {
    const std::string home = env_or("HOME", "");
    const std::string cred_path =
        env_or("AWS_SHARED_CREDENTIALS_FILE", home.empty() ? "" : home + "/.aws/credentials");
    const std::string conf_path = env_or("AWS_CONFIG_FILE", home.empty() ? "" : home + "/.aws/config");
    if (!cred_path.empty()) {
        const auto kv = parse_ini_section(cred_path, profile);
        if (auto it = kv.find("credential_process"); it != kv.end() && !it->second.empty()) return it->second;
    }
    if (!conf_path.empty()) {
        const std::string section = (profile == "default") ? "default" : ("profile " + profile);
        const auto kv = parse_ini_section(conf_path, section);
        if (auto it = kv.find("credential_process"); it != kv.end() && !it->second.empty()) return it->second;
    }
    return "";
}

// Run a profile's credential_process helper and parse its JSON stdout, which has the shape
//   {"Version":1,"AccessKeyId":..,"SecretAccessKey":..,"SessionToken":..,"Expiration":..}
// (note "SessionToken", unlike the "Token" the metadata endpoints use). The command is trusted input — it
// comes from the user's own ~/.aws config, exactly as the AWS CLI treats it.
bool load_credential_process(const std::string& profile, Credentials& cred) {
    const std::string cmd = profile_credential_process(profile);
    if (cmd.empty()) {
        return false;
    }
    std::string out;
    FILE* pipe = ::popen(cmd.c_str(), "r");
    if (pipe == nullptr) {
        return false;
    }
    char buf[4096];
    size_t got = 0;
    while ((got = std::fread(buf, 1, sizeof buf, pipe)) > 0) {
        out.append(buf, got);
        if (out.size() > (1u << 20)) {  // 1 MiB cap; the credential JSON is tiny
            break;
        }
    }
    ::pclose(pipe);  // a failed helper just yields no usable JSON, caught by valid() below
    cred.access_key = json_field(out, "AccessKeyId");
    cred.secret_key = json_field(out, "SecretAccessKey");
    cred.session_token = json_field(out, "SessionToken");
    cred.expiry = parse_iso8601(json_field(out, "Expiration"));
    return cred.valid();
}

// ECS / EKS container credentials (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or _FULL_URI).
bool load_ecs(Credentials& cred) {
    const std::string rel = env_or("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "");
    const std::string full = env_or("AWS_CONTAINER_CREDENTIALS_FULL_URI", "");
    std::string url;
    if (!rel.empty()) {
        url = "http://169.254.170.2" + rel;
    } else if (!full.empty()) {
        url = full;
    } else {
        return false;
    }
    std::vector<std::string> headers;
    const std::string token = env_or("AWS_CONTAINER_AUTHORIZATION_TOKEN", "");
    if (!token.empty()) {
        headers.push_back("Authorization: " + token);
    }
    std::string body;
    if (!http_metadata(url, headers, false, body)) {
        return false;
    }
    fill_creds_from_json(body, cred);
    return cred.valid();
}

// EC2 instance role via IMDSv2 (falls back to IMDSv1 if the token PUT is refused).
bool load_imds(Credentials& cred) {
    const std::string base = "http://169.254.169.254";
    std::string token;
    http_metadata(base + "/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds: 21600"}, true, token);
    std::vector<std::string> headers;
    if (!token.empty()) {
        headers.push_back("X-aws-ec2-metadata-token: " + token);
    }
    std::string role;
    if (!http_metadata(base + "/latest/meta-data/iam/security-credentials/", headers, false, role)) {
        return false;
    }
    role = trim_ws(role);
    if (const auto nl = role.find('\n'); nl != std::string::npos) {
        role = trim_ws(role.substr(0, nl));  // first role if several are listed
    }
    if (role.empty()) {
        return false;
    }
    std::string body;
    if (!http_metadata(base + "/latest/meta-data/iam/security-credentials/" + role, headers, false, body)) {
        return false;
    }
    fill_creds_from_json(body, cred);
    return cred.valid();
}

// Explain why `profile` yielded no static keys (for diagnostics): missing files, missing profile, or a
// profile that uses a mechanism the built-in reader does not resolve (SSO / credential_process / assume-role
// — the AWS CLI handles these, so `aws` working while this reader doesn't usually means one of them).
std::string describe_profile_gap(const std::string& profile) {
    const std::string home = env_or("HOME", "");
    const std::string cred_path =
        env_or("AWS_SHARED_CREDENTIALS_FILE", home.empty() ? "" : home + "/.aws/credentials");
    const std::string conf_path = env_or("AWS_CONFIG_FILE", home.empty() ? "" : home + "/.aws/config");
    const bool cred_ok = !cred_path.empty() && std::ifstream(cred_path).good();
    const bool conf_ok = !conf_path.empty() && std::ifstream(conf_path).good();
    if (!cred_ok && !conf_ok) {
        return "no profile files (looked for '" + cred_path + "' and '" + conf_path + "')";
    }
    const auto cred_kv = cred_ok ? parse_ini_section(cred_path, profile) : std::map<std::string, std::string>{};
    const std::string section = (profile == "default") ? "default" : ("profile " + profile);
    const auto conf_kv = conf_ok ? parse_ini_section(conf_path, section) : std::map<std::string, std::string>{};
    if (cred_kv.empty() && conf_kv.empty()) {
        return "profile '" + profile + "' not found in the profile files";
    }
    const auto has = [](const std::map<std::string, std::string>& m, const char* k) {
        return m.find(k) != m.end();
    };
    if (has(conf_kv, "credential_process") || has(cred_kv, "credential_process")) {
        return "profile '" + profile +
               "' credential_process helper failed or returned no usable credentials";
    }
    if (has(conf_kv, "sso_session") || has(conf_kv, "sso_account_id") || has(conf_kv, "sso_start_url")) {
        return "profile '" + profile +
               "' uses AWS SSO, which the built-in reader does not resolve — run 'aws sso login', then "
               "export AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN to env";
    }
    if (has(conf_kv, "role_arn") || has(conf_kv, "source_profile")) {
        return "profile '" + profile +
               "' uses assume-role, which the built-in reader does not perform — export creds to env";
    }
    return "profile '" + profile + "' has no aws_access_key_id/aws_secret_access_key";
}

// Thread-safe provider walking the standard chain, caching the result and refreshing temporary creds a few
// minutes before they expire. Shared by every stream the (process-singleton) factory opens. On failure it
// records a per-source diagnostic (see diagnostic()) so the caller can report *why* no creds were found.
class CredentialProvider {
public:
    explicit CredentialProvider(std::string profile) : profile_(std::move(profile)) {}

    Credentials get() {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::system_clock::now();
        if (cached_.valid() && (!cached_.expiry || now < *cached_.expiry - std::chrono::minutes(5))) {
            return cached_;
        }
        // Don't hammer IMDS when there are simply no creds: back off between failed resolutions.
        if (!cached_.valid() && attempted_ && now < last_attempt_ + std::chrono::seconds(2)) {
            return cached_;
        }
        attempted_ = true;
        last_attempt_ = now;
        Credentials fresh;
        std::string diag;
        if (resolve(fresh, diag)) {
            cached_ = fresh;
            diagnostic_.clear();
        } else {
            diagnostic_ = diag;
        }
        return cached_;
    }

    // Why the last resolution found nothing — a chain of "source: reason" notes.
    std::string diagnostic() {
        std::lock_guard<std::mutex> lock(mutex_);
        return diagnostic_.empty() ? "no AWS credentials found" : diagnostic_;
    }

private:
    bool resolve(Credentials& out, std::string& diag) {
        const std::string ak = env_or("AWS_ACCESS_KEY_ID", "");
        const std::string sk = env_or("AWS_SECRET_ACCESS_KEY", "");
        if (!ak.empty() && !sk.empty()) {
            out.access_key = ak;
            out.secret_key = sk;
            out.session_token = env_or("AWS_SESSION_TOKEN", "");
            out.expiry = std::nullopt;
            return true;
        }
        std::string notes = "env: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY not set";
        {
            Credentials prof;
            std::string region_unused;
            load_profile(profile_, prof, region_unused);
            if (prof.valid()) {
                prof.expiry = std::nullopt;  // shared-file creds are static
                out = prof;
                return true;
            }
            if (load_credential_process(profile_, out)) {  // profile's credential_process helper
                return true;
            }
            notes += "; profile: " + describe_profile_gap(profile_);
        }
        if (!env_or("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "").empty() ||
            !env_or("AWS_CONTAINER_CREDENTIALS_FULL_URI", "").empty()) {
            if (load_ecs(out)) {
                return true;
            }
            notes += "; ECS: container endpoint returned no usable creds";
        }
        if (load_imds(out)) {
            return true;
        }
        notes += "; IMDS: no EC2 instance role (metadata endpoint unreachable or empty)";
        diag = notes;
        return false;
    }

    std::mutex mutex_;
    Credentials cached_;
    std::string diagnostic_;
    std::string profile_;
    bool attempted_ = false;
    std::chrono::system_clock::time_point last_attempt_{};
};

}  // namespace

namespace s3detail {
struct Config {
    std::string region;
    std::string endpoint;    // empty -> AWS virtual-hosted; non-empty -> path-style against this endpoint
    bool path_style = false;
    int max_attempts = 3;    // total tries per GET (AWS_MAX_ATTEMPTS), >= 1
    std::shared_ptr<CredentialProvider> creds;
};
}  // namespace s3detail

namespace {

// Resolved request target: the Host header value, the full request URL, and the canonical (encoded) path.
struct Endpoint {
    std::string host;
    std::string url;
    std::string path;
};

Endpoint build_endpoint(const s3detail::Config& cfg, const std::string& bucket, const std::string& key,
                        const std::string& region) {
    Endpoint e;
    if (cfg.path_style) {
        // endpoint like "http://localhost:9000" — strip scheme to get the host:port for the Host header.
        std::string ep = cfg.endpoint;
        std::string scheme = "https://";
        if (ep.rfind("http://", 0) == 0) {
            scheme = "http://";
            ep = ep.substr(7);
        } else if (ep.rfind("https://", 0) == 0) {
            ep = ep.substr(8);
        }
        while (!ep.empty() && ep.back() == '/') {
            ep.pop_back();
        }
        e.host = ep;
        e.path = uri_encode_path("/" + bucket + "/" + key);
        e.url = scheme + e.host + e.path;
    } else {
        e.host = bucket + ".s3." + region + ".amazonaws.com";
        e.path = uri_encode_path("/" + key);
        e.url = "https://" + e.host + e.path;
    }
    return e;
}

// Capture the `x-amz-bucket-region` response header (S3 returns it on wrong-region redirects), so we can
// re-target and retry against the correct region.
std::size_t capture_region_header(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
    const std::size_t n = size * nitems;
    auto* region = static_cast<std::string*>(userdata);
    const std::string kKey = "x-amz-bucket-region:";
    std::string line(buffer, n);
    std::string prefix = line.substr(0, std::min(line.size(), kKey.size()));
    for (char& c : prefix) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (prefix == kKey) {
        *region = trim_ws(line.substr(kKey.size()));
    }
    return n;
}

bool is_retriable_curl(CURLcode rc) {
    switch (rc) {
        case CURLE_OPERATION_TIMEDOUT:
        case CURLE_COULDNT_CONNECT:
        case CURLE_COULDNT_RESOLVE_HOST:
        case CURLE_COULDNT_RESOLVE_PROXY:
        case CURLE_SEND_ERROR:
        case CURLE_RECV_ERROR:
        case CURLE_GOT_NOTHING:
        case CURLE_PARTIAL_FILE:
        case CURLE_SSL_CONNECT_ERROR:
            return true;
        default:
            return false;
    }
}

// Full-jitter exponential backoff before retry `attempt` (1-based).
void sleep_backoff(int attempt) {
    long ceiling = kBackoffBaseMs;
    for (int i = 1; i < attempt && ceiling < kBackoffCapMs; ++i) {
        ceiling <<= 1;
    }
    ceiling = std::min(ceiling, kBackoffCapMs);
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<long> dist(0, ceiling);
    std::this_thread::sleep_for(std::chrono::milliseconds(dist(rng)));
}

// --- disk-resident LRU block cache -----------------------------------------------------------------
// Process-global, opt-in. Persists fetched read-ahead-aligned blocks as flat files so a re-read of any
// offset inside a previously fetched block is served from local disk instead of a fresh range GET. The
// LRU is mtime-based: a hit touches the file's mtime (most-recently-used), and a store evicts the file
// with the oldest mtime once the directory exceeds the capacity. N <= 500, so the O(N) eviction scan is
// cheap. File I/O and eviction run under one mutex; the enabled() check on the hot path is lock-free.

class DiskCache {
public:
    bool configure(const std::string& dir, int max_blocks) {
        std::lock_guard<std::mutex> lock(mu_);
        if (max_blocks <= 0) {
            enabled_.store(false, std::memory_order_relaxed);
            return true;
        }
        max_blocks = std::clamp(max_blocks, 2, 500);
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        if (ec) {
            enabled_.store(false, std::memory_order_relaxed);
            return false;
        }
        dir_ = dir;
        max_blocks_ = max_blocks;
        enabled_.store(true, std::memory_order_relaxed);
        return true;
    }

    bool enabled() const { return enabled_.load(std::memory_order_relaxed); }

    void stats(std::uint64_t* out_hits, std::uint64_t* out_misses) const {
        if (out_hits != nullptr) {
            *out_hits = hits_.load(std::memory_order_relaxed);
        }
        if (out_misses != nullptr) {
            *out_misses = misses_.load(std::memory_order_relaxed);
        }
    }

    // On a hit: read the block into `out`, promote it (mtime -> now), count the hit, return true.
    // On a miss: count the miss, return false (the caller then fetches from S3 and calls store()).
    bool try_load(const std::string& uri, std::uint64_t chunk_start, std::vector<char>& out) {
        std::lock_guard<std::mutex> lock(mu_);
        const std::filesystem::path path = path_for(uri, chunk_start);
        std::error_code ec;
        const auto size = std::filesystem::file_size(path, ec);
        if (ec) {  // missing or unstattable -> miss
            misses_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            misses_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        out.resize(static_cast<std::size_t>(size));
        if (size > 0 && !in.read(out.data(), static_cast<std::streamsize>(size))) {
            misses_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        std::filesystem::last_write_time(path, std::filesystem::file_time_type::clock::now(), ec);
        hits_.fetch_add(1, std::memory_order_relaxed);
        return true;
    }

    // Write `data` as the block for (uri, chunk_start), then evict the oldest blocks past capacity. The
    // block is written to a temp file and renamed into place so a crash never leaves a torn block behind.
    void store(const std::string& uri, std::uint64_t chunk_start, const std::vector<char>& data) {
        std::lock_guard<std::mutex> lock(mu_);
        const std::filesystem::path path = path_for(uri, chunk_start);
        const std::filesystem::path tmp = path.string() + ".tmp";
        {
            std::ofstream o(tmp, std::ios::binary | std::ios::trunc);
            if (!o) {
                return;  // cache write is best-effort; a failure just means a future miss
            }
            if (!data.empty()) {
                o.write(data.data(), static_cast<std::streamsize>(data.size()));
            }
            if (!o) {
                o.close();
                std::error_code ec;
                std::filesystem::remove(tmp, ec);
                return;
            }
        }
        std::error_code ec;
        std::filesystem::rename(tmp, path, ec);
        if (ec) {
            std::filesystem::remove(tmp, ec);
            return;
        }
        evict_if_needed();
    }

private:
    std::filesystem::path path_for(const std::string& uri, std::uint64_t chunk_start) const {
        std::uint64_t h = 5381;
        for (unsigned char c : uri) {
            h = ((h << 5) + h) + c;  // djb2
        }
        return std::filesystem::path(dir_) / (hex16(h) + "_" + hex16(chunk_start) + ".blk");
    }

    static std::string hex16(std::uint64_t v) {
        static const char* const kHex = "0123456789abcdef";
        std::string s(16, '0');
        for (int i = 15; i >= 0; --i) {
            s[i] = kHex[v & 0xF];
            v >>= 4;
        }
        return s;
    }

    // Called with mu_ held. Deletes the oldest-mtime *.blk file until the count is within capacity.
    void evict_if_needed() {
        for (;;) {
            std::error_code ec;
            std::size_t count = 0;
            std::filesystem::path oldest;
            std::filesystem::file_time_type oldest_t = std::filesystem::file_time_type::max();
            for (const auto& entry : std::filesystem::directory_iterator(dir_, ec)) {
                if (ec) {
                    return;
                }
                if (entry.path().extension() != ".blk") {
                    continue;
                }
                ++count;
                const auto t = entry.last_write_time(ec);
                if (ec) {
                    continue;
                }
                if (t < oldest_t) {
                    oldest_t = t;
                    oldest = entry.path();
                }
            }
            if (count <= static_cast<std::size_t>(max_blocks_) || oldest.empty()) {
                return;
            }
            std::filesystem::remove(oldest, ec);
        }
    }

    std::atomic<bool> enabled_{false};
    std::mutex mu_;
    std::string dir_;
    int max_blocks_ = 0;
    std::atomic<std::uint64_t> hits_{0};
    std::atomic<std::uint64_t> misses_{0};
};

DiskCache g_disk_cache;

// Seekable streambuf over S3 range GETs. Each underflow/refetch pulls one read-ahead window so consecutive
// slices within a window cost no extra GET (matching the access pattern in nano_lance_external_blob.cpp).
// The single curl handle is reused across windows so the connection stays keep-alive for the object.
class S3Streambuf : public std::streambuf {
public:
    S3Streambuf(std::shared_ptr<const s3detail::Config> cfg, std::string uri, std::string bucket,
                std::string key, std::size_t read_ahead)
        : cfg_(std::move(cfg)), uri_(std::move(uri)), bucket_(std::move(bucket)), key_(std::move(key)),
          region_(cfg_->region), read_ahead_(read_ahead == 0 ? 1 : read_ahead) {
        ensure_curl_global_init();
        curl_ = curl_easy_init();
        const Endpoint e = build_endpoint(*cfg_, bucket_, key_, region_);
        host_ = e.host;
        url_ = e.url;
        path_ = e.path;
    }

    ~S3Streambuf() override {
        if (curl_ != nullptr) {
            curl_easy_cleanup(curl_);
        }
    }

    bool ok() const { return curl_ != nullptr; }

protected:
    int_type underflow() override {
        if (gptr() < egptr()) {
            return traits_type::to_int_type(*gptr());
        }
        if (reached_eof_) {
            return traits_type::eof();
        }
        const std::uint64_t next = window_start_ + window_len_;
        if (!load_window(next)) {
            return traits_type::eof();
        }
        if (window_len_ == 0) {
            reached_eof_ = true;
            return traits_type::eof();
        }
        return traits_type::to_int_type(*gptr());
    }

    pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which) override {
        if ((which & std::ios_base::in) == 0) {
            return pos_type(off_type(-1));
        }
        std::int64_t base = 0;
        if (dir == std::ios_base::beg) {
            base = 0;
        } else if (dir == std::ios_base::cur) {
            base = static_cast<std::int64_t>(cur_pos());
        } else {
            return pos_type(off_type(-1));  // SEEK_END: object size unknown; the caller only uses beg/cur
        }
        const std::int64_t target = base + static_cast<std::int64_t>(off);
        if (target < 0) {
            return pos_type(off_type(-1));
        }
        return seekpos(pos_type(static_cast<off_type>(target)), which);
    }

    pos_type seekpos(pos_type sp, std::ios_base::openmode which) override {
        if ((which & std::ios_base::in) == 0) {
            return pos_type(off_type(-1));
        }
        // The caller seeks before every read, so this is the start of a fresh logical fetch: drop any stale
        // error so a later error() reflects only this fetch.
        g_last_error.clear();
        const std::uint64_t target = static_cast<std::uint64_t>(static_cast<off_type>(sp));
        // Inside the live window? Just move the get pointer — no GET.
        if (window_len_ > 0 && target >= window_start_ && target <= window_start_ + window_len_) {
            char* base = window_.data();
            setg(base, base + (target - window_start_), base + window_len_);
            return sp;
        }
        if (!load_window(target)) {
            return pos_type(off_type(-1));
        }
        return sp;
    }

private:
    std::uint64_t cur_pos() const {
        return window_start_ + static_cast<std::uint64_t>(gptr() - eback());
    }

    // Position the get area after a successful body (or cache) fetch. `window_origin` is where the fetched
    // bytes begin in the object: for a 206 (or a cached block) that's the fetch/chunk start; for a 200 the
    // server ignored Range and returned the whole object from offset 0. `logical_pos` is the offset the
    // caller seeked to — the get pointer is placed there within the window so reads land correctly even when
    // the window was fetched aligned to a chunk boundary below `logical_pos`.
    void install_window(std::uint64_t window_origin, std::uint64_t logical_pos, bool partial) {
        char* base = window_.data();
        if (partial) {  // 206 Partial Content, or a block served from the disk cache
            window_start_ = window_origin;
            reached_eof_ = window_.size() < read_ahead_;  // a short window means the object ended here
        } else {  // 200 OK: full object from offset 0
            window_start_ = 0;
            reached_eof_ = true;
        }
        window_len_ = window_.size();
        std::uint64_t goff = (logical_pos >= window_start_) ? (logical_pos - window_start_) : 0;
        if (goff > window_len_) {
            goff = window_len_;
        }
        setg(base, base + goff, base + window_len_);
    }

    void fail(const std::string& msg) {
        last_error_ = msg;
        g_last_error = msg;
        window_len_ = 0;
        setg(nullptr, nullptr, nullptr);
    }

    // Make the window hold the bytes covering logical offset `target`, positioning the get pointer there.
    // Fetches one read-ahead window, with retry/backoff and one-shot region redirect. When the disk cache is
    // enabled the fetch is aligned to a read-ahead-sized chunk boundary (so any later read within the chunk
    // is a hit), the block is served from disk on a hit, and a freshly fetched chunk is written back.
    // Returns false only on a real transport/HTTP error (sets the thread error); an empty/short read at
    // end-of-object is a success that flags reached_eof_.
    bool load_window(std::uint64_t target) {
        if (curl_ == nullptr) {
            fail("curl init failed");
            return false;
        }
        // With the cache on, fetch (and key) on the chunk-aligned start; otherwise fetch exactly at target.
        const bool cache_on = g_disk_cache.enabled();
        const std::uint64_t start = cache_on ? (target / read_ahead_) * read_ahead_ : target;

        if (cache_on && g_disk_cache.try_load(uri_, start, window_)) {
            install_window(start, target, /*partial=*/true);
            g_last_error.clear();
            return true;
        }

        const Credentials cred = cfg_->creds->get();
        if (!cred.valid()) {
            fail("missing AWS credentials — " + cfg_->creds->diagnostic());
            return false;
        }
        bool redirected = false;
        int attempt = 0;
        for (;;) {
            window_.clear();
            window_.reserve(read_ahead_);
            region_header_.clear();

            const std::uint64_t last = start + read_ahead_ - 1;
            const std::string range = "bytes=" + std::to_string(start) + "-" + std::to_string(last);
            const std::string amz_date = amz_now();  // fresh per attempt: backoff must not skew the signature

            std::vector<s3v4::Header> sign_headers = {
                {"host", host_},
                {"range", range},
                {"x-amz-content-sha256", "UNSIGNED-PAYLOAD"},
                {"x-amz-date", amz_date},
            };
            if (!cred.session_token.empty()) {
                sign_headers.push_back({"x-amz-security-token", cred.session_token});
            }
            s3v4::CanonicalRequest req;
            req.method = "GET";
            req.uri = path_;
            req.query = "";
            req.headers = sign_headers;
            req.payload_hash = "UNSIGNED-PAYLOAD";
            const std::string authz = s3v4::build_authorization(req, cred.access_key, cred.secret_key,
                                                                region_, "s3", amz_date);

            curl_slist* hdrs = nullptr;
            hdrs = curl_slist_append(hdrs, ("x-amz-date: " + amz_date).c_str());
            hdrs = curl_slist_append(hdrs, "x-amz-content-sha256: UNSIGNED-PAYLOAD");
            hdrs = curl_slist_append(hdrs, ("Range: " + range).c_str());
            if (!cred.session_token.empty()) {
                hdrs = curl_slist_append(hdrs, ("x-amz-security-token: " + cred.session_token).c_str());
            }
            hdrs = curl_slist_append(hdrs, ("Authorization: " + authz).c_str());

            curl_easy_reset(curl_);  // preserves the live connection + DNS/TLS caches (keep-alive)
            curl_easy_setopt(curl_, CURLOPT_URL, url_.c_str());
            apply_tls_options(curl_);
            curl_easy_setopt(curl_, CURLOPT_HTTPGET, 1L);
            curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, hdrs);
            curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, &write_to_vector);
            curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &window_);
            curl_easy_setopt(curl_, CURLOPT_HEADERFUNCTION, &capture_region_header);
            curl_easy_setopt(curl_, CURLOPT_HEADERDATA, &region_header_);
            curl_easy_setopt(curl_, CURLOPT_FOLLOWLOCATION, 0L);
            curl_easy_setopt(curl_, CURLOPT_NOSIGNAL, 1L);
            curl_easy_setopt(curl_, CURLOPT_TCP_KEEPALIVE, 1L);
            curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, kConnectTimeoutSec);
            curl_easy_setopt(curl_, CURLOPT_LOW_SPEED_LIMIT, kLowSpeedBytes);
            curl_easy_setopt(curl_, CURLOPT_LOW_SPEED_TIME, kLowSpeedTimeSec);

            const CURLcode rc = curl_easy_perform(curl_);
            long code = 0;
            curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &code);
            curl_slist_free_all(hdrs);

            if (rc == CURLE_OK && (code == 200 || code == 206)) {
                if (cache_on && code == 206) {  // only aligned partial blocks are cacheable
                    g_disk_cache.store(uri_, start, window_);
                }
                install_window(start, target, code == 206);
                g_last_error.clear();
                return true;
            }
            if (rc == CURLE_OK && code == 416) {  // Range Not Satisfiable: at/over the end of the object.
                window_start_ = start;
                window_len_ = 0;
                reached_eof_ = true;
                setg(nullptr, nullptr, nullptr);
                g_last_error.clear();
                return true;
            }

            // Wrong-region redirect (virtual-hosted only): re-target to the region S3 reported and retry
            // immediately (once), without consuming a backoff attempt.
            if (rc == CURLE_OK && !cfg_->path_style && (code == 301 || code == 307 || code == 400) &&
                !region_header_.empty() && region_header_ != region_ && !redirected) {
                region_ = region_header_;
                const Endpoint e = build_endpoint(*cfg_, bucket_, key_, region_);
                host_ = e.host;
                url_ = e.url;
                path_ = e.path;
                redirected = true;
                continue;
            }

            const bool http_retriable =
                rc == CURLE_OK && (code == 500 || code == 502 || code == 503 || code == 504 || code == 429);
            const bool retriable = is_retriable_curl(rc) || http_retriable;
            ++attempt;
            if (retriable && attempt < cfg_->max_attempts) {
                sleep_backoff(attempt);
                continue;
            }

            if (rc != CURLE_OK) {
                fail(std::string("S3 GET transport error: ") + curl_error_text(rc));
            } else {
                std::string body(window_.begin(), window_.end());
                if (body.size() > 512) {
                    body.resize(512);
                }
                fail("S3 GET HTTP " + std::to_string(code) + ": " + body);
            }
            return false;
        }
    }

    std::shared_ptr<const s3detail::Config> cfg_;
    std::string uri_;  // original s3:// URI, used as the disk-cache key
    std::string bucket_;
    std::string key_;
    std::string region_;  // effective region (may change once on a wrong-region redirect)
    std::string host_;
    std::string url_;
    std::string path_;  // percent-encoded canonical path
    std::size_t read_ahead_;
    CURL* curl_ = nullptr;
    std::string region_header_;  // x-amz-bucket-region captured from the last response

    std::vector<char> window_;
    std::uint64_t window_start_ = 0;
    std::size_t window_len_ = 0;
    bool reached_eof_ = false;
    std::string last_error_;
};

// istream that owns its streambuf so the unique_ptr<istream> the factory returns keeps the buffer alive.
class S3IStream : public std::istream {
public:
    explicit S3IStream(std::unique_ptr<S3Streambuf> buf) : std::istream(buf.get()), buf_(std::move(buf)) {}

private:
    std::unique_ptr<S3Streambuf> buf_;
};

}  // namespace

S3MinStreamFactory::S3MinStreamFactory() {
    auto cfg = std::make_shared<s3detail::Config>();
    const std::string profile = aws_profile();
    cfg->creds = std::make_shared<CredentialProvider>(profile);

    // Region precedence: env -> shared-config profile -> default. (Credentials resolve lazily on first use.)
    std::string region = env_or("AWS_REGION", env_or("AWS_DEFAULT_REGION", ""));
    if (region.empty()) {
        Credentials ignore;
        load_profile(profile, ignore, region);
    }
    cfg->region = region.empty() ? "us-east-1" : region;

    cfg->endpoint = env_or("AWS_ENDPOINT_URL", "");
    cfg->path_style = !cfg->endpoint.empty();
    const int attempts = std::atoi(env_or("AWS_MAX_ATTEMPTS", "3").c_str());
    cfg->max_attempts = attempts >= 1 ? attempts : 3;
    config_ = cfg;
}

std::string S3MinStreamFactory::error() const { return g_last_error; }

std::unique_ptr<std::istream> S3MinStreamFactory::open(const std::string& uri, std::size_t read_ahead_bytes) {
    g_last_error.clear();
    if (uri.rfind("s3://", 0) != 0) {
        g_last_error = "not an s3:// URI";
        return nullptr;
    }
    const std::string rest = uri.substr(5);  // strip "s3://"
    const auto slash = rest.find('/');
    if (slash == std::string::npos || slash == 0 || slash + 1 >= rest.size()) {
        g_last_error = "malformed s3:// URI (expected s3://bucket/key)";
        return nullptr;
    }
    const std::string bucket = rest.substr(0, slash);
    const std::string key = rest.substr(slash + 1);

    if (!config_->creds->get().valid()) {
        g_last_error = "missing AWS credentials — " + config_->creds->diagnostic();
        return nullptr;
    }

    auto buf = std::make_unique<S3Streambuf>(config_, uri, bucket, key, read_ahead_bytes);
    if (!buf->ok()) {
        g_last_error = "failed to initialize libcurl handle";
        return nullptr;
    }
    return std::make_unique<S3IStream>(std::move(buf));
}

bool configure_disk_cache(const std::string& cache_dir, int max_blocks) {
    return g_disk_cache.configure(cache_dir, max_blocks);
}

void disk_cache_stats(std::uint64_t* out_hits, std::uint64_t* out_misses) {
    g_disk_cache.stats(out_hits, out_misses);
}

// --- object-store client: HEAD, range GET, ListObjectsV2 -------------------------------------------

namespace {

constexpr int kClientRetries = 3;                   // retries after the first attempt (4 tries in all)
constexpr std::size_t kClientTextCap = 16u << 20;   // largest list page / error body kept in memory

// One libcurl easy handle per thread, reused for every S3Client on that thread. Each request resets it
// (which keeps the live connection and DNS/TLS caches) and sets all of its own options.
struct ThreadCurl {
    CURL* handle = nullptr;
    ~ThreadCurl() {
        if (handle != nullptr) {
            curl_easy_cleanup(handle);
        }
    }
};

CURL* thread_easy_handle() {
    thread_local ThreadCurl tc;
    if (tc.handle == nullptr) {
        tc.handle = curl_easy_init();
    }
    return tc.handle;
}

// RFC 3986 encoding of one query-string name or value: everything except unreserved bytes, '/' included.
std::string uri_encode_component(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                                c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back("0123456789ABCDEF"[c >> 4]);
            out.push_back("0123456789ABCDEF"[c & 0x0F]);
        }
    }
    return out;
}

// "s3://bucket/key" -> bucket and key. Object operations need a non-empty key; listings may have none.
bool split_s3_uri(const std::string& uri, bool need_key, std::string& bucket, std::string& key,
                  std::string& error) {
    if (uri.rfind("s3://", 0) != 0) {
        error = uri + ": not an s3:// URI";
        return false;
    }
    const std::string rest = uri.substr(5);
    const auto slash = rest.find('/');
    bucket = rest.substr(0, slash);
    key = (slash == std::string::npos) ? std::string() : rest.substr(slash + 1);
    if (bucket.empty() || (need_key && key.empty())) {
        error = uri + ": malformed s3:// URI (expected s3://bucket/key)";
        return false;
    }
    return true;
}

bool parse_u64(const std::string& s, std::uint64_t& out) {
    if (s.empty()) {
        return false;
    }
    std::uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') {
            return false;
        }
        const auto d = static_cast<std::uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) {
            return false;
        }
        v = v * 10 + d;
    }
    out = v;
    return true;
}

void append_utf8(std::string& out, std::uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// Decodes the XML entities S3 uses in keys and messages (named, decimal and hex numeric references).
std::string xml_unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '&') {
            out.push_back(s[i]);
            continue;
        }
        const auto semi = s.find(';', i);
        if (semi == std::string::npos || semi - i > 12) {
            out.push_back('&');
            continue;
        }
        const std::string ent = s.substr(i + 1, semi - i - 1);
        if (ent == "amp") {
            out.push_back('&');
        } else if (ent == "lt") {
            out.push_back('<');
        } else if (ent == "gt") {
            out.push_back('>');
        } else if (ent == "quot") {
            out.push_back('"');
        } else if (ent == "apos") {
            out.push_back('\'');
        } else if (!ent.empty() && ent[0] == '#') {
            const bool hex = ent.size() > 1 && (ent[1] == 'x' || ent[1] == 'X');
            const std::size_t first = hex ? 2 : 1;
            bool ok = ent.size() > first;
            std::uint32_t cp = 0;
            for (std::size_t j = first; ok && j < ent.size(); ++j) {
                const char c = ent[j];
                std::uint32_t d = 0;
                if (c >= '0' && c <= '9') {
                    d = static_cast<std::uint32_t>(c - '0');
                } else if (hex && c >= 'a' && c <= 'f') {
                    d = static_cast<std::uint32_t>(c - 'a' + 10);
                } else if (hex && c >= 'A' && c <= 'F') {
                    d = static_cast<std::uint32_t>(c - 'A' + 10);
                } else {
                    ok = false;
                    break;
                }
                cp = cp * (hex ? 16u : 10u) + d;
                if (cp > 0x10FFFF) {
                    ok = false;
                }
            }
            if (!ok) {
                out.push_back('&');
                continue;
            }
            append_utf8(out, cp);
        } else {
            out.push_back('&');
            continue;
        }
        i = semi;
    }
    return out;
}

// Finds the next <tag>...</tag> at or after `pos`. On success `inner` holds the raw text between the tags and
// `pos` moves past the closing tag. S3 responses carry no attributes on these elements.
bool next_element(const std::string& xml, std::size_t& pos, const std::string& tag, std::string& inner) {
    const std::string open = "<" + tag + ">";
    const std::string close = "</" + tag + ">";
    const auto b = xml.find(open, pos);
    if (b == std::string::npos) {
        return false;
    }
    const std::size_t start = b + open.size();
    const auto e = xml.find(close, start);
    if (e == std::string::npos) {
        return false;
    }
    inner = xml.substr(start, e - start);
    pos = e + close.size();
    return true;
}

// The <Code> of an S3 XML error body, or "" when there is none.
std::string xml_error_code(const std::string& body) {
    std::size_t pos = 0;
    std::string code;
    if (next_element(body, pos, "Code", code)) {
        return xml_unescape(code);
    }
    return "";
}

// Canonical query string for ListObjectsV2: parameter names in byte order, values encoded.
std::string list_query(const std::string& prefix, const std::string& delimiter, const std::string& token) {
    std::string q;
    if (!token.empty()) {
        q += "continuation-token=" + uri_encode_component(token) + "&";
    }
    if (!delimiter.empty()) {
        q += "delimiter=" + uri_encode_component(delimiter) + "&";
    }
    q += "list-type=2&prefix=" + uri_encode_component(prefix);
    return q;
}

// Parses one ListObjectsV2 page: appends its objects and common prefixes and reports the continuation.
bool parse_list_page(const std::string& xml, std::vector<ObjectInfo>& objects, std::vector<std::string>& prefixes,
                     bool& truncated, std::string& next_token, std::string& error) {
    std::size_t pos = 0;
    std::string body;
    while (next_element(xml, pos, "Contents", body)) {
        std::size_t key_pos = 0;
        std::size_t size_pos = 0;
        std::string key;
        std::string size_text;
        std::uint64_t size = 0;
        if (!next_element(body, key_pos, "Key", key) || !next_element(body, size_pos, "Size", size_text) ||
            !parse_u64(size_text, size)) {
            error = "malformed ListObjectsV2 response (Contents)";
            return false;
        }
        objects.push_back(ObjectInfo{xml_unescape(key), size});
    }
    pos = 0;
    while (next_element(xml, pos, "CommonPrefixes", body)) {
        std::size_t p = 0;
        std::string prefix;
        if (!next_element(body, p, "Prefix", prefix)) {
            error = "malformed ListObjectsV2 response (CommonPrefixes)";
            return false;
        }
        prefixes.push_back(xml_unescape(prefix));
    }
    std::string flag;
    pos = 0;
    truncated = next_element(xml, pos, "IsTruncated", flag) && flag == "true";
    std::string tok;
    pos = 0;
    next_token.clear();
    if (next_element(xml, pos, "NextContinuationToken", tok)) {
        next_token = xml_unescape(tok);
    }
    if (truncated && next_token.empty()) {
        error = "truncated ListObjectsV2 response without NextContinuationToken";
        return false;
    }
    return true;
}

// One signed request. `dst` receives the body of a 206 for a range read (exactly `dst_cap` bytes at most);
// every other body is collected into the reply's text.
struct Call {
    std::string method;  // "GET", "HEAD" or "PUT"
    std::string bucket;
    std::string key;     // "" for a listing (bucket root)
    std::string query;   // canonical, already encoded; "" when none
    std::string range;   // "bytes=a-b" or ""
    std::uint8_t* dst = nullptr;
    std::size_t dst_cap = 0;
    // PUT / POST: the body -- from memory (`body`), or `body_len` bytes of `body_file` from `body_offset` --
    // and headers sent with it unsigned ("Content-Type: ...", "If-None-Match: *", ...). A memory body's
    // SHA-256 is signed; a file body sends UNSIGNED-PAYLOAD unless `payload_hash` is given.
    const std::uint8_t* body = nullptr;
    std::size_t body_len = 0;
    std::FILE* body_file = nullptr;
    std::uint64_t body_offset = 0;
    std::uint64_t file_len = 0;
    std::string payload_hash;
    std::vector<std::string> extra_headers;
};

struct Reply {
    long code = 0;
    CURLcode rc = CURLE_OK;
    bool overflow = false;  // the body was larger than dst_cap / the text cap, and the transfer was aborted
    std::size_t dst_len = 0;
    std::int64_t content_length = -1;  // HEAD only
    std::string text;
    std::string etag;  // the ETag response header, quotes included, when one was sent
};

// Write-callback state, one per attempt.
struct Sink {
    CURL* handle = nullptr;
    std::uint8_t* dst = nullptr;
    std::size_t dst_cap = 0;
    std::size_t dst_len = 0;
    std::string text;
    bool overflow = false;
};

std::size_t sink_write(char* ptr, std::size_t size, std::size_t nmemb, void* userdata) {
    const std::size_t n = size * nmemb;
    auto* s = static_cast<Sink*>(userdata);
    long code = 0;
    curl_easy_getinfo(s->handle, CURLINFO_RESPONSE_CODE, &code);
    if (s->dst != nullptr && code == 206) {
        if (n > s->dst_cap - s->dst_len) {
            s->overflow = true;
            return 0;  // abort: more bytes than the caller asked for
        }
        std::memcpy(s->dst + s->dst_len, ptr, n);
        s->dst_len += n;
        return n;
    }
    if (s->text.size() + n > kClientTextCap) {
        s->overflow = true;
        return 0;
    }
    s->text.append(ptr, n);
    return n;
}

// Seek a stdio stream to a 64-bit offset.
bool seek_file(std::FILE* f, std::uint64_t offset) {
#if defined(_WIN32)
    return _fseeki64(f, static_cast<__int64>(offset), SEEK_SET) == 0;
#else
    return fseeko(f, static_cast<off_t>(offset), SEEK_SET) == 0;
#endif
}

// Read-callback state for a request body: from memory, or a range of a file streamed in libcurl's
// chunks (never held whole). A fresh one per attempt, so a retry sends the body from its start.
struct Upload {
    const std::uint8_t* data = nullptr;
    std::FILE* file = nullptr;
    std::uint64_t offset = 0;  // file: where the body starts
    std::uint64_t len = 0;
    std::uint64_t at = 0;
    bool failed = false;       // file: a seek or read failed (the transfer is aborted)
};

std::size_t upload_read(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
    auto* u = static_cast<Upload*>(userdata);
    const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(size * nitems, u->len - u->at));
    if (want == 0) {
        return 0;
    }
    if (u->file == nullptr) {
        std::memcpy(buffer, u->data + u->at, want);
        u->at += want;
        return want;
    }
    if (u->at == 0 && !seek_file(u->file, u->offset)) {
        u->failed = true;
        return CURL_READFUNC_ABORT;
    }
    const std::size_t got = std::fread(buffer, 1, want, u->file);
    if (got != want) {  // the file shrank or failed while being sent: never send a short object
        u->failed = true;
        return CURL_READFUNC_ABORT;
    }
    u->at += got;
    return got;
}

// Header callback: keeps the ETag header's value.
std::size_t capture_etag(char* buffer, std::size_t size, std::size_t nitems, void* userdata) {
    const std::size_t n = size * nitems;
    std::string line(buffer, n);
    const auto lower = [](char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); };
    if (line.size() > 5 && lower(line[0]) == 'e' && lower(line[1]) == 't' && lower(line[2]) == 'a' &&
        lower(line[3]) == 'g' && line[4] == ':') {
        std::string value = line.substr(5);
        const auto first = value.find_first_not_of(" \t");
        const auto last = value.find_last_not_of(" \t\r\n");
        *static_cast<std::string*>(userdata) =
            first == std::string::npos ? std::string() : value.substr(first, last - first + 1);
    }
    return n;
}

// Sends `call` with SigV4 signing, retrying 5xx, 429 and transport errors that libcurl marks retriable.
// Returns false only when no request could be made (no credentials, no handle); otherwise `reply` holds the
// last attempt's outcome, and the caller interprets it.
// Test-only fault injection, for the commit protocols built on this client (never set in production):
//   NANOS3READER_FAULTS="<action>:<METHOD>:<key substring>:<n>[,...]"
// matches requests by method and a substring of the key; <n> is the 1-based count of matching
// attempts the rule hits ("*": every one). Actions:
//   fail       no request is sent; the attempt fails as an unreachable host (retried as such)
//   http500    no request is sent; the attempt answers HTTP 500 (retried as such)
//   lost       the request is sent and the server acts on it, then the reply is dropped: the attempt
//              fails as a timeout, so a retry sees the effect of the first one (a PUT's 412)
//   nocond     If-None-Match / If-Match are not sent (a store that ignores conditional writes)
// Retries are attempts too: "fail:PUT:data/:*" fails a PUT under data/ however often it is retried.
enum class FaultAction { None, Fail, Http500, Lost, NoCond };

struct FaultRule {
    FaultAction action = FaultAction::None;
    std::string method;
    std::string key_part;
    std::uint64_t nth = 0;  // 0: every matching attempt
    std::atomic<std::uint64_t> seen{0};
};

std::vector<std::unique_ptr<FaultRule>>& fault_rules() {
    static std::vector<std::unique_ptr<FaultRule>> rules = [] {
        std::vector<std::unique_ptr<FaultRule>> out;
        const char* env = std::getenv("NANOS3READER_FAULTS");
        std::string spec = env != nullptr ? env : "";
        std::size_t at = 0;
        while (at < spec.size()) {
            std::size_t end = spec.find(',', at);
            if (end == std::string::npos) {
                end = spec.size();
            }
            const std::string item = spec.substr(at, end - at);
            at = end + 1;
            std::vector<std::string> parts;
            std::size_t p = 0;
            for (int i = 0; i < 3; ++i) {
                const std::size_t colon = item.find(':', p);
                if (colon == std::string::npos) {
                    break;
                }
                parts.push_back(item.substr(p, colon - p));
                p = colon + 1;
            }
            if (parts.size() != 3) {
                continue;
            }
            auto rule = std::make_unique<FaultRule>();
            const std::string& action = parts[0];
            rule->action = action == "fail"      ? FaultAction::Fail
                           : action == "http500" ? FaultAction::Http500
                           : action == "lost"    ? FaultAction::Lost
                           : action == "nocond"  ? FaultAction::NoCond
                                                 : FaultAction::None;
            rule->method = parts[1];
            rule->key_part = parts[2];
            const std::string nth = item.substr(p);
            rule->nth = nth == "*" ? 0U : std::strtoull(nth.c_str(), nullptr, 10);
            if (rule->action != FaultAction::None && (nth == "*" || rule->nth > 0U)) {
                out.push_back(std::move(rule));
            }
        }
        return out;
    }();
    return rules;
}

/// The fault this attempt of `call` is to suffer (None when no rule matches, the usual case).
FaultAction fault_for(const Call& call) {
    auto& rules = fault_rules();
    if (rules.empty()) {
        return FaultAction::None;
    }
    for (auto& rule : rules) {
        if (rule->method != call.method || call.key.find(rule->key_part) == std::string::npos) {
            continue;
        }
        const std::uint64_t n = rule->seen.fetch_add(1U) + 1U;
        if (rule->nth == 0U || n == rule->nth) {
            return rule->action;
        }
    }
    return FaultAction::None;
}

bool run_request(const s3detail::Config& cfg, const Credentials* fixed_creds, const Call& call, Reply& reply,
                 std::string& error) {
    ensure_curl_global_init();
    const std::string shown = "s3://" + call.bucket + (call.key.empty() ? "" : "/" + call.key);
    Credentials cred;
    if (fixed_creds != nullptr) {
        cred = *fixed_creds;
    } else {
        cred = cfg.creds->get();
        if (!cred.valid()) {
            error = shown + ": missing AWS credentials — " + cfg.creds->diagnostic();
            return false;
        }
    }
    const Endpoint ep = build_endpoint(cfg, call.bucket, call.key, cfg.region);
    std::string url = ep.url;
    if (!call.query.empty()) {
        url += "?" + call.query;
    }
    CURL* h = thread_easy_handle();
    if (h == nullptr) {
        error = shown + ": failed to initialize libcurl handle";
        return false;
    }
    const bool put = call.method == "PUT";
    const bool post = call.method == "POST";
    const bool file_body = call.body_file != nullptr;
    const std::uint64_t body_len = file_body ? call.file_len : call.body_len;
    // A memory body's SHA-256 is signed (S3 checks it); a file body sends the hash it was given, else
    // UNSIGNED-PAYLOAD (no second read of the file; HTTPS protects the transfer). No body: UNSIGNED-PAYLOAD.
    std::string payload_hash = "UNSIGNED-PAYLOAD";
    if (!call.payload_hash.empty()) {
        payload_hash = call.payload_hash;
    } else if ((put || post) && !file_body) {
        payload_hash = s3v4::sha256_hex(call.body, call.body_len);
    }

    for (int attempt = 0;; ++attempt) {
        const FaultAction fault = fault_for(call);
        if (fault == FaultAction::Fail || fault == FaultAction::Http500) {
            reply = Reply{};
            reply.rc = fault == FaultAction::Fail ? CURLE_COULDNT_CONNECT : CURLE_OK;
            reply.code = fault == FaultAction::Fail ? 0 : 500;
            if (attempt < kClientRetries) {
                sleep_backoff(attempt + 1);
                continue;
            }
            return true;
        }
        const std::string amz_date = amz_now();  // fresh per attempt so a backoff never skews the signature
        std::vector<s3v4::Header> sign_headers = {
            {"host", ep.host},
            {"x-amz-content-sha256", payload_hash},
            {"x-amz-date", amz_date},
        };
        if (!call.range.empty()) {
            sign_headers.push_back({"range", call.range});
        }
        if (!cred.session_token.empty()) {
            sign_headers.push_back({"x-amz-security-token", cred.session_token});
        }
        s3v4::CanonicalRequest req;
        req.method = call.method;
        req.uri = ep.path;
        req.query = call.query;
        req.headers = sign_headers;
        req.payload_hash = payload_hash;
        const std::string authz =
            s3v4::build_authorization(req, cred.access_key, cred.secret_key, cfg.region, "s3", amz_date);

        curl_slist* hdrs = nullptr;
        hdrs = curl_slist_append(hdrs, ("x-amz-date: " + amz_date).c_str());
        hdrs = curl_slist_append(hdrs, ("x-amz-content-sha256: " + payload_hash).c_str());
        for (const auto& extra : call.extra_headers) {
            if (fault == FaultAction::NoCond && (extra.rfind("If-None-Match:", 0) == 0 || extra.rfind("If-Match:", 0) == 0)) {
                continue;
            }
            hdrs = curl_slist_append(hdrs, extra.c_str());
        }
        if (put || post) {
            hdrs = curl_slist_append(hdrs, "Expect:");  // no 100-continue round trip: the body goes at once
        }
        if (!call.range.empty()) {
            hdrs = curl_slist_append(hdrs, ("Range: " + call.range).c_str());
        }
        if (!cred.session_token.empty()) {
            hdrs = curl_slist_append(hdrs, ("x-amz-security-token: " + cred.session_token).c_str());
        }
        hdrs = curl_slist_append(hdrs, ("Authorization: " + authz).c_str());

        Sink sink;
        sink.handle = h;
        sink.dst = call.dst;
        sink.dst_cap = call.dst_cap;
        curl_easy_reset(h);
        curl_easy_setopt(h, CURLOPT_URL, url.c_str());
        apply_tls_options(h);
        Upload upload;
        upload.data = call.body;
        upload.file = call.body_file;
        upload.offset = call.body_offset;
        upload.len = body_len;
        std::string etag;
        if (call.method == "HEAD") {
            curl_easy_setopt(h, CURLOPT_NOBODY, 1L);
        } else if (put) {
            curl_easy_setopt(h, CURLOPT_UPLOAD, 1L);
            curl_easy_setopt(h, CURLOPT_READFUNCTION, &upload_read);
            curl_easy_setopt(h, CURLOPT_READDATA, &upload);
            curl_easy_setopt(h, CURLOPT_INFILESIZE_LARGE, static_cast<curl_off_t>(body_len));
            curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, &capture_etag);
            curl_easy_setopt(h, CURLOPT_HEADERDATA, &etag);
        } else if (post) {
            curl_easy_setopt(h, CURLOPT_POST, 1L);
            curl_easy_setopt(h, CURLOPT_READFUNCTION, &upload_read);
            curl_easy_setopt(h, CURLOPT_READDATA, &upload);
            curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body_len));
        } else if (call.method == "DELETE") {
            curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, "DELETE");
        } else {
            curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
        }
        curl_easy_setopt(h, CURLOPT_HTTPHEADER, hdrs);
        curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, &sink_write);
        curl_easy_setopt(h, CURLOPT_WRITEDATA, &sink);
        curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);
        curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(h, CURLOPT_TCP_KEEPALIVE, 1L);
        curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, kConnectTimeoutSec);
        curl_easy_setopt(h, CURLOPT_LOW_SPEED_LIMIT, kLowSpeedBytes);
        curl_easy_setopt(h, CURLOPT_LOW_SPEED_TIME, kLowSpeedTimeSec);

        const CURLcode rc = curl_easy_perform(h);
        long code = 0;
        curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
        curl_off_t clen = -1;
        if (call.method == "HEAD") {
            curl_easy_getinfo(h, CURLINFO_CONTENT_LENGTH_DOWNLOAD_T, &clen);
        }
        curl_slist_free_all(hdrs);

        reply.code = fault == FaultAction::Lost ? 0 : code;
        reply.rc = fault == FaultAction::Lost ? CURLE_OPERATION_TIMEDOUT : rc;
        reply.overflow = sink.overflow;
        reply.dst_len = sink.dst_len;
        reply.content_length = static_cast<std::int64_t>(clen);
        reply.text = std::move(sink.text);
        reply.etag = std::move(etag);

        const bool http_retriable = reply.rc == CURLE_OK && (code == 429 || code == 500 || code == 502 ||
                                                       code == 503 || code == 504);  // 503 SlowDown included
        if (upload.failed) {
            reply.rc = CURLE_READ_ERROR;  // the local file, not the network: no retry would help
            return true;
        }
        const bool transport_retriable = reply.rc != CURLE_OK && !sink.overflow && is_retriable_curl(reply.rc);
        if ((http_retriable || transport_retriable) && attempt < kClientRetries) {
            sleep_backoff(attempt + 1);
            continue;
        }
        return true;
    }
}

// Message for an HTTP status that is not the expected success.
std::string http_failure(const std::string& shown, const Reply& r) {
    std::string msg = shown + ": HTTP " + std::to_string(r.code);
    const std::string xc = xml_error_code(r.text);
    if (!xc.empty()) {
        msg += " " + xc;
    }
    return msg;
}

// Message for a request that got no usable HTTP response (transfer failed or was aborted).
std::string transfer_failure(const std::string& shown, const Reply& r) {
    if (r.overflow) {
        return shown + ": response body is larger than the request asked for";
    }
    return shown + ": " + curl_error_text(r.rc);
}

}  // namespace

struct S3Client::Impl {
    s3detail::Config cfg;          // region, endpoint, path_style; creds is the env chain (null when static)
    bool has_fixed_creds = false;  // explicit ClientOptions keys
    Credentials fixed_creds;
    std::string refusal;           // non-empty: every call fails with this message (bad options, plain HTTP)
};

S3Client::S3Client(ClientOptions options) : impl_(std::make_unique<Impl>()) {
    Impl& im = *impl_;
    const bool have_ak = !options.access_key_id.empty();
    const bool have_sk = !options.secret_access_key.empty();
    const std::string profile = aws_profile();
    if (have_ak != have_sk) {
        im.refusal = "ClientOptions: access_key_id and secret_access_key must be given together";
    } else if (have_ak) {
        im.has_fixed_creds = true;
        im.fixed_creds = Credentials{options.access_key_id, options.secret_access_key, options.session_token,
                                     std::nullopt};
    } else {
        im.cfg.creds = std::make_shared<CredentialProvider>(profile);
    }

    std::string region = options.region;
    if (region.empty()) {
        region = env_or("AWS_REGION", env_or("AWS_DEFAULT_REGION", ""));
    }
    if (region.empty()) {
        Credentials ignore;
        load_profile(profile, ignore, region);
    }
    im.cfg.region = region.empty() ? "us-east-1" : region;

    im.cfg.endpoint = options.endpoint.empty() ? env_or("AWS_ENDPOINT_URL", "") : options.endpoint;
    im.cfg.path_style = !im.cfg.endpoint.empty();
    im.cfg.max_attempts = kClientRetries + 1;
    // As Lance's object store: allow_http from the options, else AWS_ALLOW_HTTP=true in the environment.
    std::string allow_env = env_or("AWS_ALLOW_HTTP", "");
    for (auto& ch : allow_env) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    const bool allow_http = options.allow_http || allow_env == "true";
    if (im.refusal.empty() && im.cfg.endpoint.rfind("http://", 0) == 0 && !allow_http) {
        im.refusal = "endpoint " + im.cfg.endpoint +
                     " is plain HTTP; set ClientOptions::allow_http (or AWS_ALLOW_HTTP=true) to allow it";
    }
}

S3Client::~S3Client() = default;
S3Client::S3Client(S3Client&&) noexcept = default;
S3Client& S3Client::operator=(S3Client&&) noexcept = default;

bool S3Client::head(const std::string& uri, std::uint64_t& size, std::string& error) {
    error.clear();
    std::string bucket;
    std::string key;
    if (!split_s3_uri(uri, true, bucket, key, error)) {
        return false;
    }
    if (!impl_->refusal.empty()) {
        error = uri + ": " + impl_->refusal;
        return false;
    }
    Call call;
    call.method = "HEAD";
    call.bucket = bucket;
    call.key = key;
    Reply r;
    if (!run_request(impl_->cfg, impl_->has_fixed_creds ? &impl_->fixed_creds : nullptr, call, r, error)) {
        return false;
    }
    if (r.overflow || r.rc != CURLE_OK) {
        error = transfer_failure(uri, r);
        return false;
    }
    if (r.code != 200) {
        error = http_failure(uri, r);
        return false;
    }
    if (r.content_length < 0) {
        error = uri + ": HEAD response has no Content-Length";
        return false;
    }
    size = static_cast<std::uint64_t>(r.content_length);
    return true;
}

bool S3Client::read_range(const std::string& uri, std::uint64_t offset, std::uint64_t n, std::uint8_t* dst,
                          std::string& error) {
    error.clear();
    std::string bucket;
    std::string key;
    if (!split_s3_uri(uri, true, bucket, key, error)) {
        return false;
    }
    if (!impl_->refusal.empty()) {
        error = uri + ": " + impl_->refusal;
        return false;
    }
    if (n == 0) {
        return true;
    }
    if (dst == nullptr) {
        error = uri + ": read_range called with a null destination";
        return false;
    }
    if (offset > UINT64_MAX - (n - 1)) {
        error = uri + ": byte range overflows 64 bits";
        return false;
    }
    const std::uint64_t last = offset + n - 1;
    Call call;
    call.method = "GET";
    call.bucket = bucket;
    call.key = key;
    call.range = "bytes=" + std::to_string(offset) + "-" + std::to_string(last);
    call.dst = dst;
    call.dst_cap = static_cast<std::size_t>(n);
    Reply r;
    if (!run_request(impl_->cfg, impl_->has_fixed_creds ? &impl_->fixed_creds : nullptr, call, r, error)) {
        return false;
    }
    if (r.overflow || r.rc != CURLE_OK) {
        error = transfer_failure(uri, r);
        return false;
    }
    if (r.code == 200) {
        error = uri + ": server ignored the Range header (HTTP 200)";
        return false;
    }
    if (r.code != 206) {
        error = http_failure(uri, r);
        return false;
    }
    if (static_cast<std::uint64_t>(r.dst_len) != n) {
        error = uri + ": short read at offset " + std::to_string(offset) + ": got " +
                std::to_string(r.dst_len) + " of " + std::to_string(n) + " bytes (object ends first)";
        return false;
    }
    return true;
}

bool S3Client::list(const std::string& prefix_uri, const std::string& delimiter, std::vector<ObjectInfo>& objects,
                    std::vector<std::string>& common_prefixes, std::string& error) {
    error.clear();
    std::vector<ObjectInfo> found;
    std::vector<std::string> prefixes;
    std::string bucket;
    std::string prefix;
    if (!split_s3_uri(prefix_uri, false, bucket, prefix, error)) {
        return false;
    }
    if (!impl_->refusal.empty()) {
        error = prefix_uri + ": " + impl_->refusal;
        return false;
    }
    std::string token;
    for (;;) {
        Call call;
        call.method = "GET";
        call.bucket = bucket;
        call.query = list_query(prefix, delimiter, token);
        Reply r;
        if (!run_request(impl_->cfg, impl_->has_fixed_creds ? &impl_->fixed_creds : nullptr, call, r, error)) {
            return false;
        }
        if (r.overflow || r.rc != CURLE_OK) {
            error = transfer_failure(prefix_uri, r);
            return false;
        }
        if (r.code != 200) {
            error = http_failure(prefix_uri, r);
            return false;
        }
        bool truncated = false;
        std::string next;
        if (!parse_list_page(r.text, found, prefixes, truncated, next, error)) {
            error = prefix_uri + ": " + error;
            return false;
        }
        if (!truncated) {
            break;
        }
        if (next == token) {
            error = prefix_uri + ": listing did not advance (repeated continuation token)";
            return false;
        }
        token = next;
    }
    objects = std::move(found);
    common_prefixes = std::move(prefixes);
    return true;
}

bool S3Client::put(const std::string& uri, const std::uint8_t* data, std::size_t size, const PutOptions& options,
                   std::string* etag, std::string& error, bool* precondition_failed) {
    error.clear();
    if (precondition_failed != nullptr) {
        *precondition_failed = false;
    }
    std::string bucket;
    std::string key;
    if (!split_s3_uri(uri, true, bucket, key, error)) {
        return false;
    }
    if (!impl_->refusal.empty()) {
        error = uri + ": " + impl_->refusal;
        return false;
    }
    if (data == nullptr && size != 0) {
        error = uri + ": put called with a null body";
        return false;
    }
    constexpr std::uint64_t kMaxSinglePut = std::uint64_t{5} << 30U;  // S3's limit for one PUT
    if (static_cast<std::uint64_t>(size) > kMaxSinglePut) {
        error = uri + ": " + std::to_string(size) + " bytes is more than one PUT may carry (5 GiB)";
        return false;
    }
    const auto clean = [](const std::string& v) { return v.find_first_of("\r\n") == std::string::npos; };
    if (!clean(options.content_type) || !clean(options.if_match)) {
        error = uri + ": put options must not contain line breaks";
        return false;
    }
    Call call;
    call.method = "PUT";
    call.bucket = bucket;
    call.key = key;
    call.body = data;
    call.body_len = size;
    call.extra_headers.push_back("Content-Type: " +
                                 (options.content_type.empty() ? std::string("application/octet-stream")
                                                               : options.content_type));
    if (options.if_none_match) {
        call.extra_headers.push_back("If-None-Match: *");
    }
    if (!options.if_match.empty()) {
        call.extra_headers.push_back("If-Match: " + options.if_match);
    }
    Reply r;
    if (!run_request(impl_->cfg, impl_->has_fixed_creds ? &impl_->fixed_creds : nullptr, call, r, error)) {
        return false;
    }
    if (r.overflow || r.rc != CURLE_OK) {
        error = transfer_failure(uri, r);
        return false;
    }
    if (r.code == 412) {
        if (precondition_failed != nullptr) {
            *precondition_failed = true;
        }
        error = http_failure(uri, r) + " (precondition failed: " +
                (options.if_none_match ? std::string("the object exists") : std::string("the ETag differs")) + ")";
        return false;
    }
    if (r.code != 200) {
        error = http_failure(uri, r);
        return false;
    }
    if (etag != nullptr) {
        *etag = r.etag;
    }
    return true;
}

}  // namespace nanos3reader

// --- Uploading files and directories -----------------------------------------------------------------

namespace nanos3reader {

namespace {

namespace fs = std::filesystem;

constexpr std::uint64_t kMiB = std::uint64_t{1} << 20U;
constexpr std::uint64_t kMinPartSize = 5 * kMiB;               // S3's minimum (all parts but the last)
constexpr std::uint64_t kMaxParts = 10000;                     // S3's maximum part count
constexpr std::uint64_t kMaxSinglePutBytes = std::uint64_t{5} << 30U;

struct FileCloser {
    void operator()(std::FILE* f) const {
        if (f != nullptr) {
            std::fclose(f);
        }
    }
};
using FilePtr = std::unique_ptr<std::FILE, FileCloser>;

FilePtr open_for_read(const fs::path& path) {
#if defined(_WIN32)
    return FilePtr(_wfopen(path.c_str(), L"rb"));
#else
    return FilePtr(std::fopen(path.c_str(), "rb"));
#endif
}

// The text between the first <tag> and its </tag>, unescaped; "" when absent.
std::string xml_tag(const std::string& body, const std::string& tag) {
    const std::string open = "<" + tag + ">";
    const std::string close = "</" + tag + ">";
    const auto b = body.find(open);
    if (b == std::string::npos) {
        return "";
    }
    const auto e = body.find(close, b + open.size());
    if (e == std::string::npos) {
        return "";
    }
    return xml_unescape(body.substr(b + open.size(), e - b - open.size()));
}

std::string xml_escape(const std::string& s) {
    std::string out;
    for (const char c : s) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default: out.push_back(c);
        }
    }
    return out;
}

// The part size for a file of `size` bytes: the requested one, at least S3's minimum, raised (to a whole
// MiB) so the file fits in 10,000 parts.
std::uint64_t part_size_for(std::uint64_t size, std::uint64_t requested) {
    std::uint64_t ps = std::max(requested, kMinPartSize);
    const std::uint64_t needed = (size + kMaxParts - 1) / kMaxParts;
    if (ps < needed) {
        ps = (needed + kMiB - 1) / kMiB * kMiB;
    }
    return ps;
}

// The outcome of one request, as an error message ("" when it is `expect`ed and the transfer worked).
std::string request_failure(const std::string& shown, const std::string& path, const Reply& r, long expect) {
    if (r.rc == CURLE_READ_ERROR) {
        return path + ": the file could not be read while uploading (did it change or shrink?)";
    }
    if (r.overflow || r.rc != CURLE_OK) {
        return transfer_failure(shown, r);
    }
    if (r.code != expect) {
        return http_failure(shown, r);
    }
    return "";
}

}  // namespace

bool S3Client::put_file(const std::string& uri, const std::string& path, const FileUploadOptions& options,
                        std::string* etag, std::string& error) {
    error.clear();
    std::string bucket;
    std::string key;
    if (!split_s3_uri(uri, true, bucket, key, error)) {
        return false;
    }
    if (!impl_->refusal.empty()) {
        error = uri + ": " + impl_->refusal;
        return false;
    }
    if (options.content_type.find_first_of("\r\n") != std::string::npos) {
        error = uri + ": the content type must not contain line breaks";
        return false;
    }
    std::error_code ec;
    if (!fs::is_regular_file(fs::path(path), ec)) {
        error = path + ": not a regular file" + (ec ? " (" + ec.message() + ")" : std::string());
        return false;
    }
    const std::uint64_t size = fs::file_size(fs::path(path), ec);
    if (ec) {
        error = path + ": " + ec.message();
        return false;
    }
    const Credentials* creds = impl_->has_fixed_creds ? &impl_->fixed_creds : nullptr;
    const std::string content_type =
        "Content-Type: " + (options.content_type.empty() ? std::string("application/octet-stream") : options.content_type);

    // One PUT.
    const std::uint64_t threshold = std::min(std::max<std::uint64_t>(options.multipart_threshold, 1), kMaxSinglePutBytes + 1);
    if (size < threshold) {
        FilePtr f = open_for_read(path);
        if (!f) {
            error = path + ": " + std::strerror(errno);
            return false;
        }
        Call call;
        call.method = "PUT";
        call.bucket = bucket;
        call.key = key;
        call.body_file = f.get();
        call.file_len = size;
        call.extra_headers.push_back(content_type);
        if (options.sign_payload && !s3v4::sha256_file_hex(f.get(), 0, size, call.payload_hash)) {
            error = path + ": the file could not be read to hash it";
            return false;
        }
        Reply r;
        if (!run_request(impl_->cfg, creds, call, r, error)) {
            return false;
        }
        error = request_failure(uri, path, r, 200);
        if (!error.empty()) {
            return false;
        }
        if (etag != nullptr) {
            *etag = r.etag;
        }
        return true;
    }

    // Multipart: create, the parts (several at a time, each retried on its own), complete; abort on failure.
    const std::uint64_t part_size = part_size_for(size, options.part_size);
    const std::uint64_t parts = (size + part_size - 1) / part_size;
    Call create;
    create.method = "POST";
    create.bucket = bucket;
    create.key = key;
    create.query = "uploads=";
    create.extra_headers.push_back(content_type);
    Reply r;
    if (!run_request(impl_->cfg, creds, create, r, error)) {
        return false;
    }
    error = request_failure(uri, path, r, 200);
    if (!error.empty()) {
        error += " (starting a multipart upload)";
        return false;
    }
    const std::string upload_id = xml_tag(r.text, "UploadId");
    if (upload_id.empty()) {
        error = uri + ": the multipart upload was started without an UploadId";
        return false;
    }
    const std::string id_query = "uploadId=" + uri_encode_component(upload_id);
    const auto abort_upload = [&]() {
        Call abort;
        abort.method = "DELETE";
        abort.bucket = bucket;
        abort.key = key;
        abort.query = id_query;
        Reply ignored;
        std::string ignored_error;
        run_request(impl_->cfg, creds, abort, ignored, ignored_error);  // best effort
    };

    std::vector<std::string> part_etags(static_cast<std::size_t>(parts));
    std::atomic<std::uint64_t> next{0};
    std::atomic<bool> failed{false};
    std::mutex error_mutex;
    std::string first_error;
    const auto fail_with = [&](const std::string& message) {
        std::lock_guard<std::mutex> lock(error_mutex);
        if (first_error.empty()) {
            first_error = message;
        }
        failed = true;
    };
    const auto worker = [&]() {
        FilePtr f = open_for_read(path);
        if (!f) {
            fail_with(path + ": " + std::strerror(errno));
            return;
        }
        for (;;) {
            const std::uint64_t i = next++;
            if (i >= parts || failed) {
                return;
            }
            const std::uint64_t offset = i * part_size;
            Call call;
            call.method = "PUT";
            call.bucket = bucket;
            call.key = key;
            call.query = "partNumber=" + std::to_string(i + 1) + "&" + id_query;  // sorted, as SigV4 wants
            call.body_file = f.get();
            call.body_offset = offset;
            call.file_len = std::min(part_size, size - offset);
            if (options.sign_payload &&
                !s3v4::sha256_file_hex(f.get(), offset, call.file_len, call.payload_hash)) {
                fail_with(path + ": the file could not be read to hash it");
                return;
            }
            Reply pr;
            std::string perr;
            if (!run_request(impl_->cfg, creds, call, pr, perr)) {
                fail_with(perr);
                return;
            }
            perr = request_failure(uri, path, pr, 200);
            if (perr.empty() && pr.etag.empty()) {
                perr = uri + ": part " + std::to_string(i + 1) + " was accepted without an ETag";
            }
            if (!perr.empty()) {
                fail_with(perr + " (part " + std::to_string(i + 1) + " of " + std::to_string(parts) + ")");
                return;
            }
            part_etags[static_cast<std::size_t>(i)] = pr.etag;
        }
    };
    const auto threads = static_cast<std::size_t>(
        std::min<std::uint64_t>(std::max(options.part_concurrency, 1U), parts));
    std::vector<std::thread> pool;
    pool.reserve(threads - 1);
    for (std::size_t t = 1; t < threads; ++t) {
        pool.emplace_back(worker);
    }
    worker();
    for (auto& t : pool) {
        t.join();
    }
    if (failed) {
        abort_upload();
        error = first_error;
        return false;
    }

    std::string xml = "<CompleteMultipartUpload xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">";
    for (std::uint64_t i = 0; i < parts; ++i) {
        xml += "<Part><PartNumber>" + std::to_string(i + 1) + "</PartNumber><ETag>" +
               xml_escape(part_etags[static_cast<std::size_t>(i)]) + "</ETag></Part>";
    }
    xml += "</CompleteMultipartUpload>";
    Call complete;
    complete.method = "POST";
    complete.bucket = bucket;
    complete.key = key;
    complete.query = id_query;
    complete.body = reinterpret_cast<const std::uint8_t*>(xml.data());
    complete.body_len = xml.size();
    complete.extra_headers.push_back("Content-Type: application/xml");
    Reply cr;
    if (!run_request(impl_->cfg, creds, complete, cr, error)) {
        abort_upload();
        return false;
    }
    error = request_failure(uri, path, cr, 200);
    // S3 can answer 200 and still fail the completion, with an <Error> body.
    if (error.empty() && cr.text.find("<Error>") != std::string::npos) {
        error = uri + ": completing the multipart upload failed: " + xml_tag(cr.text, "Code") + " " +
                xml_tag(cr.text, "Message");
    }
    if (!error.empty()) {
        abort_upload();
        return false;
    }
    if (etag != nullptr) {
        *etag = xml_tag(cr.text, "ETag");
    }
    return true;
}

bool S3Client::put_directory(const std::string& dir, const std::string& prefix_uri,
                             const DirectoryUploadOptions& options,
                             const std::function<void(const FileUploadResult&)>& on_file,
                             DirectoryUploadStats& stats, std::string& error) {
    error.clear();
    stats = DirectoryUploadStats{};
    const auto started = std::chrono::steady_clock::now();
    std::string bucket;
    std::string prefix;
    if (!split_s3_uri(prefix_uri, false, bucket, prefix, error)) {
        return false;
    }
    std::string base = "s3://" + bucket + "/" + prefix;
    if (!prefix.empty() && prefix.back() != '/') {
        base += "/";
    }
    const fs::path root(dir);
    std::error_code ec;
    if (!fs::is_directory(root, ec)) {
        error = dir + ": not a directory" + (ec ? " (" + ec.message() + ")" : std::string());
        return false;
    }

    // Every regular file, with its size: a directory that cannot be read fails the upload (its files would
    // be missing from the results otherwise).
    struct Item {
        fs::path path;
        std::string uri;
        std::uint64_t size = 0;
    };
    std::vector<Item> items;
    fs::recursive_directory_iterator it(root, ec);
    if (ec) {
        error = dir + ": " + ec.message();
        return false;
    }
    for (const fs::recursive_directory_iterator end; it != end; it.increment(ec)) {
        if (ec) {
            error = dir + ": " + ec.message();
            return false;
        }
        std::error_code fec;
        if (!it->is_regular_file(fec)) {  // follows a symlink to a file; directories and specials skipped
            continue;
        }
        Item item;
        item.path = it->path();
        item.size = it->file_size(fec);
        if (fec) {
            error = item.path.string() + ": " + fec.message();
            return false;
        }
        item.uri = base + item.path.lexically_relative(root).generic_string();
        items.push_back(std::move(item));
    }
    if (ec) {
        error = dir + ": " + ec.message();
        return false;
    }
    // Largest first, so a big file does not start last and set the finishing time alone.
    std::stable_sort(items.begin(), items.end(), [](const Item& a, const Item& b) { return a.size > b.size; });

    std::atomic<std::size_t> next{0};
    std::mutex report_mutex;
    std::string first_error;
    const auto worker = [&]() {
        for (;;) {
            const std::size_t i = next++;
            if (i >= items.size()) {
                return;
            }
            const Item& item = items[i];
            FileUploadResult result;
            result.path = item.path.string();
            result.uri = item.uri;
            result.bytes = item.size;
            const auto t0 = std::chrono::steady_clock::now();
            result.ok = put_file(item.uri, result.path, options.file, nullptr, result.error);
            result.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
            std::lock_guard<std::mutex> lock(report_mutex);
            if (result.ok) {
                ++stats.files;
                stats.bytes += result.bytes;
            } else {
                ++stats.failed;
                if (first_error.empty()) {
                    first_error = result.error;
                }
            }
            if (on_file) {
                on_file(result);
            }
        }
    };
    const auto threads = std::min<std::size_t>(std::max(options.concurrency, 1U), std::max<std::size_t>(items.size(), 1));
    std::vector<std::thread> pool;
    pool.reserve(threads - 1);
    for (std::size_t t = 1; t < threads; ++t) {
        pool.emplace_back(worker);
    }
    worker();
    for (auto& t : pool) {
        t.join();
    }
    stats.seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
    if (stats.failed != 0) {
        error = std::to_string(stats.failed) + " of " + std::to_string(items.size()) +
                " file(s) failed; first: " + first_error;
        return false;
    }
    return true;
}

}  // namespace nanos3reader

namespace nanos3reader {

std::string tls_ca_source() { return ca_config().source; }

}  // namespace nanos3reader
