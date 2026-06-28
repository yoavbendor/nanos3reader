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
#include <openssl/sha.h>
#endif

namespace nanos3reader {
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
    unsigned char digest[32];
    sha256_raw(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), digest);
    return hex_encode(digest, sizeof digest);
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
                fail(std::string("S3 GET transport error: ") + curl_easy_strerror(rc));
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

}  // namespace nanos3reader
