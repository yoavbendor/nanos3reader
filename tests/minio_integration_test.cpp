// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// End-to-end test of the actual reading path against a live S3-compatible store (MinIO in CI). The SigV4
// unit test covers signing in isolation; this exercises everything the unit test can't: path-style
// addressing via AWS_ENDPOINT_URL, real range GETs, read-ahead window refetches, seeking (within and
// across windows), EOF, and error reporting on a missing key.
//
// It is data-driven so it stays in lockstep with whatever CI uploads — no content is hard-coded here:
//
//   NANOS3READER_IT_URI      (required) s3://bucket/key of an object CI has uploaded
//   NANOS3READER_IT_EXPECT   (required) path to a local file holding byte-identical content
//   NANOS3READER_IT_MISSING  (optional) s3://bucket/key that does NOT exist (negative test)
//   NANOS3READER_IT_LISTING  (required) s3://bucket/prefix/ seeded with 1,101 objects (see client_checks)
//   NANOS3READER_IT_PUT_PREFIX (required) s3://bucket/prefix/ the test may write under (see put_checks)
//
// When the required variables are unset the test exits 77, which CMake maps to "skipped" — so a plain
// `ctest` on a developer box with no MinIO doesn't report a failure.

#include "nanos3reader/s3_reader.h"

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

namespace {

constexpr int kSkip = 77;  // CMake SKIP_RETURN_CODE

int failures = 0;

void fail(const std::string& what) {
    std::cerr << "FAIL " << what << '\n';
    ++failures;
}

const char* env(const char* name) {
    const char* v = std::getenv(name);
    return (v != nullptr && v[0] != '\0') ? v : nullptr;
}

std::string read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// Read `len` bytes starting at `offset` from a freshly opened stream and return them.
std::string read_range(nanos3reader::S3MinStreamFactory& factory, const std::string& uri,
                       std::size_t read_ahead, std::uint64_t offset, std::size_t len) {
    auto s = factory.open(uri, read_ahead);
    if (!s) {
        fail("open(" + uri + ") returned null: " + factory.error());
        return {};
    }
    s->seekg(static_cast<std::streamoff>(offset));
    std::string out(len, '\0');
    s->read(out.data(), static_cast<std::streamsize>(len));
    out.resize(static_cast<std::size_t>(s->gcount()));
    return out;
}

// --- S3Client checks ----------------------------------------------------------------------------------
//
// The listing prefix is seeded by CI (and by hand for a local run) with kListingCount objects
// "<prefix>f00000.bin" .. "<prefix>f01099.bin", object i holding listing_size(i) bytes, plus
// "<prefix>sub/one.bin" of kSubSize bytes. 1,101 keys is more than one ListObjectsV2 page of 1,000.

constexpr int kListingCount = 1100;
constexpr std::uint64_t kSubSize = 3;

std::string listing_name(int i) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "f%05d.bin", i);
    return buf;
}

std::uint64_t listing_size(int i) { return 1 + static_cast<std::uint64_t>(i % 13); }

// Compares a listing with the expected key -> size map (exact set, exact sizes).
void expect_listing(const char* what, const std::vector<nanos3reader::ObjectInfo>& got,
                    const std::map<std::string, std::uint64_t>& want) {
    std::map<std::string, std::uint64_t> have;
    for (const auto& o : got) have[o.key] = o.size;
    if (got.size() != want.size() || have != want) {
        fail(std::string(what) + ": got " + std::to_string(got.size()) + " objects, want " +
             std::to_string(want.size()) + (have == want ? "" : " (keys or sizes differ)"));
    }
}

void client_checks(const std::string& uri, const std::string& expected, const std::string& listing) {
    using nanos3reader::ClientOptions;
    using nanos3reader::ObjectInfo;
    using nanos3reader::S3Client;

    // Listings return bucket-relative keys, so expected keys use the prefix without "s3://bucket/".
    const std::string key_prefix = listing.substr(listing.find('/', 5) + 1);
    const std::uint64_t n = expected.size();
    if (n < 8192) {
        fail("client checks need an object of at least 8 KiB");
        return;
    }
    // Plain-HTTP endpoints (CI and moto) need allow_http; an explicit endpoint is otherwise refused.
    ClientOptions http_ok;
    http_ok.allow_http = true;
    S3Client client(http_ok);  // environment chain, like the stream factory
    std::string err;
    std::uint64_t size = 0;

    // HEAD: size of the object; a missing key is a 404 that names the URI.
    if (!client.head(uri, size, err)) {
        fail("head: " + err);
    } else if (size != n) {
        fail("head size " + std::to_string(size) + " != " + std::to_string(n));
    }
    if (client.head(listing + "missing.bin", size, err)) {
        fail("head of a missing key succeeded");
    } else if (err.find("404") == std::string::npos || err.find(listing + "missing.bin") == std::string::npos) {
        fail("head of a missing key: unexpected error: " + err);
    }

    // Range GETs: start, unaligned middle, up to EOF, and the whole object in one request.
    struct Case { std::uint64_t off; std::uint64_t len; };
    const Case cases[] = {{0, 100}, {n / 3 + 7, 5000}, {n - 4096, 4096}, {0, n}};
    for (const Case& c : cases) {
        std::string buf(static_cast<std::size_t>(c.len), '\0');
        if (!client.read_range(uri, c.off, c.len, reinterpret_cast<std::uint8_t*>(buf.data()), err)) {
            fail("read_range(" + std::to_string(c.off) + ", " + std::to_string(c.len) + "): " + err);
        } else if (buf != expected.substr(static_cast<std::size_t>(c.off), static_cast<std::size_t>(c.len))) {
            fail("read_range mismatch at offset " + std::to_string(c.off) + " len " + std::to_string(c.len));
        }
    }

    // Short read: the range runs past EOF, so the body is 10 bytes instead of 100.
    {
        std::string buf(100, '\0');
        if (client.read_range(uri, n - 10, 100, reinterpret_cast<std::uint8_t*>(buf.data()), err)) {
            fail("short read succeeded");
        } else if (err.find("short read") == std::string::npos) {
            fail("short read: unexpected error: " + err);
        }
    }
    // Entirely past EOF: S3 answers 416, which is a 4xx and is reported, not retried.
    {
        char b[1];
        if (client.read_range(uri, n, 1, reinterpret_cast<std::uint8_t*>(b), err)) {
            fail("read past EOF succeeded");
        } else if (err.find("416") == std::string::npos) {
            fail("read past EOF: unexpected error: " + err);
        }
    }
    if (!client.read_range(uri, 5, 0, nullptr, err)) fail("zero-length read: " + err);

    // ListObjectsV2 without a delimiter: every key under the prefix, across two pages.
    std::vector<ObjectInfo> objects;
    std::vector<std::string> prefixes;
    {
        std::map<std::string, std::uint64_t> want;
        for (int i = 0; i < kListingCount; ++i) want[key_prefix + listing_name(i)] = listing_size(i);
        want[key_prefix + "sub/one.bin"] = kSubSize;
        if (!client.list(listing, "", objects, prefixes, err)) {
            fail("list (no delimiter): " + err);
        } else {
            expect_listing("list (no delimiter)", objects, want);
            if (!prefixes.empty()) fail("list (no delimiter) returned common prefixes");
        }
    }
    // With "/": immediate children only, the sub-directory as a common prefix.
    {
        std::map<std::string, std::uint64_t> want;
        for (int i = 0; i < kListingCount; ++i) want[key_prefix + listing_name(i)] = listing_size(i);
        if (!client.list(listing, "/", objects, prefixes, err)) {
            fail("list (delimiter /): " + err);
        } else {
            expect_listing("list (delimiter /)", objects, want);
            if (prefixes != std::vector<std::string>{key_prefix + "sub/"}) fail("list (delimiter /) common prefixes wrong");
        }
    }
    // A prefix with nothing under it lists empty and succeeds.
    if (!client.list(listing + "no-such-dir/", "/", objects, prefixes, err) || !objects.empty() || !prefixes.empty()) {
        fail("empty listing: " + err);
    }

    // Explicit ClientOptions keys (from the environment) take the static-credential path.
    {
        ClientOptions o;
        o.allow_http = true;
        const char* ak = env("AWS_ACCESS_KEY_ID");
        const char* sk = env("AWS_SECRET_ACCESS_KEY");
        if (ak == nullptr || sk == nullptr) {
            fail("explicit-options check needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
        } else {
            o.access_key_id = ak;
            o.secret_access_key = sk;
            if (const char* t = env("AWS_SESSION_TOKEN")) o.session_token = t;
            if (const char* r = env("AWS_REGION")) o.region = r;
            if (const char* ep = env("AWS_ENDPOINT_URL")) o.endpoint = ep;
            S3Client explicit_client(o);
            std::uint64_t s2 = 0;
            if (!explicit_client.head(uri, s2, err) || s2 != n) fail("explicit-options head: " + err);
        }
    }

    // Refusals that need no network: plain HTTP without allow_http, and half-given keys.
    {
        // AWS_ALLOW_HTTP=true in the environment also allows it (as Lance's object store): clear it for the
        // refusal, then set it and check the endpoint is no longer refused for being plain HTTP.
        const char* saved = std::getenv("AWS_ALLOW_HTTP");
        const std::string saved_value = saved != nullptr ? saved : "";
        unsetenv("AWS_ALLOW_HTTP");
        ClientOptions o;
        o.endpoint = "http://127.0.0.1:9";
        {
            S3Client c(o);
            if (c.head(uri, size, err)) {
                fail("plain-HTTP endpoint accepted without allow_http");
            } else if (err.find("allow_http") == std::string::npos) {
                fail("plain-HTTP refusal: unexpected error: " + err);
            }
        }
        setenv("AWS_ALLOW_HTTP", "TRUE", 1);
        {
            S3Client c(o);
            if (!c.head(uri, size, err) && err.find("allow_http") != std::string::npos) {
                fail("AWS_ALLOW_HTTP=true did not allow a plain-HTTP endpoint: " + err);
            }
        }
        if (saved != nullptr) {
            setenv("AWS_ALLOW_HTTP", saved_value.c_str(), 1);
        } else {
            unsetenv("AWS_ALLOW_HTTP");
        }
    }
    {
        ClientOptions o;
        o.access_key_id = "only-a-key-id";
        S3Client c(o);
        if (c.head(uri, size, err)) {
            fail("access_key_id without secret_access_key accepted");
        } else if (err.find("must be given together") == std::string::npos) {
            fail("half-given keys: unexpected error: " + err);
        }
    }

    // One client shared by eight threads, each doing 40 reads at scattered offsets.
    {
        const std::size_t len = 512;
        std::atomic<int> bad{0};
        std::vector<std::thread> threads;
        for (int t = 0; t < 8; ++t) {
            threads.emplace_back([&, t] {
                for (int k = 0; k < 40; ++k) {
                    const std::uint64_t off = (static_cast<std::uint64_t>(t) * 7919u + static_cast<std::uint64_t>(k) * 104729u) % (n - len);
                    std::string buf(len, '\0');
                    std::string e;
                    if (!client.read_range(uri, off, len, reinterpret_cast<std::uint8_t*>(buf.data()), e) ||
                        buf != expected.substr(static_cast<std::size_t>(off), len)) {
                        ++bad;
                    }
                }
            });
        }
        for (auto& th : threads) th.join();
        if (bad != 0) fail("concurrent reads: " + std::to_string(bad.load()) + " of 320 failed or mismatched");
    }
}

}  // namespace

// S3Client::put: whole objects written and read back, overwrites, the empty object, the conditional forms
// (If-None-Match: *, If-Match: <etag>) and their precondition failures, and errors for a missing bucket.
void put_checks(const std::string& prefix) {
    using nanos3reader::ClientOptions;
    using nanos3reader::PutOptions;
    using nanos3reader::S3Client;

    ClientOptions http_ok;
    http_ok.allow_http = true;
    S3Client client(http_ok);
    std::string err;
    const std::string run = std::to_string(static_cast<unsigned long long>(::getpid())) + "-" +
                            std::to_string(static_cast<unsigned long long>(std::time(nullptr)));
    const auto bytes = [](std::size_t n, unsigned seed) {
        std::vector<std::uint8_t> v(n);
        for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::uint8_t>((i * 131U + seed * 7U) ^ (i >> 5U));
        return v;
    };
    const auto read_back = [&](const std::string& uri, std::vector<std::uint8_t>& out) {
        std::uint64_t size = 0;
        if (!client.head(uri, size, err)) return false;
        out.assign(static_cast<std::size_t>(size), 0);
        return size == 0 || client.read_range(uri, 0, size, out.data(), err);
    };

    // A ~3 MiB object (one request), read back byte for byte, with its ETag.
    const std::string big = prefix + "put-" + run + "/big.bin";
    const auto body = bytes(3U << 20U, 1);
    std::string etag;
    if (!client.put(big, body.data(), body.size(), PutOptions{}, &etag, err)) {
        fail("put of a 3 MiB object: " + err);
        return;
    }
    if (etag.size() < 2 || etag.front() != '"') fail("put returned no quoted ETag: '" + etag + "'");
    std::vector<std::uint8_t> got;
    if (!read_back(big, got) || got != body) fail("3 MiB object read back differs: " + err);

    // Overwrite with other content; the new bytes are read.
    const auto body2 = bytes(1000, 2);
    std::string etag2;
    if (!client.put(big, body2.data(), body2.size(), PutOptions{}, &etag2, err)) fail("overwrite: " + err);
    if (!read_back(big, got) || got != body2) fail("overwritten object reads its old content: " + err);
    if (etag2 == etag) fail("an overwrite kept the old ETag");

    // The empty object.
    const std::string empty = prefix + "put-" + run + "/empty.bin";
    if (!client.put(empty, nullptr, 0, PutOptions{}, nullptr, err)) fail("put of an empty object: " + err);
    std::uint64_t size = 1;
    if (!client.head(empty, size, err) || size != 0) fail("empty object HEAD: " + err);

    // If-None-Match: * creates once, then fails its precondition.
    const std::string once = prefix + "put-" + run + "/once.json";
    PutOptions create;
    create.if_none_match = true;
    create.content_type = "application/json";
    const std::string v1 = "{\"version\": 1}";
    const std::string v2 = "{\"version\": 2}";
    bool pre = true;
    std::string once_etag;
    if (!client.put(once, reinterpret_cast<const std::uint8_t*>(v1.data()), v1.size(), create, &once_etag, err,
                    &pre) || pre) {
        fail("conditional create of a new key: " + err);
    }
    if (client.put(once, reinterpret_cast<const std::uint8_t*>(v2.data()), v2.size(), create, nullptr, err, &pre)) {
        fail("conditional create overwrote an existing key");
    } else if (!pre) {
        fail("conditional create on an existing key did not report a failed precondition: " + err);
    }
    if (!read_back(once, got) || std::string(got.begin(), got.end()) != v1) fail("the first create was replaced");

    // If-Match: a wrong ETag fails; the current one replaces.
    PutOptions swap;
    swap.if_match = "\"00000000000000000000000000000000\"";
    if (client.put(once, reinterpret_cast<const std::uint8_t*>(v2.data()), v2.size(), swap, nullptr, err, &pre)) {
        fail("If-Match with a wrong ETag replaced the object");
    } else if (!pre) {
        fail("If-Match with a wrong ETag did not report a failed precondition: " + err);
    }
    swap.if_match = once_etag;
    if (!client.put(once, reinterpret_cast<const std::uint8_t*>(v2.data()), v2.size(), swap, nullptr, err, &pre)) {
        fail("If-Match with the current ETag: " + err);
    }
    if (!read_back(once, got) || std::string(got.begin(), got.end()) != v2) fail("If-Match did not replace");

    // Errors: a bucket that does not exist names the object and the status; a bad URI fails before any request.
    const std::string bucket_end = prefix.substr(5, prefix.find('/', 5) - 5);
    const std::string missing = "s3://" + bucket_end + "-no-such-bucket-" + run + "/x.bin";
    if (client.put(missing, body2.data(), body2.size(), PutOptions{}, nullptr, err)) {
        fail("put into a missing bucket succeeded");
    } else if (err.find(missing) == std::string::npos || err.find("HTTP 404") == std::string::npos) {
        fail("missing-bucket error lacks the URI or status: " + err);
    }
    if (client.put("not-a-uri", body2.data(), body2.size(), PutOptions{}, nullptr, err)) fail("put of a bad URI");
}

// S3Client::put_file / put_directory: a small file (one PUT), a multipart file (three parts, the last short),
// signed and unsigned payloads, and a directory tree mapped to <prefix>/<relative path> -- every key and
// byte checked by reading it back -- plus the errors for a missing file and a missing directory.
void file_upload_checks(const std::string& prefix) {
    using nanos3reader::ClientOptions;
    using nanos3reader::DirectoryUploadOptions;
    using nanos3reader::DirectoryUploadStats;
    using nanos3reader::FileUploadOptions;
    using nanos3reader::FileUploadResult;
    using nanos3reader::S3Client;
    namespace fs = std::filesystem;

    ClientOptions http_ok;
    http_ok.allow_http = true;
    S3Client client(http_ok);
    std::string err;
    const std::string run = std::to_string(static_cast<unsigned long long>(::getpid())) + "-" +
                            std::to_string(static_cast<unsigned long long>(std::time(nullptr)));
    const fs::path root = fs::temp_directory_path() / ("nanos3reader-upload-" + run);
    std::error_code ec;
    fs::create_directories(root / "tree" / "sub dir" / "deeper", ec);
    const auto write = [](const fs::path& p, std::size_t n, unsigned seed) {
        std::string data(n, '\0');
        for (std::size_t i = 0; i < n; ++i) data[i] = static_cast<char>((i * 2654435761U + seed) >> 7U);
        std::ofstream(p, std::ios::binary) << data;
        return data;
    };
    const auto read_back = [&](const std::string& uri, std::string& out) {
        std::uint64_t size = 0;
        if (!client.head(uri, size, err)) return false;
        out.assign(static_cast<std::size_t>(size), '\0');
        return size == 0 || client.read_range(uri, 0, size, reinterpret_cast<std::uint8_t*>(out.data()), err);
    };

    // One file, one PUT and as a multipart upload (5 MiB parts, 13 MiB file: parts of 5, 5 and 3 MiB).
    const std::string big = write(root / "big.bin", 13U << 20U, 3);
    for (const bool sign : {false, true}) {
        FileUploadOptions single;
        single.sign_payload = sign;
        FileUploadOptions multi = single;
        multi.multipart_threshold = 5U << 20U;
        multi.part_size = 5U << 20U;
        multi.part_concurrency = 2;
        for (const auto* o : {&single, &multi}) {
            const std::string uri = prefix + "files-" + run + "/" + (o == &single ? "one" : "multi") +
                                    (sign ? "-signed" : "") + ".bin";
            std::string etag;
            std::string got;
            if (!client.put_file(uri, (root / "big.bin").string(), *o, &etag, err)) {
                fail("put_file " + uri + ": " + err);
            } else if (!read_back(uri, got) || got != big) {
                fail("put_file " + uri + " reads back different bytes: " + err);
            } else if (o == &multi && etag.find("-3") == std::string::npos) {
                fail("multipart put_file did not go up in 3 parts (ETag " + etag + ")");
            }
        }
    }

    // A tree: nested directories, names that need escaping, an empty file.
    std::map<std::string, std::string> files;
    files["top.txt"] = write(root / "tree" / "top.txt", 1000, 1);
    files["empty.bin"] = write(root / "tree" / "empty.bin", 0, 2);
    files["sub dir/a+b=c.bin"] = write(root / "tree" / "sub dir" / "a+b=c.bin", 70000, 4);
    files["sub dir/deeper/x%20y #1.dat"] = write(root / "tree" / "sub dir" / "deeper" / "x%20y #1.dat", 12345, 5);
    files["sub dir/deeper/large.bin"] = write(root / "tree" / "sub dir" / "deeper" / "large.bin", 11U << 20U, 6);
    DirectoryUploadOptions dopts;
    dopts.concurrency = 3;
    dopts.file.multipart_threshold = 5U << 20U;
    dopts.file.part_size = 5U << 20U;
    DirectoryUploadStats stats;
    std::size_t reported = 0;
    const std::string tree = prefix + "tree-" + run;  // no trailing '/': put_directory adds one
    if (!client.put_directory((root / "tree").string(), tree, dopts,
                              [&](const FileUploadResult& r) {
                                  ++reported;
                                  if (!r.ok) fail("put_directory: " + r.path + ": " + r.error);
                              },
                              stats, err)) {
        fail("put_directory: " + err);
    }
    if (reported != files.size() || stats.files != files.size() || stats.failed != 0) {
        fail("put_directory reported " + std::to_string(reported) + " files, uploaded " +
             std::to_string(stats.files) + ", want " + std::to_string(files.size()));
    }
    std::vector<nanos3reader::ObjectInfo> listed;
    std::vector<std::string> common;
    if (!client.list(tree + "/", "", listed, common, err) || listed.size() != files.size()) {
        fail("put_directory: listing has " + std::to_string(listed.size()) + " objects: " + err);
    }
    for (const auto& [rel, data] : files) {
        std::string got;
        if (!read_back(tree + "/" + rel, got) || got != data) fail("put_directory: " + rel + " differs: " + err);
    }

    // Errors.
    if (client.put_file(prefix + "x", (root / "missing.bin").string(), FileUploadOptions{}, nullptr, err)) {
        fail("put_file of a missing file succeeded");
    }
    if (client.put_directory((root / "missing").string(), tree, dopts, nullptr, stats, err)) {
        fail("put_directory of a missing directory succeeded");
    }
    fs::remove_all(root, ec);
}

int main() {
    const char* uri_c = env("NANOS3READER_IT_URI");
    const char* expect_c = env("NANOS3READER_IT_EXPECT");
    if (uri_c == nullptr || expect_c == nullptr) {
        std::cerr << "skipping: set NANOS3READER_IT_URI and NANOS3READER_IT_EXPECT to run\n";
        return kSkip;
    }
    const std::string uri = uri_c;
    const std::string expected = read_file(expect_c);
    if (expected.empty()) {
        fail(std::string("expected file is empty or unreadable: ") + expect_c);
        return 1;
    }
    std::cerr << "integration test: " << uri << " (" << expected.size() << " bytes)\n";

    nanos3reader::S3MinStreamFactory factory;

    // 1. Full sequential read. A deliberately small read-ahead forces many window refetches over the object,
    //    exercising the underflow/keep-alive refetch path rather than a single GET.
    {
        const std::size_t read_ahead = 4096;
        auto s = factory.open(uri, read_ahead);
        if (!s) {
            fail("open for full read returned null: " + factory.error());
        } else {
            std::ostringstream got;
            got << s->rdbuf();
            if (got.str() != expected) {
                fail("full sequential read mismatch (got " + std::to_string(got.str().size()) +
                     " bytes, want " + std::to_string(expected.size()) + ")");
            }
        }
    }

    // 2. Seeks to assorted offsets, each reading a slice that spans several read-ahead windows. Covers
    //    start, an unaligned middle, and a range that runs right up to the end of the object.
    {
        const std::size_t read_ahead = 1024;
        const std::size_t n = expected.size();
        struct Case { std::uint64_t off; std::size_t len; };
        const Case cases[] = {
            {0, 100},
            {n / 3 + 7, 5000},
            {n > 4096 ? n - 4096 : 0, 4096},  // up to EOF
        };
        for (const Case& c : cases) {
            const std::string got = read_range(factory, uri, read_ahead, c.off, c.len);
            const std::string want = expected.substr(c.off, c.len);
            if (got != want) {
                fail("range read mismatch at offset " + std::to_string(c.off) + " len " +
                     std::to_string(c.len) + " (got " + std::to_string(got.size()) + " bytes)");
            }
        }
    }

    // 3. Two seeks/reads on one stream, the second landing inside the window the first already fetched
    //    (no extra GET). Also checks tellg() tracks the logical position.
    {
        auto s = factory.open(uri, 1 << 16);
        if (!s) {
            fail("open for in-window seek returned null: " + factory.error());
        } else if (expected.size() >= 200) {
            char buf[64];
            s->seekg(10);
            s->read(buf, 50);
            if (std::string(buf, 50) != expected.substr(10, 50)) fail("in-window read #1 mismatch");
            if (s->tellg() != std::streampos(60)) fail("tellg after read #1 != 60");
            s->seekg(100);  // same 64 KiB window — must not error
            s->read(buf, 50);
            if (std::string(buf, 50) != expected.substr(100, 50)) fail("in-window read #2 mismatch");
        }
    }

    // 4. Reading to the exact end sets eof and never overruns.
    {
        auto s = factory.open(uri, 8192);
        if (!s) {
            fail("open for EOF check returned null: " + factory.error());
        } else {
            s->seekg(0);
            std::string buf(expected.size() + 16, '\0');
            s->read(buf.data(), static_cast<std::streamsize>(buf.size()));
            if (static_cast<std::size_t>(s->gcount()) != expected.size()) {
                fail("EOF read count " + std::to_string(s->gcount()) + " != object size " +
                     std::to_string(expected.size()));
            }
            if (!s->eof()) fail("eof() not set after reading past end");
        }
    }

    // 5. Negative path: a missing key. open() succeeds (no GET yet); the first read fails and surfaces an
    //    error via the failbit/eof with no bytes delivered.
    if (const char* missing = env("NANOS3READER_IT_MISSING")) {
        auto s = factory.open(missing, 4096);
        if (!s) {
            // Acceptable: some configs may fail at open. Just make sure it's reported.
            if (factory.error().empty()) fail("missing-key open returned null without an error message");
        } else {
            char buf[16];
            s->read(buf, sizeof buf);
            if (s->gcount() != 0) fail("read of missing key returned data");
            if (s->good()) fail("stream still good() after reading a missing key");
        }
    }

    // 6. Disk LRU block cache: the first full read is all misses (and populates the cache on disk); a
    //    second full read of the same object is served from disk (hits increase) and returns identical
    //    bytes. The read-ahead is small enough that the object spans several blocks.
    {
        const std::filesystem::path cache_dir =
            std::filesystem::temp_directory_path() / ("nanos3reader-it-cache-" + std::to_string(::getpid()));
        std::error_code ec;
        std::filesystem::remove_all(cache_dir, ec);  // start clean even if a prior run left files
        if (!nanos3reader::configure_disk_cache(cache_dir.string(), 100)) {
            fail("configure_disk_cache failed for " + cache_dir.string());
        } else {
            const std::size_t read_ahead = 64 * 1024;

            std::uint64_t h0 = 0, m0 = 0;
            nanos3reader::disk_cache_stats(&h0, &m0);
            {
                auto s = factory.open(uri, read_ahead);
                std::ostringstream got;
                if (s) got << s->rdbuf();
                if (!s || got.str() != expected) fail("cached read #1 (cold) mismatch");
            }
            std::uint64_t h1 = 0, m1 = 0;
            nanos3reader::disk_cache_stats(&h1, &m1);
            if (m1 <= m0) fail("expected cache misses on the cold read");

            {
                auto s = factory.open(uri, read_ahead);
                std::ostringstream got;
                if (s) got << s->rdbuf();
                if (!s || got.str() != expected) fail("cached read #2 (warm) mismatch");
            }
            std::uint64_t h2 = 0, m2 = 0;
            nanos3reader::disk_cache_stats(&h2, &m2);
            if (h2 <= h1) fail("expected cache hits on the warm read");

            // Disable the cache again so it doesn't leak into any later additions to this test.
            nanos3reader::configure_disk_cache("", 0);
            std::filesystem::remove_all(cache_dir, ec);
        }
    }

    // 7. S3Client: HEAD, range GETs, ListObjectsV2 (paging, delimiter), error reporting, threads. The
    //    listing prefix must be seeded (see the layout above client_checks); a missing variable is a failure.
    if (const char* listing = env("NANOS3READER_IT_LISTING")) {
        client_checks(uri, expected, listing);
    } else {
        fail("NANOS3READER_IT_LISTING must name the seeded listing prefix (s3://bucket/listing/)");
    }

    // 8. S3Client::put, put_file and put_directory under a writable prefix.
    if (const char* put_prefix = env("NANOS3READER_IT_PUT_PREFIX")) {
        put_checks(put_prefix);
        file_upload_checks(put_prefix);
    } else {
        fail("NANOS3READER_IT_PUT_PREFIX must name a prefix the test may write under (s3://bucket/put/)");
    }

    if (failures != 0) {
        std::cerr << failures << " integration check(s) failed\n";
        return 1;
    }
    std::cout << "MinIO integration OK\n";
    return 0;
}
