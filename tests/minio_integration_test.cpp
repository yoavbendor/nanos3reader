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
//
// When the required variables are unset the test exits 77, which CMake maps to "skipped" — so a plain
// `ctest` on a developer box with no MinIO doesn't report a failure.

#include "nanos3reader/s3_reader.h"

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

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

}  // namespace

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

    if (failures != 0) {
        std::cerr << failures << " integration check(s) failed\n";
        return 1;
    }
    std::cout << "MinIO integration OK\n";
    return 0;
}
