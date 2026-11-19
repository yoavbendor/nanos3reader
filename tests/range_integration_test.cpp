// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// End-to-end test of the S3 range source and spilling writer (s3_range.h) against a live S3-compatible store (moto
// in CI). Data-driven, like minio_integration_test.cpp:
//
//   NANOS3READER_IT_URI        (required) s3://bucket/key of an object CI uploaded
//   NANOS3READER_IT_EXPECT     (required) local file with byte-identical content
//   NANOS3READER_IT_PUT_PREFIX (required) s3://bucket/prefix/ the test may write under
//
// Exits 77 (CMake "skipped") when those are unset, so a plain `ctest` on a box with no store reports no failure.

#include "nanos3reader/s3_range.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

using nanos3reader::FileUploadOptions;
using nanos3reader::open_s3_range_source;
using nanos3reader::open_s3_writer;
using nanos3reader::RangeSource;
using nanos3reader::S3Client;
using nanos3reader::S3RangeOptions;
using nanos3reader::S3WriterOptions;
using nanos3reader::SpillWriterOptions;

constexpr int kSkip = 77;

int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::cerr << __FILE__ << ":" << __LINE__ << ": FAIL " #cond "\n"; \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

const char* env(const char* name) {
    const char* v = std::getenv(name);
    return (v != nullptr && v[0] != '\0') ? v : nullptr;
}

std::vector<std::uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Reads the whole object behind `uri` with range reads of at most `chunk` bytes.
bool read_back(S3Client& client, const std::string& uri, std::uint64_t size, std::vector<std::uint8_t>& out,
               std::uint64_t chunk) {
    out.assign(static_cast<std::size_t>(size), 0);
    std::string error;
    for (std::uint64_t off = 0; off < size; off += chunk) {
        const std::uint64_t n = std::min<std::uint64_t>(chunk, size - off);
        if (!client.read_range(uri, off, n, out.data() + off, error)) {
            std::cerr << "read_back: " << error << "\n";
            return false;
        }
    }
    return true;
}

// Deterministic content for the write tests.
std::vector<std::uint8_t> pattern(std::size_t n, std::uint32_t seed) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<std::uint8_t>((i * 2654435761U + seed) >> 13);
    }
    return v;
}

void source_checks(const std::shared_ptr<S3Client>& client, const std::string& uri, const std::vector<std::uint8_t>& want) {
    std::string error;
    auto source = open_s3_range_source(client, uri, error);
    CHECK(source != nullptr);
    if (!source) {
        std::cerr << error << "\n";
        return;
    }
    CHECK(source->size() == want.size());

    // A footer-sized read at the end (goes through the cache's block).
    const std::uint64_t tail = std::min<std::uint64_t>(source->footer_read_size(), want.size());
    std::vector<std::uint8_t> got(static_cast<std::size_t>(tail));
    CHECK(source->read_at(want.size() - tail, tail, got.data(), error));
    CHECK(std::equal(got.begin(), got.end(), want.end() - static_cast<std::ptrdiff_t>(tail)));

    // Many small reads, scattered, and a large read that bypasses the block.
    for (std::uint64_t off = 0; off + 100 <= want.size(); off += 4099) {
        std::uint8_t small[100];
        CHECK(source->read_at(off, 100, small, error));
        CHECK(std::equal(small, small + 100, want.begin() + static_cast<std::ptrdiff_t>(off)));
    }
    const std::size_t big = std::min<std::size_t>(300000, want.size());
    std::vector<std::uint8_t> bigbuf(big);
    CHECK(source->read_at(0, big, bigbuf.data(), error));
    CHECK(std::equal(bigbuf.begin(), bigbuf.end(), want.begin()));

    // A read past the end fails.
    CHECK(!source->read_at(want.size(), 1, got.data(), error));

    // Missing objects are reported, not opened.
    std::string missing_error;
    CHECK(open_s3_range_source(client, uri + ".does-not-exist", missing_error) == nullptr);
    CHECK(!missing_error.empty());
}

void writer_checks(const std::shared_ptr<S3Client>& client, const std::string& prefix) {
    std::string error;

    // Small object: memory path, one PUT.
    {
        const std::string uri = prefix + "range/small.bin";
        const auto data = pattern(1000, 1);
        auto w = open_s3_writer(client, uri);
        CHECK(w != nullptr);
        if (w) {
            w->write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
            CHECK(w->commit(error));
            CHECK(!w->spilled());
        }
        std::uint64_t size = 0;
        CHECK(client->head(uri, size, error) && size == data.size());
        std::vector<std::uint8_t> back;
        CHECK(read_back(*client, uri, size, back, 256));
        CHECK(back == data);
    }

    // Large object: spills (memory limit 1 MiB) and goes up as a multipart upload (threshold 8 MiB, parts 5 MiB).
    {
        const std::string uri = prefix + "range/big.bin";
        const auto data = pattern(12 * 1024 * 1024, 7);
        S3WriterOptions options;
        options.spill.memory_limit = 1024 * 1024;
        options.upload.multipart_threshold = 8U * 1024U * 1024U;
        options.upload.part_size = 5U * 1024U * 1024U;
        auto w = open_s3_writer(client, uri, options);
        CHECK(w != nullptr);
        if (w) {
            for (std::size_t off = 0; off < data.size(); off += 65536) {
                const std::size_t n = std::min<std::size_t>(65536, data.size() - off);
                w->write(reinterpret_cast<const char*>(data.data() + off), static_cast<std::streamsize>(n));
            }
            CHECK(w->spilled());
            CHECK(w->bytes_written() == data.size());
            CHECK(w->commit(error));
        }
        std::uint64_t size = 0;
        CHECK(client->head(uri, size, error) && size == data.size());
        std::vector<std::uint8_t> back;
        CHECK(read_back(*client, uri, size, back, 4U * 1024U * 1024U));
        CHECK(back == data);
    }

    // A writer destroyed without commit() publishes nothing.
    {
        const std::string uri = prefix + "range/abandoned.bin";
        {
            auto w = open_s3_writer(client, uri);
            CHECK(w != nullptr);
            if (w) {
                *w << "never committed";
            }
        }
        std::uint64_t size = 0;
        CHECK(!client->head(uri, size, error));
    }

    // A non-s3 URI is refused by the writer.
    CHECK(open_s3_writer(client, "/local/path") == nullptr);
}

}  // namespace

int main() {
    const char* uri = env("NANOS3READER_IT_URI");
    const char* expect = env("NANOS3READER_IT_EXPECT");
    const char* put_prefix = env("NANOS3READER_IT_PUT_PREFIX");
    if (uri == nullptr || expect == nullptr || put_prefix == nullptr) {
        std::cout << "range integration: NANOS3READER_IT_URI / _EXPECT / _PUT_PREFIX not set; skipped\n";
        return kSkip;
    }
    const auto want = read_file(expect);
    auto client = std::make_shared<S3Client>();

    source_checks(client, uri, want);
    writer_checks(client, put_prefix);

    if (failures != 0) {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "range integration passed\n";
    return 0;
}
