// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Offline tests of the generic range adapters (range.h): the block cache over a fake source, and the spilling
// writer with fake sinks. No network: these run in a plain `ctest`.

#include "nanos3reader/range.hpp"

#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

using nanos3reader::BlockCachedSource;
using nanos3reader::ObjectSink;
using nanos3reader::RangeSource;
using nanos3reader::SpillingObjectWriter;
using nanos3reader::SpillWriterOptions;

int failures = 0;

#define CHECK(cond)                                                          \
    do {                                                                     \
        if (!(cond)) {                                                       \
            std::cerr << __FILE__ << ":" << __LINE__ << ": FAIL " #cond "\n"; \
            ++failures;                                                      \
        }                                                                    \
    } while (0)

// An in-memory RangeSource that counts the requests it serves.
class FakeSource final : public RangeSource {
public:
    FakeSource(std::vector<std::uint8_t> bytes, std::uint64_t block) : bytes_(std::move(bytes)), block_(block) {}
    std::uint64_t size() const override { return bytes_.size(); }
    bool read_at(std::uint64_t offset, std::uint64_t n, std::uint8_t* dst, std::string& error) override {
        ++requests;
        if (offset + n > bytes_.size()) {
            error = "fake: short read";
            return false;
        }
        std::memcpy(dst, bytes_.data() + offset, static_cast<std::size_t>(n));
        return true;
    }
    std::uint64_t small_read_block() const override { return block_; }
    std::uint64_t requests = 0;

private:
    std::vector<std::uint8_t> bytes_;
    std::uint64_t block_;
};

std::vector<std::uint8_t> pattern(std::size_t n) {
    std::vector<std::uint8_t> v(n);
    for (std::size_t i = 0; i < n; ++i) {
        v[i] = static_cast<std::uint8_t>((i * 31U + 7U) % 251U);
    }
    return v;
}

// Whether `got` (n bytes) equals `want` starting at `offset`.
bool same_bytes(const std::uint8_t* got, const std::vector<std::uint8_t>& want, std::size_t offset, std::size_t n) {
    return std::memcmp(got, want.data() + offset, n) == 0;
}

void block_cache_tests() {
    const auto data = pattern(10000);
    auto inner = std::make_unique<FakeSource>(data, 1024);
    FakeSource* raw = inner.get();
    BlockCachedSource cached(std::move(inner));
    CHECK(cached.size() == 10000);

    std::string error;
    std::vector<std::uint8_t> got(4096);

    // Small reads inside one block cost one request.
    CHECK(cached.read_at(0, 100, got.data(), error));
    CHECK(same_bytes(got.data(), data, 0, 100));
    CHECK(cached.read_at(200, 50, got.data(), error));
    CHECK(same_bytes(got.data(), data, 200, 50));
    CHECK(raw->requests == 1);

    // A read crossing a block boundary widens the block and is still correct.
    CHECK(cached.read_at(1000, 100, got.data(), error));
    CHECK(same_bytes(got.data(), data, 1000, 100));
    CHECK(raw->requests == 2);

    // The last block is cut at the object's end.
    CHECK(cached.read_at(9950, 50, got.data(), error));
    CHECK(same_bytes(got.data(), data, 9950, 50));
    CHECK(raw->requests == 3);

    // A read of a block or more bypasses the cache: one request, correct bytes.
    CHECK(cached.read_at(100, 4096, got.data(), error));
    CHECK(same_bytes(got.data(), data, 100, 4096));
    CHECK(raw->requests == 4);

    // Reads past the end fail without reaching the inner source.
    CHECK(!cached.read_at(9999, 2, got.data(), error));
    CHECK(!error.empty());
    CHECK(raw->requests == 4);

    // Zero-length reads succeed without a request.
    CHECK(cached.read_at(5, 0, got.data(), error));
    CHECK(raw->requests == 4);

    // drop_cache forces the next small read to fetch its block again.
    cached.drop_cache();
    CHECK(cached.read_at(0, 10, got.data(), error));
    CHECK(same_bytes(got.data(), data, 0, 10));
    CHECK(raw->requests == 5);

    // A block size of 0 turns caching off: every small read is a request.
    auto uncached_inner = std::make_unique<FakeSource>(data, 0);
    FakeSource* uraw = uncached_inner.get();
    BlockCachedSource uncached(std::move(uncached_inner));
    CHECK(uncached.read_at(0, 10, got.data(), error));
    CHECK(uncached.read_at(0, 10, got.data(), error));
    CHECK(uraw->requests == 2);
}

struct Recorder {
    std::vector<std::uint8_t> memory;
    std::filesystem::path file;
    std::string file_contents;
    int memory_calls = 0;
    int file_calls = 0;
    bool file_existed_during_call = false;
    bool fail = false;
};

ObjectSink recording_sink(Recorder& r) {
    ObjectSink sink;
    sink.put_memory = [&r](const std::uint8_t* data, std::size_t size, std::string& error) {
        ++r.memory_calls;
        if (r.fail) {
            error = "injected memory failure";
            return false;
        }
        r.memory.assign(data, data + size);
        return true;
    };
    sink.put_file = [&r](const std::filesystem::path& file, std::string& error) {
        ++r.file_calls;
        r.file = file;
        r.file_existed_during_call = std::filesystem::exists(file);
        std::ifstream in(file, std::ios::binary);
        std::ostringstream ss;
        ss << in.rdbuf();
        r.file_contents = ss.str();
        if (r.fail) {
            error = "injected file failure";
            return false;
        }
        return true;
    };
    return sink;
}

SpillWriterOptions options(std::size_t limit, const std::filesystem::path& dir) {
    SpillWriterOptions o;
    o.memory_limit = limit;
    o.temp_dir = dir;
    return o;
}

void writer_tests() {
    const auto temp = std::filesystem::temp_directory_path() / "nanos3reader-range-test";
    std::filesystem::create_directories(temp);

    // Under the limit: memory path only; the object is the bytes written; tellp counts them.
    {
        Recorder r;
        SpillingObjectWriter w(recording_sink(r), options(1024, temp));
        w << "hello, " << 42;
        CHECK(static_cast<std::streamoff>(w.tellp()) == 9);
        std::string error;
        CHECK(w.commit(error));
        CHECK(r.memory_calls == 1 && r.file_calls == 0);
        CHECK(std::string(r.memory.begin(), r.memory.end()) == "hello, 42");
        CHECK(w.bytes_written() == 9);
        CHECK(!w.spilled());
        CHECK(!w.commit(error));  // only once
    }

    // Over the limit: spills to a temporary file; put_file sees the whole content; the file is removed after.
    {
        Recorder r;
        std::string payload(300, 'x');
        for (std::size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<char>('a' + (i % 26));
        }
        std::filesystem::path seen;
        {
            SpillingObjectWriter w(recording_sink(r), options(64, temp));
            w.write(payload.data(), static_cast<std::streamsize>(payload.size()));
            CHECK(w.spilled());
            std::string error;
            CHECK(w.commit(error));
            seen = r.file;
        }
        CHECK(r.memory_calls == 0 && r.file_calls == 1);
        CHECK(r.file_existed_during_call);
        CHECK(r.file_contents == payload);
        CHECK(!seen.empty() && !std::filesystem::exists(seen));
    }

    // Destroyed without commit: nothing published, temporary file removed.
    {
        Recorder r;
        std::filesystem::path seen;
        {
            SpillingObjectWriter w(recording_sink(r), options(64, temp));
            w << std::string(200, 'z');
            CHECK(w.spilled());
            for (const auto& e : std::filesystem::directory_iterator(temp)) {
                seen = e.path();
            }
            CHECK(!seen.empty() && std::filesystem::exists(seen));
        }
        CHECK(r.memory_calls == 0 && r.file_calls == 0);
        CHECK(!seen.empty() && !std::filesystem::exists(seen));
    }

    // A failing memory sink reports its error through commit().
    {
        Recorder r;
        r.fail = true;
        SpillingObjectWriter w(recording_sink(r), options(1024, temp));
        w << "data";
        std::string error;
        CHECK(!w.commit(error));
        CHECK(error == "injected memory failure");
        CHECK(r.memory_calls == 1);
    }

    // A failing spilled upload reports its error, and the temporary file is still removed.
    {
        Recorder r;
        r.fail = true;
        std::filesystem::path seen;
        {
            SpillingObjectWriter w(recording_sink(r), options(64, temp));
            w << std::string(200, 'q');
            std::string error;
            CHECK(!w.commit(error));
            CHECK(error == "injected file failure");
            seen = r.file;
        }
        CHECK(!seen.empty() && !std::filesystem::exists(seen));
    }

    // Empty object: committed through the memory path with zero bytes.
    {
        Recorder r;
        SpillingObjectWriter w(recording_sink(r), options(1024, temp));
        std::string error;
        CHECK(w.commit(error));
        CHECK(r.memory_calls == 1 && r.memory.empty());
    }

    std::error_code ec;
    std::filesystem::remove_all(temp, ec);
}

}  // namespace

int main() {
    block_cache_tests();
    writer_tests();
    if (failures != 0) {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "range tests passed\n";
    return 0;
}
