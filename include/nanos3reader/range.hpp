// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Generic, storage-agnostic I/O adapters for object stores:
//   * RangeSource: random-access reads of one object at absolute offsets (no position, so one source serves
//     any reader in any order). S3 implementation: open_s3_range_source (s3_range.h).
//   * BlockCachedSource: wraps any RangeSource so that small reads share one aligned block, turning many small
//     requests (a footer's metadata, the pages of a column chunk) into one range GET.
//   * SpillingObjectWriter: a std::ostream that holds an object's bytes in memory up to a limit and then spills
//     them to a temporary file. Nothing is published until commit(), which hands the bytes to a sink: one
//     whole-object PUT, or a file upload. S3 implementation: open_s3_writer (s3_range.h).
//
// Nothing here depends on Arrow, Parquet or any particular format.

#ifndef NANOS3READER_RANGE_H
#define NANOS3READER_RANGE_H

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <ostream>
#include <streambuf>
#include <string>
#include <vector>

namespace nanos3reader {

// --- Range reads -----------------------------------------------------------------------------------

class RangeSource {
public:
    virtual ~RangeSource() = default;
    // The object's size, known when the source was opened.
    virtual std::uint64_t size() const = 0;
    // Exactly `n` bytes at `offset` into `dst`. False and `error` on a short or failed read.
    virtual bool read_at(std::uint64_t offset, std::uint64_t n, std::uint8_t* dst, std::string& error) = 0;
    // Reads smaller than this are served from one cached block of this size around them. 0 turns caching off.
    virtual std::uint64_t small_read_block() const { return 8U * 1024U; }
    // How much of the object's end a footer reader should fetch at once (the footer and often the metadata
    // before it). A remote source returns more, since every extra request is a round trip.
    virtual std::uint64_t footer_read_size() const { return 8U * 1024U; }
};

// Wraps a RangeSource with a block cache: a read smaller than small_read_block() is served from one aligned
// block that is fetched once and kept until a read falls outside it, so nearby small reads cost one request.
// Reads of a block or more go straight to the inner source. Not thread-safe: use one per reader.
class BlockCachedSource final : public RangeSource {
public:
    explicit BlockCachedSource(std::unique_ptr<RangeSource> inner);
    ~BlockCachedSource() override;
    BlockCachedSource(const BlockCachedSource&) = delete;
    BlockCachedSource& operator=(const BlockCachedSource&) = delete;

    std::uint64_t size() const override;
    bool read_at(std::uint64_t offset, std::uint64_t n, std::uint8_t* dst, std::string& error) override;
    std::uint64_t small_read_block() const override;
    std::uint64_t footer_read_size() const override;

    // Forget the cached block (the next small read fetches again).
    void drop_cache();

private:
    std::unique_ptr<RangeSource> inner_;
    std::vector<std::uint8_t> block_;
    std::uint64_t block_start_;  // offset of block_[0] in the object; kNoBlock when none is cached
};

// --- Spilling writer -------------------------------------------------------------------------------

struct SpillWriterOptions {
    // Bytes kept in memory before the writer switches to a temporary file.
    std::size_t memory_limit = std::size_t{8} << 20U;
    // Directory for the temporary file. Empty: the system temporary directory.
    std::filesystem::path temp_dir;
};

// Where a finished object goes. Exactly one of the two is called, from commit(). Each returns false and sets
// `error` on failure.
struct ObjectSink {
    // The whole object, held in memory (at most SpillWriterOptions::memory_limit bytes).
    std::function<bool(const std::uint8_t* data, std::size_t size, std::string& error)> put_memory;
    // The whole object, in a temporary file the writer owns (removed after this call returns).
    std::function<bool(const std::filesystem::path& file, std::string& error)> put_file;
};

namespace detail {
class SpillBuffer;  // the streambuf (defined in range.cpp)
// Owns the streambuf before the std::ostream base is constructed (base-from-member), so the base can be given it.
struct SpillBufferHolder {
    SpillBufferHolder(SpillWriterOptions options);
    ~SpillBufferHolder();
    std::unique_ptr<SpillBuffer> buf;
};
}  // namespace detail

// One object being written, as an std::ostream (tellp() counts the bytes written; the writer never seeks back).
// Bytes are buffered in memory until SpillWriterOptions::memory_limit, then go to a temporary file. An object
// becomes visible only when commit() succeeds: a writer destroyed without commit() publishes nothing and
// removes its temporary file.
class SpillingObjectWriter final : private detail::SpillBufferHolder, public std::ostream {
public:
    SpillingObjectWriter(ObjectSink sink, SpillWriterOptions options = {});
    ~SpillingObjectWriter() override;
    SpillingObjectWriter(const SpillingObjectWriter&) = delete;
    SpillingObjectWriter& operator=(const SpillingObjectWriter&) = delete;

    // Flushes, then hands the bytes to the sink. False and `error` when a write or the upload failed. Call once.
    bool commit(std::string& error);

    // Bytes written so far.
    std::uint64_t bytes_written() const;

    // Whether the bytes went to a temporary file (exceeded the memory limit).
    bool spilled() const;

private:
    ObjectSink sink_;
    bool committed_ = false;
};

}  // namespace nanos3reader

#endif  // NANOS3READER_RANGE_H
