// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#include "nanos3reader/range.hpp"

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <limits>
#include <random>

namespace nanos3reader {

namespace {
constexpr std::uint64_t kNoBlock = std::numeric_limits<std::uint64_t>::max();
}  // namespace

// --- BlockCachedSource -----------------------------------------------------------------------------

BlockCachedSource::BlockCachedSource(std::unique_ptr<RangeSource> inner)
    : inner_(std::move(inner)), block_start_(kNoBlock) {}

BlockCachedSource::~BlockCachedSource() = default;

std::uint64_t BlockCachedSource::size() const { return inner_->size(); }

std::uint64_t BlockCachedSource::small_read_block() const { return inner_->small_read_block(); }

std::uint64_t BlockCachedSource::footer_read_size() const { return inner_->footer_read_size(); }

void BlockCachedSource::drop_cache() {
    block_.clear();
    block_start_ = kNoBlock;
}

bool BlockCachedSource::read_at(std::uint64_t offset, std::uint64_t n, std::uint8_t* dst, std::string& error) {
    if (n == 0) {
        return true;
    }
    const std::uint64_t total = size();
    if (offset > total || n > total - offset) {
        error = "read of " + std::to_string(n) + " bytes at " + std::to_string(offset) + " is past the object's end (" +
                std::to_string(total) + " bytes)";
        return false;
    }
    const std::uint64_t block = inner_->small_read_block();
    if (block == 0 || n >= block) {
        return inner_->read_at(offset, n, dst, error);
    }
    if (block_start_ == kNoBlock || offset < block_start_ || offset + n > block_start_ + block_.size()) {
        // Load the aligned block that holds the read, cut at the object's end and widened if the read crosses
        // a block boundary.
        const std::uint64_t start = offset - offset % block;
        const std::uint64_t end = std::min(total, std::max(start + block, offset + n));
        block_.resize(static_cast<std::size_t>(end - start));
        if (!inner_->read_at(start, end - start, block_.data(), error)) {
            drop_cache();
            return false;
        }
        block_start_ = start;
    }
    std::memcpy(dst, block_.data() + (offset - block_start_), static_cast<std::size_t>(n));
    return true;
}

// --- SpillBuffer -----------------------------------------------------------------------------------

namespace detail {

// Bytes written so far: in memory up to the limit, then in a temporary file.
class SpillBuffer final : public std::streambuf {
public:
    explicit SpillBuffer(SpillWriterOptions options) : options_(std::move(options)) {}
    ~SpillBuffer() override { discard(); }
    SpillBuffer(const SpillBuffer&) = delete;
    SpillBuffer& operator=(const SpillBuffer&) = delete;

    std::uint64_t written() const { return written_; }
    bool spilled() const { return !file_path_.empty(); }  // also after finish() closed the file
    const std::vector<char>& memory() const { return memory_; }
    const std::filesystem::path& file_path() const { return file_path_; }
    bool failed() const { return failed_; }
    const std::string& failure() const { return failure_; }

    // Closes the temporary file, if any, so it can be uploaded. False on a write error.
    bool finish() {
        if (file_ != nullptr && std::fclose(file_) != 0) {
            fail("failed to write the temporary file " + file_path_.string());
        }
        file_ = nullptr;
        return !failed_;
    }

    // Removes the temporary file and drops the memory.
    void discard() {
        if (file_ != nullptr) {
            std::fclose(file_);
            file_ = nullptr;
        }
        if (!file_path_.empty()) {
            std::error_code ec;
            std::filesystem::remove(file_path_, ec);
            file_path_.clear();
        }
        std::vector<char>().swap(memory_);
    }

protected:
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        if (failed_ || n <= 0) {
            return failed_ ? 0 : n;
        }
        const auto size = static_cast<std::size_t>(n);
        if (file_ == nullptr && memory_.size() + size > options_.memory_limit && !spill()) {
            return 0;
        }
        if (file_ != nullptr) {
            if (std::fwrite(s, 1, size, file_) != size) {
                fail("failed to write the temporary file " + file_path_.string());
                return 0;
            }
        } else {
            memory_.insert(memory_.end(), s, s + size);
        }
        written_ += size;
        return n;
    }

    int_type overflow(int_type ch) override {
        if (traits_type::eq_int_type(ch, traits_type::eof())) {
            return traits_type::not_eof(ch);
        }
        const char c = traits_type::to_char_type(ch);
        return xsputn(&c, 1) == 1 ? ch : traits_type::eof();
    }

    // tellp() only: the writers in this library never seek back.
    pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode which) override {
        if (off == 0 && dir == std::ios_base::cur && (which & std::ios_base::out) != 0) {
            return pos_type(static_cast<off_type>(written_));
        }
        return pos_type(off_type(-1));
    }

private:
    bool spill() {
        static std::atomic<std::uint64_t> counter{0};
        std::error_code ec;
        std::filesystem::path dir = options_.temp_dir;
        if (dir.empty()) {
            dir = std::filesystem::temp_directory_path(ec);
            if (ec) {
                fail("no temporary directory for the upload: " + ec.message());
                return false;
            }
        }
        file_path_ = dir / ("nanos3reader-upload-" + std::to_string(std::random_device{}()) + "-" +
                            std::to_string(counter.fetch_add(1U)) + ".tmp");
        file_ = std::fopen(file_path_.string().c_str(), "wb");
        if (file_ == nullptr) {
            fail("failed to create a temporary file for the upload: " + file_path_.string());
            return false;
        }
        if (!memory_.empty() && std::fwrite(memory_.data(), 1, memory_.size(), file_) != memory_.size()) {
            fail("failed to write the temporary file " + file_path_.string());
            return false;
        }
        std::vector<char>().swap(memory_);
        return true;
    }

    void fail(std::string why) {
        if (!failed_) {
            failed_ = true;
            failure_ = std::move(why);
        }
    }

    SpillWriterOptions options_;
    std::vector<char> memory_;
    std::FILE* file_ = nullptr;
    std::filesystem::path file_path_;
    std::uint64_t written_ = 0;
    bool failed_ = false;
    std::string failure_;
};

SpillBufferHolder::SpillBufferHolder(SpillWriterOptions options)
    : buf(std::make_unique<SpillBuffer>(std::move(options))) {}

SpillBufferHolder::~SpillBufferHolder() = default;

}  // namespace detail

// --- SpillingObjectWriter --------------------------------------------------------------------------

SpillingObjectWriter::SpillingObjectWriter(ObjectSink sink, SpillWriterOptions options)
    : detail::SpillBufferHolder(std::move(options)), std::ostream(SpillBufferHolder::buf.get()), sink_(std::move(sink)) {}

SpillingObjectWriter::~SpillingObjectWriter() = default;

bool SpillingObjectWriter::commit(std::string& error) {
    detail::SpillBuffer& b = *SpillBufferHolder::buf;
    if (committed_) {
        error = "the object was already committed";
        return false;
    }
    committed_ = true;
    flush();
    if (!good() || b.failed() || !b.finish()) {
        error = b.failed() ? b.failure() : "failed to write the object";
        b.discard();
        return false;
    }
    bool ok = false;
    if (b.spilled()) {
        ok = sink_.put_file ? sink_.put_file(b.file_path(), error) : (error = "no file sink", false);
    } else {
        ok = sink_.put_memory ? sink_.put_memory(reinterpret_cast<const std::uint8_t*>(b.memory().data()),
                                                 b.memory().size(), error)
                              : (error = "no memory sink", false);
    }
    b.discard();
    return ok;
}

std::uint64_t SpillingObjectWriter::bytes_written() const { return SpillBufferHolder::buf->written(); }

bool SpillingObjectWriter::spilled() const { return SpillBufferHolder::buf->spilled(); }

}  // namespace nanos3reader
