// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#include "nanos3reader/s3_range.h"

namespace nanos3reader {
namespace {

constexpr const char* kScheme = "s3://";

// Whether `uri` is s3://bucket/... with a non-empty bucket.
bool has_bucket(const std::string& uri) {
    const std::string prefix(kScheme);
    if (uri.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    const auto slash = uri.find('/', prefix.size());
    return slash == std::string::npos ? uri.size() > prefix.size() : slash > prefix.size();
}

class S3RangeSource final : public RangeSource {
public:
    S3RangeSource(std::shared_ptr<S3Client> client, std::string uri, std::uint64_t size, const S3RangeOptions& options)
        : client_(std::move(client)), uri_(std::move(uri)), size_(size), options_(options) {}

    std::uint64_t size() const override { return size_; }

    bool read_at(std::uint64_t offset, std::uint64_t n, std::uint8_t* dst, std::string& error) override {
        return client_->read_range(uri_, offset, n, dst, error);
    }

    std::uint64_t small_read_block() const override { return options_.small_read_block; }

    std::uint64_t footer_read_size() const override { return options_.footer_read_size; }

private:
    std::shared_ptr<S3Client> client_;
    std::string uri_;
    std::uint64_t size_;
    S3RangeOptions options_;
};

}  // namespace

std::unique_ptr<RangeSource> open_s3_range_source(std::shared_ptr<S3Client> client, const std::string& uri,
                                                  std::string& error, const S3RangeOptions& options) {
    if (!client || !has_bucket(uri)) {
        error = "not an s3:// URI with a bucket: " + uri;
        return nullptr;
    }
    std::uint64_t size = 0;
    if (!client->head(uri, size, error)) {
        return nullptr;
    }
    std::unique_ptr<RangeSource> source = std::make_unique<S3RangeSource>(client, uri, size, options);
    if (options.block_cache) {
        source = std::make_unique<BlockCachedSource>(std::move(source));
    }
    return source;
}

std::unique_ptr<SpillingObjectWriter> open_s3_writer(std::shared_ptr<S3Client> client, const std::string& uri,
                                                     const S3WriterOptions& options) {
    if (!client || !has_bucket(uri)) {
        return nullptr;
    }
    ObjectSink sink;
    PutOptions put;
    put.content_type = options.content_type;
    sink.put_memory = [client, uri, put](const std::uint8_t* data, std::size_t size, std::string& error) {
        return client->put(uri, data, size, put, nullptr, error);
    };
    FileUploadOptions upload = options.upload;
    if (upload.content_type.empty()) {
        upload.content_type = options.content_type;
    }
    sink.put_file = [client, uri, upload](const std::filesystem::path& file, std::string& error) {
        return client->put_file(uri, file.string(), upload, nullptr, error);
    };
    return std::make_unique<SpillingObjectWriter>(std::move(sink), options.spill);
}

}  // namespace nanos3reader
