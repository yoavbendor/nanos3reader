// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// S3 bindings for the generic adapters in range.h: a RangeSource over one s3:// object, and a SpillingObjectWriter
// that publishes one s3:// object on commit(). Both go through an S3Client, which may be shared by any number of
// sources and writers (it is thread-safe).

#ifndef NANOS3READER_S3_RANGE_H
#define NANOS3READER_S3_RANGE_H

#include <cstdint>
#include <memory>
#include <string>

#include "nanos3reader/range.hpp"
#include "nanos3reader/s3_reader.h"

namespace nanos3reader {

struct S3RangeOptions {
    // Reads smaller than this share one cached block of this size (one range GET per block). 1 MiB suits a
    // remote object: many small reads become one request.
    std::uint64_t small_read_block = std::uint64_t{1} << 20U;
    // The footer reader fetches this much of the object's end in one request.
    std::uint64_t footer_read_size = std::uint64_t{64} << 10U;
    // Wrap the source in a BlockCachedSource (recommended). False returns the raw range reads.
    bool block_cache = true;
};

// Opens s3://bucket/key for range reads: one HEAD for the size, then one range GET per read (see S3RangeOptions).
// Returns nullptr and `error` (naming the object) when the HEAD fails, for example on a 404.
std::unique_ptr<RangeSource> open_s3_range_source(std::shared_ptr<S3Client> client, const std::string& uri,
                                                  std::string& error, const S3RangeOptions& options = {});

struct S3WriterOptions {
    // Objects larger than the spill memory limit are uploaded from a temporary file with put_file (multipart
    // above upload.multipart_threshold); smaller ones are one PUT from memory.
    FileUploadOptions upload;
    SpillWriterOptions spill;
    std::string content_type;  // empty: application/octet-stream
};

// A writer for s3://bucket/key. Nothing is uploaded until commit(); an object written and then destroyed without
// commit() is never created. Returns nullptr when `uri` is not an s3:// URI with a bucket.
std::unique_ptr<SpillingObjectWriter> open_s3_writer(std::shared_ptr<S3Client> client, const std::string& uri,
                                                     const S3WriterOptions& options = {});

}  // namespace nanos3reader

#endif  // NANOS3READER_S3_RANGE_H
