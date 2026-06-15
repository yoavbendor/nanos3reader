// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// s3cat — minimal nanos3reader example: open an s3:// (or any supported) URI and write a byte range to
// stdout. Doubles as a manual integration check against a real S3-compatible endpoint.
//
//   s3cat s3://bucket/key [offset] [length]
//
// Credentials/region/endpoint come from the environment and ~/.aws exactly like the AWS tools
// (AWS_PROFILE, AWS_REGION, AWS_ENDPOINT_URL for MinIO, etc.).

#include "nanos3reader/s3_reader.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <istream>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s s3://bucket/key [offset] [length]\n", argv[0]);
        return 2;
    }
    const char* uri = argv[1];
    const std::uint64_t offset = (argc > 2) ? std::strtoull(argv[2], nullptr, 10) : 0;
    const std::uint64_t length = (argc > 3) ? std::strtoull(argv[3], nullptr, 10) : 0;  // 0 = to EOF

    nanos3reader::S3MinStreamFactory factory;
    auto stream = factory.open(uri, 1 << 16);
    if (!stream) {
        std::fprintf(stderr, "open failed: %s\n", factory.error().c_str());
        return 1;
    }
    stream->seekg(static_cast<std::streamoff>(offset));

    char buf[1 << 16];
    std::uint64_t remaining = (length == 0) ? UINT64_MAX : length;
    while (remaining > 0 && *stream) {
        const std::streamsize want =
            static_cast<std::streamsize>(remaining < sizeof buf ? remaining : sizeof buf);
        stream->read(buf, want);
        const std::streamsize got = stream->gcount();
        if (got <= 0) break;
        std::fwrite(buf, 1, static_cast<std::size_t>(got), stdout);
        remaining -= static_cast<std::uint64_t>(got);
    }
    return 0;
}
