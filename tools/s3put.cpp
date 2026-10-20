// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// s3put: upload a file, or every file under a directory, to S3.
//
//   s3put [options] <file|directory> <s3://bucket/prefix/ | s3://bucket/key>
//
// A directory goes to <prefix>/<path relative to the directory> for each regular file under it (recursively;
// symlinks to files followed, symlinked directories not). A file goes to the key given, or to
// <prefix>/<file name> when the destination ends with '/'. Files are streamed from disk (never read whole),
// several at a time; large ones go up as multipart uploads. Credentials, region and endpoint come from the
// environment chain nanos3reader uses (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN,
// shared profile files, ECS container credentials, EC2 instance role; AWS_REGION; AWS_ENDPOINT_URL).
//
// Prints one line per file and a summary. Exit status: 0 when every file was uploaded (also when there was
// nothing to upload, with a warning), 1 when any upload failed, 2 for a usage error or a source that does
// not exist or cannot be listed.

#include "nanos3reader/s3_reader.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>

namespace {

void usage() {
    std::fprintf(stderr,
                 "usage: s3put [options] <file|directory> <s3://bucket/prefix/ | s3://bucket/key>\n"
                 "  -j, --jobs N                 files uploaded at once (default 8)\n"
                 "      --part-jobs N            parts of one large file uploaded at once (default 4)\n"
                 "      --multipart-threshold M  files of M MiB or more go up in parts (default 64)\n"
                 "      --part-size M            part size in MiB (default 16; at least 5)\n"
                 "      --content-type TYPE      Content-Type of every object (default application/octet-stream)\n"
                 "      --sign-payload           sign each file's SHA-256 (reads every file twice)\n"
                 "  -q, --quiet                  no per-file lines, only the summary and failures\n");
}

bool parse_count(const char* text, unsigned long long& out) {
    char* end = nullptr;
    out = std::strtoull(text, &end, 10);
    return end != text && *end == '\0' && out > 0;
}

double mbps(std::uint64_t bytes, double seconds) {
    return seconds > 0 ? static_cast<double>(bytes) * 8.0 / 1e6 / seconds : 0.0;
}

}  // namespace

int main(int argc, char** argv) {
    nanos3reader::DirectoryUploadOptions options;
    bool quiet = false;
    std::string source;
    std::string dest;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const auto value = [&](unsigned long long& out) {
            if (i + 1 >= argc || !parse_count(argv[i + 1], out)) {
                std::fprintf(stderr, "s3put: %s needs a positive number\n", arg.c_str());
                std::exit(2);
            }
            ++i;
        };
        unsigned long long n = 0;
        if (arg == "-j" || arg == "--jobs") {
            value(n);
            options.concurrency = static_cast<unsigned>(n);
        } else if (arg == "--part-jobs") {
            value(n);
            options.file.part_concurrency = static_cast<unsigned>(n);
        } else if (arg == "--multipart-threshold") {
            value(n);
            options.file.multipart_threshold = n << 20U;
        } else if (arg == "--part-size") {
            value(n);
            options.file.part_size = n << 20U;
        } else if (arg == "--content-type") {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "s3put: --content-type needs a value\n");
                return 2;
            }
            options.file.content_type = argv[++i];
        } else if (arg == "--sign-payload") {
            options.file.sign_payload = true;
        } else if (arg == "-q" || arg == "--quiet") {
            quiet = true;
        } else if (arg == "-h" || arg == "--help") {
            usage();
            return 0;
        } else if (!arg.empty() && arg[0] == '-' && arg != "-") {
            std::fprintf(stderr, "s3put: unknown option %s\n", arg.c_str());
            usage();
            return 2;
        } else if (source.empty()) {
            source = arg;
        } else if (dest.empty()) {
            dest = arg;
        } else {
            usage();
            return 2;
        }
    }
    if (source.empty() || dest.empty()) {
        usage();
        return 2;
    }

    nanos3reader::S3Client client;
    std::error_code ec;
    const std::filesystem::path src(source);
    if (std::filesystem::is_directory(src, ec)) {
        nanos3reader::DirectoryUploadStats stats;
        std::string error;
        const bool ok = client.put_directory(
            source, dest, options,
            [&](const nanos3reader::FileUploadResult& r) {
                if (!r.ok) {
                    std::fprintf(stderr, "FAILED %s -> %s: %s\n", r.path.c_str(), r.uri.c_str(), r.error.c_str());
                } else if (!quiet) {
                    std::printf("uploaded %s -> %s (%llu bytes, %.2f s)\n", r.path.c_str(), r.uri.c_str(),
                                static_cast<unsigned long long>(r.bytes), r.seconds);
                    std::fflush(stdout);
                }
            },
            stats, error);
        std::printf("s3put: %llu file(s), %llu bytes in %.2f s (%.1f Mbps), %llu failed [nanos3reader %d.%d.%d, "
                    "%u at once]\n",
                    static_cast<unsigned long long>(stats.files), static_cast<unsigned long long>(stats.bytes),
                    stats.seconds, mbps(stats.bytes, stats.seconds), static_cast<unsigned long long>(stats.failed),
                    NANOS3READER_VERSION_MAJOR, NANOS3READER_VERSION_MINOR, NANOS3READER_VERSION_PATCH,
                    options.concurrency);
        if (!ok && stats.failed == 0) {  // the directory itself could not be read
            std::fprintf(stderr, "s3put: %s\n", error.c_str());
            return 2;
        }
        if (!ok) {
            std::fprintf(stderr, "s3put: %s\n", error.c_str());
            return 1;
        }
        if (stats.files == 0) {
            std::fprintf(stderr, "s3put: warning: nothing uploaded (no files under %s)\n", source.c_str());
        }
        return 0;
    }
    if (!std::filesystem::is_regular_file(src, ec)) {
        std::fprintf(stderr, "s3put: %s: no such file or directory\n", source.c_str());
        return 2;
    }
    std::string uri = dest;
    if (!uri.empty() && uri.back() == '/') {
        uri += src.filename().string();
    }
    const std::uint64_t size = std::filesystem::file_size(src, ec);
    std::string error;
    const auto t0 = std::chrono::steady_clock::now();
    const bool ok = client.put_file(uri, source, options.file, nullptr, error);
    const double seconds = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    if (!ok) {
        std::fprintf(stderr, "FAILED %s -> %s: %s\n", source.c_str(), uri.c_str(), error.c_str());
        return 1;
    }
    if (!quiet) {
        std::printf("uploaded %s -> %s (%llu bytes, %.2f s)\n", source.c_str(), uri.c_str(),
                    static_cast<unsigned long long>(size), seconds);
    }
    std::printf("s3put: 1 file(s), %llu bytes in %.2f s (%.1f Mbps), 0 failed [nanos3reader %d.%d.%d]\n",
                static_cast<unsigned long long>(size), seconds, mbps(size, seconds), NANOS3READER_VERSION_MAJOR,
                NANOS3READER_VERSION_MINOR, NANOS3READER_VERSION_PATCH);
    return 0;
}
