/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Yoav Bendor */

/* s3cat_c — the C-API counterpart of s3cat, and a tiny throughput probe for the FFI surface. It opens an
 * s3:// object through the C API and streams it to stdout one fixed-size chunk at a time (read -> write,
 * repeat), then prints bytes / seconds / MiB-per-second to stderr. Because it's plain C calling only
 * nanos3reader_*(), a fast number here is evidence the C wrapper adds no real overhead over the C++ reader.
 *
 *   s3cat_c s3://bucket/key [chunk_bytes]      # chunk_bytes default 1 MiB
 *
 * Credentials/region/endpoint come from the environment and ~/.aws (AWS_ENDPOINT_URL=http://localhost:9000
 * for MinIO, etc.) exactly like s3cat. Send stdout to a file or /dev/null to measure raw read speed:
 *
 *   AWS_ENDPOINT_URL=http://localhost:9000 ./s3cat_c s3://bucket/key 1048576 > /dev/null
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime / CLOCK_MONOTONIC */

#include "nanos3reader/nanos3reader.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s s3://bucket/key [chunk_bytes]\n", argv[0]);
        return 2;
    }
    const char* uri = argv[1];
    size_t chunk = (argc > 2) ? (size_t)strtoull(argv[2], NULL, 10) : (size_t)(1 << 20);
    if (chunk == 0) {
        chunk = 1 << 20;
    }

    char* buf = (char*)malloc(chunk);
    if (buf == NULL) {
        fprintf(stderr, "out of memory for a %zu-byte chunk\n", chunk);
        return 1;
    }

    nanos3reader_factory* factory = nanos3reader_factory_create();
    if (factory == NULL) {
        fprintf(stderr, "factory_create failed\n");
        free(buf);
        return 1;
    }

    /* read_ahead = chunk: each chunk read maps to one range GET window. */
    nanos3reader_stream* s = nanos3reader_open(factory, uri, chunk);
    if (s == NULL) {
        fprintf(stderr, "open failed: %s\n", nanos3reader_last_error());
        nanos3reader_factory_destroy(factory);
        free(buf);
        return 1;
    }

    struct timespec t0;
    struct timespec t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    uint64_t total = 0;
    int rc = 0;
    for (;;) {
        const int64_t n = nanos3reader_read(s, buf, chunk);
        if (n < 0) {
            fprintf(stderr, "read failed after %llu bytes: %s\n", (unsigned long long)total,
                    nanos3reader_last_error());
            rc = 1;
            break;
        }
        if (n == 0) {
            break; /* end of object */
        }
        if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n) {
            fprintf(stderr, "short write to stdout\n");
            rc = 1;
            break;
        }
        total += (uint64_t)n;
    }

    clock_gettime(CLOCK_MONOTONIC, &t1);
    const double secs = (double)(t1.tv_sec - t0.tv_sec) + (double)(t1.tv_nsec - t0.tv_nsec) / 1e9;
    const double mib = (double)total / (1024.0 * 1024.0);
    fprintf(stderr, "read %llu bytes in %zu-byte chunks in %.3f s (%.1f MiB/s)\n",
            (unsigned long long)total, chunk, secs, secs > 0.0 ? mib / secs : 0.0);

    nanos3reader_close(s);
    nanos3reader_factory_destroy(factory);
    free(buf);
    return rc;
}
