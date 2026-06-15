/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Yoav Bendor */

/* Compiles as C (not C++) on purpose: it's the regression that catches any C++-ism leaking into the public C
 * header, and it confirms the C symbols link. It also exercises the error path with no network — opening a
 * non-s3 URI must fail before any credential/HTTP work and surface a message via nanos3reader_last_error(). */

#include "nanos3reader/nanos3reader.h"

#include <stdio.h>
#include <string.h>

int main(void) {
    int failures = 0;

    nanos3reader_factory* factory = nanos3reader_factory_create();
    if (factory == NULL) {
        fprintf(stderr, "FAIL factory_create returned NULL\n");
        return 1;
    }

    /* Bad scheme: rejected before any network, so this is a hermetic check of the error plumbing. */
    nanos3reader_stream* bad = nanos3reader_open(factory, "http://not-s3/key", 4096);
    if (bad != NULL) {
        fprintf(stderr, "FAIL open of non-s3 URI returned a stream\n");
        nanos3reader_close(bad);
        ++failures;
    } else if (nanos3reader_last_error()[0] == '\0') {
        fprintf(stderr, "FAIL open failed without an error message\n");
        ++failures;
    }

    /* NULL-argument guards must not crash and must report errors via return codes. */
    if (nanos3reader_read(NULL, NULL, 0) != -1) {
        fprintf(stderr, "FAIL read(NULL) did not return -1\n");
        ++failures;
    }
    if (nanos3reader_seek(NULL, 0) != -1) {
        fprintf(stderr, "FAIL seek(NULL) did not return -1\n");
        ++failures;
    }
    if (nanos3reader_tell(NULL) != -1) {
        fprintf(stderr, "FAIL tell(NULL) did not return -1\n");
        ++failures;
    }
    nanos3reader_close(NULL);  /* must be a safe no-op */

    nanos3reader_factory_destroy(factory);
    nanos3reader_factory_destroy(NULL);  /* must be a safe no-op */

    if (failures != 0) {
        fprintf(stderr, "%d C-API check(s) failed\n", failures);
        return 1;
    }
    printf("C API OK\n");
    return 0;
}
