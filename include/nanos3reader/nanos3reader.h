/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Yoav Bendor */

/* nanos3reader C API — a thin C/FFI wrapper over the C++ read-only S3 range reader, so Python (ctypes/cffi),
 * Rust (extern "C"), Go (cgo), and other languages can use it without a C++ toolchain. It mirrors the C++
 * factory+stream model 1:1:
 *
 *   factory = nanos3reader_factory_create();           // resolves creds/region/endpoint once, reuse it
 *   s       = nanos3reader_open(factory, "s3://b/k", 1<<16);
 *   n       = nanos3reader_read(s, buf, sizeof buf);   // or nanos3reader_pread(s, buf, n, offset)
 *   nanos3reader_close(s);
 *   nanos3reader_factory_destroy(factory);
 *
 * Read-only / GET-only, like the C++ library. Credentials, region, and AWS_ENDPOINT_URL (MinIO etc.) come
 * from the environment / ~/.aws exactly as the C++ API documents.
 */

#ifndef NANOS3READER_C_API_H
#define NANOS3READER_C_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Export/import decoration for shared builds; expands to nothing for the default static build. The library
 * itself is compiled with NANOS3READER_BUILDING defined (see CMake) so it exports rather than imports. */
#ifndef NANOS3READER_API
#  if defined(_WIN32) && defined(NANOS3READER_SHARED)
#    ifdef NANOS3READER_BUILDING
#      define NANOS3READER_API __declspec(dllexport)
#    else
#      define NANOS3READER_API __declspec(dllimport)
#    endif
#  elif defined(__GNUC__) && defined(NANOS3READER_SHARED)
#    define NANOS3READER_API __attribute__((visibility("default")))
#  else
#    define NANOS3READER_API
#  endif
#endif

/* Opaque handles. A factory resolves the AWS configuration once and is meant to be reused across many opens
 * (resolving credentials can hit the network — IMDSv2/ECS). An open stream owns its own keep-alive connection
 * and outlives the factory, so the factory may be destroyed while streams are still in use. */
typedef struct nanos3reader_factory nanos3reader_factory;
typedef struct nanos3reader_stream  nanos3reader_stream;

/* Create / destroy a factory. create() returns NULL only on allocation failure. destroy(NULL) is a no-op. */
NANOS3READER_API nanos3reader_factory* nanos3reader_factory_create(void);
NANOS3READER_API void                  nanos3reader_factory_destroy(nanos3reader_factory* factory);

/* Open "s3://bucket/key" as a seekable stream whose buffer fetches `read_ahead_bytes` per range GET (0 is
 * treated as 1). Returns NULL on a configuration error (bad URI, missing credentials) — call
 * nanos3reader_last_error() for the reason. */
NANOS3READER_API nanos3reader_stream* nanos3reader_open(nanos3reader_factory* factory, const char* uri,
                                                        size_t read_ahead_bytes);

/* Read up to `len` bytes from the current position into `buf`. Returns the number of bytes read (which may
 * be < len near end-of-object), 0 at end-of-object, or -1 on error (see nanos3reader_last_error()). */
NANOS3READER_API int64_t nanos3reader_read(nanos3reader_stream* stream, void* buf, size_t len);

/* Seek to `offset`, then read like nanos3reader_read — the natural random-access primitive for FFI callers.
 * Returns bytes read, 0 at/after end-of-object, or -1 on error. */
NANOS3READER_API int64_t nanos3reader_pread(nanos3reader_stream* stream, void* buf, size_t len,
                                            uint64_t offset);

/* Seek to absolute byte `offset`. Returns 0 on success, -1 on error. */
NANOS3READER_API int     nanos3reader_seek(nanos3reader_stream* stream, uint64_t offset);

/* Current absolute byte position, or -1 on error. */
NANOS3READER_API int64_t nanos3reader_tell(nanos3reader_stream* stream);

/* Close a stream and release its connection. close(NULL) is a no-op. */
NANOS3READER_API void    nanos3reader_close(nanos3reader_stream* stream);

/* Human-readable description of the most recent failed open/read/seek on the calling thread. Never NULL;
 * returns "" when there has been no error. The pointer is valid until the next nanos3reader call on this
 * thread — copy it if you need to keep it. A single stream is NOT safe to use from multiple threads at once;
 * give each thread its own stream (a factory may be shared once its credentials are resolved). */
NANOS3READER_API const char* nanos3reader_last_error(void);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* NANOS3READER_C_API_H */
