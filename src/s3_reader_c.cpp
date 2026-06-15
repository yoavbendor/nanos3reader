// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// C/FFI shim over the C++ S3MinStreamFactory + std::istream. Pure glue: every behavior (SigV4, range GETs,
// read-ahead, credential chain, error messages) lives in s3_reader.cpp; here we just expose opaque handles
// and translate iostream state into C return codes. See include/nanos3reader/nanos3reader.h.

#include "nanos3reader/nanos3reader.h"

#include "nanos3reader/s3_reader.h"

#include <istream>
#include <memory>
#include <string>

struct nanos3reader_factory {
    nanos3reader::S3MinStreamFactory impl;
};

struct nanos3reader_stream {
    std::unique_ptr<std::istream> s;
};

namespace {

// Mirror of the C++ thread-local error into a stable C string. nanos3reader::last_error() returns by value,
// so we keep the backing storage here and hand out its c_str(), valid until the next call on this thread.
const char* publish_error() {
    static thread_local std::string buf;
    buf = nanos3reader::last_error();
    return buf.c_str();
}

// Read up to len bytes at the current position. Returns bytes read, 0 at EOF, -1 on a real error. A short
// read that hit end-of-object leaves eof/failbit set; we clear it so the next call cleanly re-reports EOF
// (the underlying streambuf's end-of-object flag is sticky) and so a later seek isn't blocked by failbit.
int64_t read_current(std::istream& s, void* buf, size_t len) {
    if (len == 0) {
        return 0;
    }
    s.read(static_cast<char*>(buf), static_cast<std::streamsize>(len));
    const std::streamsize got = s.gcount();
    if (s.bad()) {
        return -1;
    }
    if (got == 0) {
        return (s.fail() && !s.eof()) ? -1 : 0;  // non-eof failure vs. genuine end-of-object
    }
    s.clear();  // drop eof/failbit from a short read so reads/seeks can continue
    return static_cast<int64_t>(got);
}

}  // namespace

extern "C" {

nanos3reader_factory* nanos3reader_factory_create(void) {
    return new (std::nothrow) nanos3reader_factory();
}

void nanos3reader_factory_destroy(nanos3reader_factory* factory) { delete factory; }

nanos3reader_stream* nanos3reader_open(nanos3reader_factory* factory, const char* uri,
                                       size_t read_ahead_bytes) {
    if (factory == nullptr || uri == nullptr) {
        return nullptr;
    }
    auto s = factory->impl.open(uri, read_ahead_bytes);
    if (!s) {
        return nullptr;  // factory recorded the reason in the thread-local error
    }
    auto* handle = new (std::nothrow) nanos3reader_stream();
    if (handle == nullptr) {
        return nullptr;
    }
    handle->s = std::move(s);
    return handle;
}

int64_t nanos3reader_read(nanos3reader_stream* stream, void* buf, size_t len) {
    if (stream == nullptr || stream->s == nullptr || (buf == nullptr && len != 0)) {
        return -1;
    }
    return read_current(*stream->s, buf, len);
}

int64_t nanos3reader_pread(nanos3reader_stream* stream, void* buf, size_t len, uint64_t offset) {
    if (stream == nullptr || stream->s == nullptr || (buf == nullptr && len != 0)) {
        return -1;
    }
    std::istream& s = *stream->s;
    s.clear();  // a previous read may have left eof/failbit set; seekg needs a clean state
    s.seekg(static_cast<std::streamoff>(offset));
    if (s.fail()) {
        return -1;
    }
    return read_current(s, buf, len);
}

int nanos3reader_seek(nanos3reader_stream* stream, uint64_t offset) {
    if (stream == nullptr || stream->s == nullptr) {
        return -1;
    }
    std::istream& s = *stream->s;
    s.clear();
    s.seekg(static_cast<std::streamoff>(offset));
    return s.fail() ? -1 : 0;
}

int64_t nanos3reader_tell(nanos3reader_stream* stream) {
    if (stream == nullptr || stream->s == nullptr) {
        return -1;
    }
    const std::istream::pos_type p = stream->s->tellg();
    return (p == std::istream::pos_type(-1)) ? -1 : static_cast<int64_t>(p);
}

void nanos3reader_close(nanos3reader_stream* stream) { delete stream; }

const char* nanos3reader_last_error(void) { return publish_error(); }

}  // extern "C"
