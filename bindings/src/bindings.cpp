// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

#include "nanos3reader/s3_reader.h"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include <cstdint>
#include <istream>
#include <memory>
#include <sstream>
#include <string>

namespace py = pybind11;

namespace {

class OpenError : public std::runtime_error {
public:
    explicit OpenError(const std::string& msg) : std::runtime_error(msg) {}
};

// S3Client failures; PreconditionFailed when a conditional put's condition does not hold (HTTP 412).
class S3Error : public std::runtime_error {
public:
    explicit S3Error(const std::string& msg) : std::runtime_error(msg) {}
};
class PreconditionFailed : public S3Error {
public:
    explicit PreconditionFailed(const std::string& msg) : S3Error(msg) {}
};

class S3Reader {
public:
    S3Reader(nanos3reader::S3MinStreamFactory& factory, const std::string& uri, std::size_t read_ahead)
        : factory_(&factory), uri_(uri) {
        stream_ = factory.open(uri, read_ahead);
        if (!stream_) {
            const std::string err = factory.error();
            throw OpenError(err.empty() ? "open failed" : err);
        }
    }

    py::bytes read(py::object size_obj) {
        if (!stream_) throw OpenError("stream is closed");
        std::string buf;
        if (size_obj.is_none()) {
            std::ostringstream out;
            out << stream_->rdbuf();
            buf = out.str();
        } else {
            const py::ssize_t size = size_obj.cast<py::ssize_t>();
            if (size < 0) {
                std::ostringstream out;
                out << stream_->rdbuf();
                buf = out.str();
            } else if (size == 0) {
                return py::bytes();
            } else {
                buf.resize(static_cast<std::size_t>(size));
                stream_->read(buf.data(), static_cast<std::streamsize>(size));
                buf.resize(static_cast<std::size_t>(stream_->gcount()));
            }
        }
        return py::bytes(buf);
    }

    std::uint64_t seek(std::int64_t offset, int whence) {
        if (!stream_) throw OpenError("stream is closed");
        std::ios::seekdir dir = std::ios::beg;
        if (whence == 1) {
            dir = std::ios::cur;
        } else if (whence == 2) {
            dir = std::ios::end;
        }
        stream_->seekg(static_cast<std::streamoff>(offset), dir);
        if (!*stream_ && !stream_->eof()) {
            throw OpenError(factory_->error().empty() ? "seek failed" : factory_->error());
        }
        return static_cast<std::uint64_t>(stream_->tellg());
    }

    std::uint64_t tell() const {
        if (!stream_) throw OpenError("stream is closed");
        return static_cast<std::uint64_t>(stream_->tellg());
    }

    void close() { stream_.reset(); }

    const std::string& uri() const { return uri_; }

private:
    nanos3reader::S3MinStreamFactory* factory_;
    std::string uri_;
    std::unique_ptr<std::istream> stream_;
};

}  // namespace

PYBIND11_MODULE(_nanos3reader, m) {
    m.doc() = "Python bindings for nanos3reader — a minimal S3 range reader and client";

    py::register_exception<OpenError>(m, "OpenError");

    py::class_<nanos3reader::S3MinStreamFactory>(m, "Factory")
        .def(py::init<>())
        .def(
            "open",
            [](nanos3reader::S3MinStreamFactory& factory, const std::string& uri, std::size_t read_ahead) {
                return std::make_unique<S3Reader>(factory, uri, read_ahead);
            },
            py::arg("uri"), py::arg("read_ahead") = 65536)
        .def("error", &nanos3reader::S3MinStreamFactory::error);

    py::class_<S3Reader>(m, "Reader")
        .def("read", &S3Reader::read, py::arg("size") = py::none())
        .def("seek", &S3Reader::seek, py::arg("offset"), py::arg("whence") = 0)
        .def("tell", &S3Reader::tell)
        .def("close", &S3Reader::close)
        .def_property_readonly("uri", &S3Reader::uri)
        .def("__enter__", [](S3Reader& self) -> S3Reader& { return self; })
        .def("__exit__",
             [](S3Reader& self, const py::object&, const py::object&, const py::object&) { self.close(); });

    m.def(
        "open",
        [](const std::string& uri, std::size_t read_ahead) {
            static thread_local nanos3reader::S3MinStreamFactory factory;
            return std::make_unique<S3Reader>(factory, uri, read_ahead);
        },
        py::arg("uri"), py::arg("read_ahead") = 65536);

    auto s3_error = py::register_exception<S3Error>(m, "S3Error");
    py::register_exception<PreconditionFailed>(m, "PreconditionFailed", s3_error.ptr());

    py::class_<nanos3reader::S3Client>(m, "Client")
        .def(py::init([](const std::string& access_key_id, const std::string& secret_access_key,
                         const std::string& session_token, const std::string& region, const std::string& endpoint,
                         bool allow_http) {
                 nanos3reader::ClientOptions o;
                 o.access_key_id = access_key_id;
                 o.secret_access_key = secret_access_key;
                 o.session_token = session_token;
                 o.region = region;
                 o.endpoint = endpoint;
                 o.allow_http = allow_http;
                 return std::make_unique<nanos3reader::S3Client>(o);
             }),
             py::arg("access_key_id") = "", py::arg("secret_access_key") = "", py::arg("session_token") = "",
             py::arg("region") = "", py::arg("endpoint") = "", py::arg("allow_http") = false)
        .def(
            "put",
            [](nanos3reader::S3Client& client, const std::string& uri, const py::bytes& data,
               const std::string& content_type, bool if_none_match, const std::string& if_match) {
                std::string body = data;  // copied once, so the request runs without the GIL
                nanos3reader::PutOptions options;
                options.content_type = content_type;
                options.if_none_match = if_none_match;
                options.if_match = if_match;
                std::string etag;
                std::string error;
                bool precondition = false;
                bool ok = false;
                {
                    py::gil_scoped_release release;
                    ok = client.put(uri, reinterpret_cast<const std::uint8_t*>(body.data()), body.size(), options,
                                    &etag, error, &precondition);
                }
                if (!ok) {
                    if (precondition) throw PreconditionFailed(error);
                    throw S3Error(error);
                }
                return etag;
            },
            py::arg("uri"), py::arg("data"), py::arg("content_type") = "", py::arg("if_none_match") = false,
            py::arg("if_match") = "")
        .def(
            "remove",
            [](nanos3reader::S3Client& client, const std::string& uri) {
                std::string error;
                bool ok = false;
                {
                    py::gil_scoped_release release;
                    ok = client.remove(uri, error);
                }
                if (!ok) throw S3Error(error);
            },
            py::arg("uri"),
            "Delete one object (a missing object is not an error, as on S3).")
        .def(
            "head",
            [](nanos3reader::S3Client& client, const std::string& uri) {
                std::uint64_t size = 0;
                std::string error;
                bool ok = false;
                {
                    py::gil_scoped_release release;
                    ok = client.head(uri, size, error);
                }
                if (!ok) throw S3Error(error);
                return size;
            },
            py::arg("uri"))
        .def(
            "read_range",
            [](nanos3reader::S3Client& client, const std::string& uri, std::uint64_t offset, std::uint64_t size) {
                std::string out(static_cast<std::size_t>(size), '\0');
                std::string error;
                bool ok = false;
                {
                    py::gil_scoped_release release;
                    ok = client.read_range(uri, offset, size, reinterpret_cast<std::uint8_t*>(out.data()), error);
                }
                if (!ok) throw S3Error(error);
                return py::bytes(out);
            },
            py::arg("uri"), py::arg("offset"), py::arg("size"));

    m.def("configure_disk_cache", &nanos3reader::configure_disk_cache, py::arg("cache_dir"),
          py::arg("max_blocks"));
    m.def(
        "disk_cache_stats",
        []() {
            std::uint64_t hits = 0, misses = 0;
            nanos3reader::disk_cache_stats(&hits, &misses);
            return py::make_tuple(hits, misses);
        });
}
