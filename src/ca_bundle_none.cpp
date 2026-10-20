// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// No CA bundle compiled in (configure with -DNANOS3READER_CA_BUNDLE=/path/to/cacert.pem for one).

#include <cstddef>

namespace nanos3reader {

const char* embedded_ca_bundle() { return nullptr; }
std::size_t embedded_ca_bundle_size() { return 0; }

}  // namespace nanos3reader
