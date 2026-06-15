// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Yoav Bendor

// Validates the built-in S3 reader's AWS SigV4 signer against AWS's own published test vectors. Pure
// computation, no network — this is the correctness gate for the signing path.

#include "nanos3reader/s3_reader.h"

#include <iostream>
#include <string>

namespace {

int failures = 0;

void check_eq(const std::string& got, const std::string& want, const char* what) {
    if (got != want) {
        std::cerr << "FAIL " << what << "\n  got:  " << got << "\n  want: " << want << '\n';
        ++failures;
    }
}

}  // namespace

int main() {
    using namespace nanos3reader::s3v4;

    // SHA-256 of the empty string (the well-known constant S3 uses for empty payloads).
    check_eq(sha256_hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256(\"\")");

    // AWS docs "Examples of how to derive a signing key for Signature Version 4".
    {
        const auto key = derive_signing_key("wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20120215",
                                            "us-east-1", "iam");
        check_eq(hex_encode(key.data(), key.size()),
                 "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d", "derive_signing_key");
    }

    // AWS SigV4 test-suite "get-vanilla": GET / with host + x-amz-date, empty-payload hash.
    {
        CanonicalRequest req;
        req.method = "GET";
        req.uri = "/";
        req.query = "";
        req.headers = {{"host", "example.amazonaws.com"}, {"x-amz-date", "20150830T123600Z"}};
        req.payload_hash = sha256_hex("");
        const std::string authz =
            build_authorization(req, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1",
                                "service", "20150830T123600Z");
        check_eq(authz,
                 "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
                 "SignedHeaders=host;x-amz-date, "
                 "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31",
                 "get-vanilla authorization");
    }

    if (failures != 0) {
        std::cerr << failures << " SigV4 check(s) failed\n";
        return 1;
    }
    std::cout << "SigV4 vectors OK\n";
    return 0;
}
