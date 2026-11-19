#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yoav Bendor
#
# Tests the static s3put / s3cat (ci/build_static.sh) inside a vanilla image -- no ca-certificates, nothing
# installed -- against an S3 server speaking TLS with a certificate from a test CA (moto, started by the
# caller on the host network):
#
#   docker run --rm --network host -v "$PWD/dist":/bin-under-test:ro -v "$PWD/tls":/tls:ro \
#       -e ENDPOINT=https://127.0.0.1:9443 -e BUCKET=... ubuntu:22.04 sh /src/ci/test_static.sh
#
# PUBLIC_TLS=1 also checks the compiled-in CA bundle against AWS S3 itself: a request with made-up
# credentials must get an HTTP answer (403), not a certificate error.

set -eu
B=/bin-under-test
: "${ENDPOINT:?}" "${BUCKET:?}"
export AWS_ACCESS_KEY_ID=testing AWS_SECRET_ACCESS_KEY=testing AWS_REGION=us-east-1
unset AWS_CA_BUNDLE CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR 2>/dev/null || true
fail() { echo "FAIL: $*"; exit 1; }

echo "== image: $(. /etc/os-release && echo "$PRETTY_NAME"), $(ldd --version 2>&1 | head -1)"
if [ -s /etc/ssl/certs/ca-certificates.crt ]; then fail "this image has a CA bundle; the test needs one without"; fi

# 1. With no CA variable and no system bundle, the compiled-in bundle is used.
"$B/s3put" --tls-info | tee /tmp/info
grep -q "compiled in" /tmp/info || fail "expected the compiled-in CA bundle"

# 2. The test server's certificate is not in the compiled-in (public) bundle: verification must fail, with
#    the hint, rather than the transfer going through unverified.
mkdir -p /tmp/tree/sub
echo hello > /tmp/tree/a.txt
head -c 7000000 /dev/urandom > /tmp/tree/sub/big.bin
: > /tmp/tree/sub/empty.bin
if AWS_ENDPOINT_URL="$ENDPOINT" "$B/s3put" -q /tmp/tree "s3://$BUCKET/untrusted/" 2>/tmp/err; then
    fail "an upload to a server with an untrusted certificate succeeded"
fi
grep -q "CA certificates: the bundle compiled in" /tmp/err || { cat /tmp/err; fail "no CA hint in the error"; }

# 3. SSL_CERT_FILE (and AWS_CA_BUNDLE) name the test CA: the tree goes up (multipart for big.bin) and reads back.
for var in SSL_CERT_FILE AWS_CA_BUNDLE; do
    prefix="s3://$BUCKET/$var-$(date +%s)"
    env "$var=/tls/ca.pem" AWS_ENDPOINT_URL="$ENDPOINT" \
        "$B/s3put" --multipart-threshold 5 --part-size 5 /tmp/tree "$prefix/" || fail "upload with $var"
    for f in a.txt sub/big.bin sub/empty.bin; do
        env "$var=/tls/ca.pem" AWS_ENDPOINT_URL="$ENDPOINT" "$B/s3cat" "$prefix/$f" > /tmp/back || fail "read back $f"
        cmp -s /tmp/back "/tmp/tree/$f" || fail "$f read back differs ($var)"
    done
    echo "ok: $var: uploaded and read back"
done

# 4. The compiled-in bundle against AWS itself.
if [ "${PUBLIC_TLS:-0}" = 1 ]; then
    if env -u AWS_ENDPOINT_URL "$B/s3put" /tmp/tree/a.txt "s3://nanos3reader-ci-tls-probe-$(date +%s)/a.txt" 2>/tmp/err; then
        fail "a put with made-up credentials succeeded"
    fi
    cat /tmp/err
    grep -q "HTTP 4" /tmp/err || fail "expected an HTTP 4xx from AWS (TLS verified), not a transport error"
    if grep -qi "ssl\|certificate" /tmp/err; then fail "TLS failed against AWS with the compiled-in bundle"; fi
    echo "ok: compiled-in bundle verified s3.amazonaws.com"
fi
echo "all static checks passed"
