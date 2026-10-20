#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yoav Bendor
#
# A statically linked s3put / s3cat (and libnanos3reader.a): libcurl, OpenSSL and zlib built static, libstdc++
# and libgcc linked in, a CA bundle compiled in. Only glibc stays shared. Built in an old-glibc image
# (manylinux2014: glibc 2.17), so the binaries run on any newer distribution:
#
#   docker run --rm -v "$PWD":/src -v "$PWD/.static-deps":/deps -v "$PWD/dist":/out \
#       quay.io/pypa/manylinux2014_x86_64 bash /src/ci/build_static.sh
#
# /deps caches the downloaded sources and the built dependencies between runs; /out receives
# s3put, s3cat, and nanos3reader-static-<version>-linux-x86_64.tar.gz (binaries, library, headers).

set -euo pipefail

SRC=${SRC:-/src}
DEPS=${DEPS:-/deps}
OUT=${OUT:-/out}
JOBS=$(nproc)
PREFIX="$DEPS/prefix"

ZLIB_VERSION=1.3.1
ZLIB_SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
OPENSSL_VERSION=3.0.15
OPENSSL_SHA256=23c666d0edf20f14249b3d8f0368acaee9ab585b09e1de82107c66e1f3ec9533
CURL_VERSION=8.10.1
CURL_SHA256=d15ebab765d793e2e96db090f0e172d127859d78ca6f6391d7eafecfd894bbc0
CACERT_DATE=2026-09-25
CACERT_SHA256=a41b5d356aea97a529fe27e0f7316d2f9d946d75927476cf9cf1b90637d00505

mkdir -p "$DEPS/src" "$OUT"

# OpenSSL's Configure needs IPC::Cmd, which the CentOS 7 based manylinux2014 image does not ship.
if ! perl -MIPC::Cmd -e1 2>/dev/null && command -v yum >/dev/null; then
    yum install -y -q perl-IPC-Cmd perl-Data-Dumper >/dev/null
fi

fetch() {  # url file sha256
    local url=$1 file="$DEPS/src/$2" sum=$3
    if [ ! -f "$file" ] || ! echo "$sum  $file" | sha256sum -c --quiet - 2>/dev/null; then
        curl -fsSL --retry 3 -o "$file.part" "$url"
        echo "$sum  $file.part" | sha256sum -c --quiet -
        mv "$file.part" "$file"
    fi
}

stamp="$PREFIX/.built-zlib-$ZLIB_VERSION-openssl-$OPENSSL_VERSION-curl-$CURL_VERSION"
if [ ! -f "$stamp" ]; then
    rm -rf "$PREFIX" "$DEPS/build"
    mkdir -p "$DEPS/build"
    fetch "https://zlib.net/fossils/zlib-$ZLIB_VERSION.tar.gz" zlib.tar.gz "$ZLIB_SHA256"
    fetch "https://github.com/openssl/openssl/releases/download/openssl-$OPENSSL_VERSION/openssl-$OPENSSL_VERSION.tar.gz" \
        openssl.tar.gz "$OPENSSL_SHA256"
    fetch "https://curl.se/download/curl-$CURL_VERSION.tar.gz" curl.tar.gz "$CURL_SHA256"

    cd "$DEPS/build" && tar xf "$DEPS/src/zlib.tar.gz" && cd "zlib-$ZLIB_VERSION"
    CFLAGS="-O2 -fPIC" ./configure --static --prefix="$PREFIX" >/dev/null
    make -j"$JOBS" >/dev/null && make install >/dev/null

    cd "$DEPS/build" && tar xf "$DEPS/src/openssl.tar.gz" && cd "openssl-$OPENSSL_VERSION"
    # openssldir /etc/ssl: the compiled-in default verify paths are the Debian/Ubuntu ones; nanos3reader
    # hands libcurl its CA certificates explicitly anyway (see tls_ca_source()).
    ./Configure linux-x86_64 no-shared no-tests no-module -fPIC \
        --prefix="$PREFIX" --libdir=lib --openssldir=/etc/ssl >/dev/null
    make -j"$JOBS" >/dev/null && make install_sw >/dev/null

    cd "$DEPS/build" && tar xf "$DEPS/src/curl.tar.gz" && cd "curl-$CURL_VERSION"
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$PREFIX" \
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON \
        -DBUILD_CURL_EXE=OFF -DBUILD_TESTING=OFF -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DENABLE_CURL_MANUAL=OFF \
        -DCURL_USE_OPENSSL=ON -DOPENSSL_ROOT_DIR="$PREFIX" -DOPENSSL_USE_STATIC_LIBS=ON -DZLIB_ROOT="$PREFIX" \
        -DCURL_USE_LIBPSL=OFF -DCURL_USE_LIBSSH2=OFF -DUSE_NGHTTP2=OFF -DCURL_BROTLI=OFF -DCURL_ZSTD=OFF \
        -DUSE_LIBIDN2=OFF -DCURL_DISABLE_LDAP=ON -DENABLE_ARES=OFF -DCURL_CA_BUNDLE=none -DCURL_CA_PATH=none \
        >/dev/null
    cmake --build build -j"$JOBS" >/dev/null && cmake --install build >/dev/null
    touch "$stamp"
fi
fetch "https://curl.se/ca/cacert-$CACERT_DATE.pem" "cacert-$CACERT_DATE.pem" "$CACERT_SHA256"

# nanos3reader itself: everything static but glibc.
rm -rf "$DEPS/nanos3reader-build"
cmake -S "$SRC" -B "$DEPS/nanos3reader-build" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_PREFIX_PATH="$PREFIX" -DCURL_DIR="$PREFIX/lib/cmake/CURL" \
    -DOPENSSL_ROOT_DIR="$PREFIX" -DOPENSSL_USE_STATIC_LIBS=ON -DZLIB_ROOT="$PREFIX" -DZLIB_USE_STATIC_LIBS=ON \
    -DNANOS3READER_CA_BUNDLE="$DEPS/src/cacert-$CACERT_DATE.pem" \
    -DNANOS3READER_BUILD_TESTS=ON -DNANOS3READER_BUILD_EXAMPLES=ON -DNANOS3READER_BUILD_TOOLS=ON \
    -DCMAKE_EXE_LINKER_FLAGS="-static-libstdc++ -static-libgcc" \
    -DCMAKE_INSTALL_PREFIX="$DEPS/nanos3reader-install"
cmake --build "$DEPS/nanos3reader-build" -j"$JOBS"
(cd "$DEPS/nanos3reader-build" && ctest --output-on-failure)
rm -rf "$DEPS/nanos3reader-install"
cmake --install "$DEPS/nanos3reader-build" >/dev/null

for exe in s3put s3cat; do
    cp "$DEPS/nanos3reader-build/$exe" "$OUT/$exe"
    strip "$OUT/$exe"
done

# Only glibc may stay shared.
for exe in s3put s3cat; do
    needed=$(readelf -d "$OUT/$exe" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p' | sort | tr '\n' ' ')
    echo "$exe NEEDED: $needed"
    for lib in $needed; do
        case "$lib" in
            libc.so.6|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|ld-linux-x86-64.so.2) ;;
            *) echo "error: $exe needs $lib (only glibc may be shared)"; exit 1 ;;
        esac
    done
    floor=$(objdump -T "$OUT/$exe" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1)
    echo "$exe glibc floor: $floor"
done

version=$("$OUT/s3put" --tls-info | sed -n 's/^s3put \([0-9.]*\):.*/\1/p')
pkg="nanos3reader-static-$version-linux-x86_64"
rm -rf "$DEPS/$pkg" && mkdir -p "$DEPS/$pkg/bin" "$DEPS/$pkg/lib"
cp "$OUT/s3put" "$OUT/s3cat" "$DEPS/$pkg/bin/"
cp -r "$DEPS/nanos3reader-install/include" "$DEPS/$pkg/"
cp "$(find "$DEPS/nanos3reader-install" -name libnanos3reader.a | head -1)" "$DEPS/$pkg/lib/"  # lib or lib64
# The libraries libnanos3reader.a needs, for linking it into another static binary.
for a in libcurl.a libssl.a libcrypto.a libz.a; do
    cp "$(find "$PREFIX" -name "$a" | head -1)" "$DEPS/$pkg/lib/"  # lib or lib64
done
cat > "$DEPS/$pkg/BUILD-INFO.txt" <<EOF
nanos3reader $version, statically linked (only glibc shared), built in manylinux2014 (glibc 2.17)
zlib $ZLIB_VERSION, OpenSSL $OPENSSL_VERSION, libcurl $CURL_VERSION
CA bundle compiled in: Mozilla's, curl.se/ca/cacert-$CACERT_DATE.pem (MPL-2.0), used only when none of
AWS_CA_BUNDLE / CURL_CA_BUNDLE / SSL_CERT_FILE / SSL_CERT_DIR is set and no system bundle is found.
Link: libnanos3reader.a libcurl.a libssl.a libcrypto.a libz.a -lpthread -ldl
EOF
tar czf "$OUT/$pkg.tar.gz" -C "$DEPS" "$pkg"
echo "built $OUT/$pkg.tar.gz"
