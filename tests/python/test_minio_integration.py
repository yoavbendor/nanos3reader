#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yoav Bendor

"""MinIO integration tests for the Python bindings.

Requires a live S3-compatible endpoint and a seeded object (CI provides both via Docker MinIO):

  AWS_ENDPOINT_URL=http://localhost:9000
  NANOS3READER_IT_URI=s3://bucket/key
  NANOS3READER_IT_EXPECT=/path/to/local/copy
"""

import os
from pathlib import Path

import pytest

from nanos3reader import Factory, open

pytestmark = pytest.mark.skipif(
    not os.environ.get("NANOS3READER_IT_URI") or not os.environ.get("NANOS3READER_IT_EXPECT"),
    reason="set NANOS3READER_IT_URI and NANOS3READER_IT_EXPECT to run",
)


@pytest.fixture(scope="module")
def expected_bytes() -> bytes:
    path = Path(os.environ["NANOS3READER_IT_EXPECT"])
    data = path.read_bytes()
    assert data, "expected file is empty or unreadable"
    return data


@pytest.fixture(scope="module")
def uri() -> str:
    return os.environ["NANOS3READER_IT_URI"]


def test_full_read(uri: str, expected_bytes: bytes):
    with open(uri, read_ahead=4096) as reader:
        assert reader.read() == expected_bytes


def test_seek_and_slice(uri: str, expected_bytes: bytes):
    with open(uri) as reader:
        reader.seek(10)
        assert reader.read(50) == expected_bytes[10:60]
        assert reader.tell() == 60
        reader.seek(100)
        assert reader.read(50) == expected_bytes[100:150]


def test_factory_range_read(uri: str, expected_bytes: bytes):
    factory = Factory()
    with factory.open(uri, read_ahead=1024) as reader:
        n = len(expected_bytes)
        reader.seek(n // 3 + 7)
        assert reader.read(5000) == expected_bytes[n // 3 + 7 : n // 3 + 7 + 5000]


# ── Client.put (needs a writable prefix: NANOS3READER_IT_PUT_PREFIX=s3://bucket/prefix/) ────────────────

put_prefix = os.environ.get("NANOS3READER_IT_PUT_PREFIX")
needs_put_prefix = pytest.mark.skipif(not put_prefix, reason="set NANOS3READER_IT_PUT_PREFIX to run")


@pytest.fixture
def client():
    from nanos3reader import Client

    return Client(allow_http=True)  # endpoint and credentials from the environment, as the reader


@pytest.fixture
def key_prefix(request) -> str:
    return f"{put_prefix}py-{os.getpid()}-{request.node.name}/"


@needs_put_prefix
def test_put_and_read_back(client, key_prefix: str):
    body = os.urandom(2 * 1024 * 1024 + 17)
    uri = key_prefix + "blob.bin"
    etag = client.put(uri, body)
    assert etag.startswith('"') and etag.endswith('"')
    assert client.head(uri) == len(body)
    assert client.read_range(uri, 0, len(body)) == body
    assert client.read_range(uri, 1000, 10) == body[1000:1010]
    with open(uri, read_ahead=65536) as r:  # the stream reader sees the written object too
        assert r.read() == body


@needs_put_prefix
def test_put_overwrite_and_empty(client, key_prefix: str):
    uri = key_prefix + "x.txt"
    first = client.put(uri, b"one", content_type="text/plain")
    second = client.put(uri, b"two!")
    assert first != second
    assert client.read_range(uri, 0, 4) == b"two!"
    empty = key_prefix + "empty"
    client.put(empty, b"")
    assert client.head(empty) == 0


@needs_put_prefix
def test_conditional_put(client, key_prefix: str):
    from nanos3reader import PreconditionFailed, S3Error

    uri = key_prefix + "manifest.json"
    etag = client.put(uri, b'{"v": 1}', content_type="application/json", if_none_match=True)
    with pytest.raises(PreconditionFailed):
        client.put(uri, b'{"v": 2}', if_none_match=True)
    with pytest.raises(PreconditionFailed):
        client.put(uri, b'{"v": 2}', if_match='"00000000000000000000000000000000"')
    assert issubclass(PreconditionFailed, S3Error)
    client.put(uri, b'{"v": 2}', if_match=etag)
    assert client.read_range(uri, 0, 8) == b'{"v": 2}'


@needs_put_prefix
def test_put_errors(client):
    from nanos3reader import S3Error

    bucket = put_prefix[len("s3://"):].split("/", 1)[0]
    with pytest.raises(S3Error, match="HTTP 404"):
        client.put(f"s3://{bucket}-missing-{os.getpid()}/x", b"data")
    with pytest.raises(S3Error):
        client.put("not-a-uri", b"data")


@needs_put_prefix
def test_remove(client, key_prefix: str):
    import nanos3reader

    uri = key_prefix + "obj.bin"
    client.put(uri, b"x")
    assert client.head(uri) == 1
    client.remove(uri)
    with pytest.raises(nanos3reader.S3Error):
        client.head(uri)
    client.remove(uri)  # a missing object: not an error
