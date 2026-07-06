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
