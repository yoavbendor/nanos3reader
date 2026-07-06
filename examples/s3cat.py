#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yoav Bendor

# s3cat — minimal nanos3reader Python example: open an s3:// URI and write a byte range to stdout.
#
#   python examples/s3cat.py s3://bucket/key [offset] [length]
#
# Credentials/region/endpoint come from the environment and ~/.aws exactly like the AWS tools
# (AWS_PROFILE, AWS_REGION, AWS_ENDPOINT_URL for MinIO, etc.).

import sys

from nanos3reader import open as s3_open


def main() -> int:
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} s3://bucket/key [offset] [length]", file=sys.stderr)
        return 2

    uri = sys.argv[1]
    offset = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    length = int(sys.argv[3]) if len(sys.argv) > 3 else 0  # 0 = to EOF

    try:
        with s3_open(uri) as reader:
            if offset:
                reader.seek(offset)
            if length:
                sys.stdout.buffer.write(reader.read(length))
            elif offset:
                sys.stdout.buffer.write(reader.read())
            else:
                sys.stdout.buffer.write(reader.read())
    except Exception as exc:
        print(f"open/read failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
