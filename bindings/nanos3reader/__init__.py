# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yoav Bendor

"""Python bindings for nanos3reader — a minimal, read-only S3 range reader."""

from nanos3reader._nanos3reader import (
    Factory,
    OpenError,
    Reader,
    configure_disk_cache,
    disk_cache_stats,
    open,
)

__all__ = [
    "Factory",
    "OpenError",
    "Reader",
    "configure_disk_cache",
    "disk_cache_stats",
    "open",
]

__version__ = "0.3.0"
