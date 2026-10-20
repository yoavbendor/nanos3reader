# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Yoav Bendor

"""Python bindings for nanos3reader — a minimal S3 range reader and client (HEAD, range reads, PUT)."""

from nanos3reader._nanos3reader import (
    Client,
    Factory,
    OpenError,
    PreconditionFailed,
    Reader,
    S3Error,
    configure_disk_cache,
    disk_cache_stats,
    open,
)

__all__ = [
    "Client",
    "Factory",
    "OpenError",
    "PreconditionFailed",
    "Reader",
    "S3Error",
    "configure_disk_cache",
    "disk_cache_stats",
    "open",
]

__version__ = "0.5.0"
