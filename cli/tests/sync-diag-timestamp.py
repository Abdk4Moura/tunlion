#!/usr/bin/env python3
"""Tee bytes immediately, timestamping each line even if it never completes."""
import datetime
import os
import sys

with open(sys.argv[1], "wb", buffering=0) as log:
    start = True
    while chunk := os.read(0, 65536):
        for part in chunk.splitlines(keepends=True):
            if start:
                now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
                log.write(f"{now} ".encode())
            log.write(part)
            start = part.endswith(b"\n")
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
