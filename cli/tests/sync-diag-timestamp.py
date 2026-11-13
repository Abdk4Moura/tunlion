#!/usr/bin/env python3
"""Tee each complete line with its UTC observation time to a diagnostic file."""
import datetime
import sys

with open(sys.argv[1], "w", buffering=1) as log:
    for line in sys.stdin:
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")
        log.write(f"{now} {line}")
        sys.stdout.write(line)
        sys.stdout.flush()
