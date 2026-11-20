#!/usr/bin/env python3
"""Disposable ONLY: deterministic Go-style first-delta byte WAL fixtures.

The live Xray physical-stop canary uses the published (UNINSTRUMENTED)
binary and must never claim synthetic byte WALs represent authentic
metered kernel transfers. These records exercise cryptographic and
crash-consistency verifier behavior only.
"""
import hashlib
import os
from pathlib import Path

import journal_integrity

FIELDS = journal_integrity.METER_FIELDS

def write_test_meter_intents(checkpoint, directory):
    directory = Path(directory)
    for row in checkpoint["inboundMeters"]:
        for direction in ("uplink","downlink"):
            total = row[direction+"Bytes"]
            if total == 0:
                continue
            record = {
                "schemaVersion":1,
                "runtimeId":checkpoint["runtimeId"],
                "email":row["email"],
                "direction":direction,
                "sequence":1,
                "previousBytes":0,
                "nextBytes":total,
                "previousDigest":"0"*64,
                "digest":"",
            }
            assert tuple(record) == FIELDS
            record["digest"]=hashlib.sha256(
                journal_integrity._canonical_go(record)).hexdigest()
            stem = hashlib.sha256((
                checkpoint["runtimeId"]+"\x00"+row["email"]+"\x00"+direction
            ).encode()).hexdigest()
            path = directory / ("meter-"+stem+".jsonl")
            with path.open("xb") as sink:
                os.chmod(path, 0o600)
                sink.write(journal_integrity._canonical_go(record))
                sink.flush()
                os.fsync(sink.fileno())
    fd=os.open(directory, os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
