#!/usr/bin/env python3
"""Disposable ONLY: Go-format fsynced first-WAL and independent birth index.

Published Xray is NOT instrumented. Synthetic records NEVER imply physical
byte transmission; tests use them solely to exercise fail-closed signed
Node STOP/prepare semantics, especially deleted or missing old WAL files.
"""
import hashlib
import json
import os
from pathlib import Path

import journal_integrity
import meter_inventory_audit

FIELDS=journal_integrity.METER_FIELDS
INVENTORY_FIELDS=meter_inventory_audit.FIELDS


def _append_synthetic_inventory(directory,record,filename):
    path=directory / meter_inventory_audit.NAME
    if path.exists():
        raw=path.read_bytes()
        if not raw.endswith(b"\n"):
            raise ValueError("synthetic pre-existing Xray index was torn")
        last=json.loads(raw[:-1].split(b"\n")[-1])
        sequence=last["sequence"]+1
        previous=last["digest"]
    else:
        sequence=1
        previous="0"*64
    entry={
        "schemaVersion":1,"sequence":sequence,
        "filename":filename,"runtimeId":record["runtimeId"],
        "email":record["email"],"direction":record["direction"],
        "firstWalDigest":record["digest"],"previousDigest":previous,
        "digest":"",
    }
    assert tuple(entry)==INVENTORY_FIELDS
    entry["digest"]=hashlib.sha256(
        journal_integrity._canonical_go(entry)).hexdigest()
    flags=os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW
    if sequence==1:flags|=os.O_CREAT|os.O_EXCL
    fd=os.open(path,flags,0o600)
    try:
        data=journal_integrity._canonical_go(entry)
        if os.write(fd,data)!=len(data):
            raise OSError("short synthetic index entry")
        os.fsync(fd)
    finally:
        os.close(fd)


def write_test_meter_intents(checkpoint,directory):
    directory=Path(directory)
    for row in checkpoint["inboundMeters"]:
        for direction in ("uplink","downlink"):
            total=row[direction+"Bytes"]
            if total==0:
                continue
            record={
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
            assert tuple(record)==FIELDS
            record["digest"]=hashlib.sha256(
                journal_integrity._canonical_go(record)).hexdigest()
            stem=hashlib.sha256((
                checkpoint["runtimeId"]+"\x00"+row["email"]+"\x00"+direction
            ).encode()).hexdigest()
            filename="meter-"+stem+".jsonl"
            path=directory/filename
            with path.open("xb") as sink:
                os.chmod(path,0o600)
                sink.write(journal_integrity._canonical_go(record))
                sink.flush()
                os.fsync(sink.fileno())
            # A fixture follows exactly the patched Xray safe ordering:
            # fsync WAL first, fsync independent inventory second, then a
            # file/dir fsync barrier before any hypothetical data transfer.
            _append_synthetic_inventory(directory,record,filename)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
