#!/usr/bin/env python3
"""Independent old-PID verifier for CI-only fsynced WAL birth index.

A local listing of existing meter-*.jsonl cannot detect deleting an old
byte-bearing file. Every first-WAL fsync must also append and fsync an
independent hash-chained *birth* registry before traffic can leave Xray.
This code reads actual root-owned files from a trusted Docker bind mount.
It does NOT prove off-host deletion or final transport byte delivery.
"""
import hashlib
import json
import os
import re
import stat

NAME="xmesh-meter-inventory-v1.jsonl"
FIELDS=("schemaVersion","sequence","filename","runtimeId","email",
        "direction","firstWalDigest","previousDigest","digest")
NOFOLLOW=getattr(os,"O_NOFOLLOW",0)
CLOEXEC=getattr(os,"O_CLOEXEC",0)
MAX_BYTES=64 << 20
MAX_ENTRIES=4096
HEX64=re.compile(r"[0-9a-f]{64}\Z")
EMAIL=re.compile(r"xmesh-u([1-9][0-9]{0,18})--([^\x00-\x20>]{1,128})\Z")


def strict_pairs(pairs):
    data={}
    for key,value in pairs:
        if key in data:
            raise ValueError("duplicate old-Xray WAL inventory JSON property")
        data[key]=value
    return data


def _read_inventory(dfd):
    try:
        before=os.stat(NAME,dir_fd=dfd,follow_symlinks=False)
    except FileNotFoundError:
        return None
    if (not stat.S_ISREG(before.st_mode) or
            stat.S_IMODE(before.st_mode)!=0o600 or
            before.st_uid!=os.geteuid() or before.st_nlink!=1 or
            not 0<before.st_size<=MAX_BYTES):
        raise ValueError("unsafe indexed old-Xray WAL registry inode")
    fd=os.open(NAME,os.O_RDONLY|NOFOLLOW|CLOEXEC,dir_fd=dfd)
    try:
        opened=os.fstat(fd)
        if ((opened.st_dev,opened.st_ino,opened.st_size)!=
                (before.st_dev,before.st_ino,before.st_size)):
            raise ValueError("old-Xray byte registry replaced during open")
        chunks=[]
        length=0
        while length<before.st_size:
            chunk=os.read(fd,min(65536,before.st_size-length))
            if not chunk:break
            chunks.append(chunk)
            length+=len(chunk)
        raw=b"".join(chunks)
        after=os.stat(NAME,dir_fd=dfd,follow_symlinks=False)
        if (len(raw)!=before.st_size or not raw.endswith(b"\n") or
                (after.st_dev,after.st_ino,after.st_size)!=
                (before.st_dev,before.st_ino,before.st_size)):
            raise ValueError("crash-torn or replaced indexed Xray WAL inventory")
        return raw
    finally:
        os.close(fd)


def verify_meter_inventory(dfd,seen_wal_names,read_wal,canonical):
    """Cross-check complete prior-WAL directory list against durable births.

    Returns (registered entries, independently reread WAL tuples), so the
    Node's signed STOP digest can bind a user's exact index entries plus
    exact validated WAL byte-hashes without ever trusting an HTTP claim.
    """
    if not isinstance(seen_wal_names,list) or len(seen_wal_names)>MAX_ENTRIES:
        raise ValueError("unbounded old-Xray byte WAL scan")
    raw=_read_inventory(dfd)
    if raw is None:
        if seen_wal_names:
            raise ValueError("old-Xray meter journal exists without birth index")
        return {},{}
    lines=raw[:-1].split(b"\n")
    if not 0<len(lines)<=MAX_ENTRIES:
        raise ValueError("unbounded meter-index entries")
    entries={}
    previous="0"*64
    for i,line in enumerate(lines):
        if not 0<len(line)<=1024:
            raise ValueError("noncanonical old-Xray WAL inventory length")
        try:
            step=json.loads(line.decode("utf-8"),object_pairs_hook=strict_pairs,
                            parse_constant=lambda _: (_ for _ in ()).throw(
                                ValueError("invalid indexed Xray meter counter")))
        except (ValueError,UnicodeDecodeError) as exc:
            raise ValueError("invalid Xray WAL index JSON") from exc
        if (not isinstance(step,dict) or tuple(step)!=FIELDS or
                canonical(step)!=line+b"\n" or
                type(step["schemaVersion"]) is not int or
                step["schemaVersion"]!=1 or
                type(step["sequence"]) is not int or
                step["sequence"]!=i+1 or
                step["previousDigest"]!=previous):
            raise ValueError("old-Xray WAL inventory canonical hash chain lost")
        filename=step["filename"]
        run=step["runtimeId"]
        email=step["email"]
        direction=step["direction"]
        digest=step["digest"]
        first=step["firstWalDigest"]
        if (not isinstance(run,str) or HEX64.fullmatch(run) is None or
                not isinstance(email,str) or EMAIL.fullmatch(email) is None or
                any(c in email for c in "<>&") or
                direction not in ("uplink","downlink") or
                not isinstance(digest,str) or HEX64.fullmatch(digest) is None or
                not isinstance(first,str) or HEX64.fullmatch(first) is None or
                not isinstance(filename,str)):
            raise ValueError("unsafe old-Xray WAL index scope")
        want="meter-"+hashlib.sha256(
            (run+"\x00"+email+"\x00"+direction).encode("utf-8")
        ).hexdigest()+".jsonl"
        if filename!=want or filename in entries:
            raise ValueError("old-Xray indexed WAL filename replay or mismatch")
        base=dict(step)
        base["digest"]=""
        if digest!=hashlib.sha256(canonical(base)).hexdigest():
            raise ValueError("Xray indexed WAL birth chain changed")
        entries[filename]=step
        previous=digest
    if set(entries)!=set(seen_wal_names):
        raise ValueError("missing previously fsynced or unindexed old-Xray WAL")
    wal={}
    for name in sorted(entries):
        last,content_digest,first_digest=read_wal(dfd,name)
        birth=entries[name]
        if (last["runtimeId"]!=birth["runtimeId"] or
                last["email"]!=birth["email"] or
                last["direction"]!=birth["direction"] or
                first_digest!=birth["firstWalDigest"]):
            raise ValueError("Xray WAL birth does not match indexed first byte")
        wal[name]=(last,content_digest,first_digest)
    return entries,wal
