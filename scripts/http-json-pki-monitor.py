#!/usr/bin/env python3
"""Run bounded PKI readiness checks and atomically publish aggregate status."""
from __future__ import annotations
import argparse, json, os, stat, subprocess, tempfile, time
from pathlib import Path
from http_json_integration_common import HTTPJSONIntegrationError, strict_json, valid_text

MAX_CONFIG=64*1024; MAX_IDENTITIES=4; CHECK_TIMEOUT=5

def config(path_value):
    path=Path(path_value)
    if not path.is_absolute(): raise HTTPJSONIntegrationError("monitor configuration path must be absolute")
    try: descriptor=os.open(path,os.O_RDONLY|getattr(os,"O_NOFOLLOW",0))
    except OSError as error: raise HTTPJSONIntegrationError("monitor configuration cannot be opened safely") from error
    try:
        metadata=os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_size>MAX_CONFIG or metadata.st_mode&0o022:
            raise HTTPJSONIntegrationError("monitor configuration boundary is unsafe")
        with os.fdopen(descriptor,"rb",closefd=False) as stream: raw=stream.read(MAX_CONFIG+1)
    finally: os.close(descriptor)
    value=strict_json(raw,"monitor configuration")
    fields={"schema_version","checker","openssl","credentials","renew_before_seconds"}
    if not isinstance(value,dict) or set(value)!=fields or value["schema_version"]!="telosieve.http-json-pki-monitor/v1":
        raise HTTPJSONIntegrationError("monitor configuration shape is invalid")
    if not isinstance(value["credentials"],list) or not 1<=len(value["credentials"])<=MAX_IDENTITIES:
        raise HTTPJSONIntegrationError("monitor credential count is invalid")
    if any(not isinstance(item,str) or not Path(item).is_absolute() for item in value["credentials"]):
        raise HTTPJSONIntegrationError("monitor credential path is invalid")
    if len(set(value["credentials"]))!=len(value["credentials"]): raise HTTPJSONIntegrationError("monitor credential path is duplicated")
    if not all(isinstance(value[field],str) and Path(value[field]).is_absolute() for field in ("checker","openssl")):
        raise HTTPJSONIntegrationError("monitor executable path is invalid")
    checker=Path(value["checker"])
    if checker.is_symlink() or not checker.is_file(): raise HTTPJSONIntegrationError("monitor checker is invalid")
    checker_metadata=checker.stat()
    if checker_metadata.st_nlink!=1 or checker_metadata.st_mode&0o022 or checker_metadata.st_mode&0o111==0:
        raise HTTPJSONIntegrationError("monitor checker boundary is unsafe")
    horizon=value["renew_before_seconds"]
    if not isinstance(horizon,int) or isinstance(horizon,bool) or not 0<=horizon<=30*24*3600:
        raise HTTPJSONIntegrationError("monitor renewal horizon is invalid")
    return value

def publish(path_value,payload):
    path=Path(path_value)
    if not path.is_absolute() or not path.parent.is_dir() or path.parent.is_symlink(): raise HTTPJSONIntegrationError("status path is invalid")
    if path.exists() or path.is_symlink():
        metadata=path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1 or metadata.st_mode&0o077:
            raise HTTPJSONIntegrationError("existing status boundary is unsafe")
    descriptor,raw=tempfile.mkstemp(prefix=f".{path.name}.",dir=path.parent)
    temporary=Path(raw)
    try:
        os.fchmod(descriptor,0o600)
        with os.fdopen(descriptor,"wb") as stream: stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary,path)
        directory=os.open(path.parent,os.O_RDONLY); os.fsync(directory); os.close(directory)
    finally: temporary.unlink(missing_ok=True)

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--config",required=True); parser.add_argument("--status",required=True); args=parser.parse_args()
    value=config(args.config); ready=0
    for credential in value["credentials"]:
        try:
            result=subprocess.run([value["checker"],"--openssl",value["openssl"],"--credentials",credential,
                "--renew-before-seconds",str(value["renew_before_seconds"])],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,check=False,timeout=CHECK_TIMEOUT,env={"LC_ALL":"C"})
            ready+=result.returncode==0
        except (OSError,subprocess.TimeoutExpired): pass
    payload={"schema_version":"telosieve.http-json-pki-monitor-status/v1","checked_at":int(time.time()),
        "identities":len(value["credentials"]),"ready":ready,"not_ready":len(value["credentials"])-ready,
        "renew_before_seconds":value["renew_before_seconds"],"secrets_disclosed":False,
        "status":"ready" if ready==len(value["credentials"]) else "not-ready"}
    encoded=json.dumps(payload,separators=(",",":")).encode()+b"\n"; publish(args.status,encoded); print(encoded.decode(),end="")
    return 0 if payload["status"]=="ready" else 1

if __name__=="__main__":
    try: raise SystemExit(main())
    except (HTTPJSONIntegrationError,OSError,subprocess.TimeoutExpired) as error: raise SystemExit(f"http-json-pki-monitor: {error}") from error
