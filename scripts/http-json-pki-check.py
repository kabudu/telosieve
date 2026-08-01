#!/usr/bin/env python3
"""Offline readiness check for HTTP/JSON mutual-TLS credentials."""
from __future__ import annotations
import argparse, datetime, json, os, stat, subprocess, tempfile
from pathlib import Path
from http_json_integration_common import HTTPJSONIntegrationError, credential_value

MAX_OUTPUT=16*1024; TIMEOUT=3; MAX_HORIZON=30*24*3600

def executable(value):
    path=Path(value)
    if not path.is_absolute() or path.is_symlink() or not path.is_file(): raise HTTPJSONIntegrationError("OpenSSL executable is invalid")
    metadata=path.stat()
    if metadata.st_nlink!=1 or metadata.st_mode&0o022 or metadata.st_mode&0o111==0: raise HTTPJSONIntegrationError("OpenSSL executable boundary is unsafe")
    return path

def command(binary,args,output=False):
    with tempfile.TemporaryFile() as stdout,tempfile.TemporaryFile() as stderr:
        try: result=subprocess.run([str(binary),*args],stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
            env={"LC_ALL":"C"},check=False,timeout=TIMEOUT)
        except subprocess.TimeoutExpired as error: raise HTTPJSONIntegrationError("PKI check timed out") from error
        if result.returncode or stdout.tell()>MAX_OUTPUT or stderr.tell()>MAX_OUTPUT: raise HTTPJSONIntegrationError("PKI material failed validation")
        if output: stdout.seek(0); return stdout.read(MAX_OUTPUT+1)
    return b""

def main():
    parser=argparse.ArgumentParser(); parser.add_argument("--openssl",required=True); parser.add_argument("--credentials",required=True)
    parser.add_argument("--renew-before-seconds",type=int,default=7*24*3600); args=parser.parse_args()
    if not 0<=args.renew_before_seconds<=MAX_HORIZON: raise HTTPJSONIntegrationError("renewal horizon is invalid")
    binary=executable(args.openssl); material=credential_value(args.credentials,True)
    ca=material["ca_certificate"]; crl=material["certificate_revocation_list"]
    certificate=material["client_certificate"]; key=material["client_key"]
    command(binary,["x509","-in",ca,"-noout","-checkend",str(args.renew_before_seconds)])
    command(binary,["x509","-in",certificate,"-noout","-checkend",str(args.renew_before_seconds)])
    command(binary,["crl","-in",crl,"-noout","-verify","-CAfile",ca])
    raw=command(binary,["crl","-in",crl,"-noout","-nextupdate"],True).decode("ascii").strip()
    if not raw.startswith("nextUpdate="): raise HTTPJSONIntegrationError("CRL nextUpdate is invalid")
    try: next_update=datetime.datetime.strptime(raw.removeprefix("nextUpdate="),"%b %d %H:%M:%S %Y GMT").replace(tzinfo=datetime.timezone.utc)
    except ValueError as error: raise HTTPJSONIntegrationError("CRL nextUpdate is invalid") from error
    if next_update<=datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=args.renew_before_seconds):
        raise HTTPJSONIntegrationError("CRL expires inside renewal horizon")
    command(binary,["verify","-CAfile",ca,"-CRLfile",crl,"-crl_check","-purpose","sslclient",certificate])
    certificate_public=command(binary,["x509","-in",certificate,"-noout","-pubkey"],True)
    key_public=command(binary,["pkey","-in",key,"-pubout"],True)
    if certificate_public!=key_public: raise HTTPJSONIntegrationError("client certificate and key do not match")
    print(json.dumps({"schema_version":"telosieve.http-json-pki-readiness/v1","tls_version":"1.3",
        "ca_verified":True,"crl_verified":True,"client_verified":True,"key_pair_verified":True,
        "renew_before_seconds":args.renew_before_seconds,"secrets_disclosed":False,"status":"ready"},separators=(",",":")))
    return 0

if __name__=="__main__":
    try: raise SystemExit(main())
    except (HTTPJSONIntegrationError,OSError,UnicodeDecodeError) as error: raise SystemExit(f"http-json-pki-check: {error}") from error
