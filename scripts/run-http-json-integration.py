#!/usr/bin/env python3
"""Qualify Telosieve against orchestrated real HTTP endpoints."""
from __future__ import annotations
import http.client, json, os, pathlib, resource, ssl, subprocess, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
ADAPTER = (ROOT / "scripts/http-json-integration-adapter.py").resolve()
PRODUCER = (ROOT / "scripts/http-json-observation-producer.py").resolve()
PATH = "/v1/telosieve/snapshot"
LOAD_EVALUATIONS, LOAD_CONCURRENCY = 8, 4
TOKENS = {"adapter":"A"*32,"producer-a":"B"*32,"producer-b":"C"*32}
BASE_SNAPSHOT = {"schema_version":"telosieve.http-json-snapshot/v1","revision":"revision-81","complete":True,
                 "desired":{"cluster/epoch":"7","user/message":"new"},
                 "replicas":{name:{"cluster/epoch":"7","user/message":"old"} for name in ("replica-a","replica-b","replica-c")}}

class State:
    def __init__(self): self.lock=threading.Lock(); self.modes={token:"valid" for token in TOKENS.values()}; self.gets=0; self.mutations=0

class QualificationHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address): pass

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, *_): pass
    def _mutation(self):
        with self.server.state.lock: self.server.state.mutations += 1
        self.send_response(405); self.send_header("Content-Length","0"); self.end_headers()
    do_POST=_mutation; do_PUT=_mutation; do_PATCH=_mutation; do_DELETE=_mutation
    def do_GET(self):
        token=self.headers.get("Authorization","").removeprefix("Bearer ")
        with self.server.state.lock:
            mode=self.server.state.modes.get(token,"unauthorized"); self.server.state.gets += 1
        if self.path != PATH: mode="not-found"
        if mode=="timeout": time.sleep(2)
        if mode=="redirect":
            self.send_response(302); self.send_header("Location",PATH); self.send_header("Content-Length","0"); self.end_headers(); return
        if mode in {"unauthorized","not-found"}:
            self.send_response(401 if mode=="unauthorized" else 404); self.send_header("Content-Length","0"); self.end_headers(); return
        if mode=="malformed": body=b"{"
        elif mode=="oversized":
            self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(2*1024*1024+1)); self.end_headers(); return
        else:
            value=json.loads(json.dumps(BASE_SNAPSHOT))
            if mode=="incomplete": value["complete"]=False
            if mode=="disagreement": value["revision"]="revision-82"
            body=json.dumps(value,separators=(",",":")).encode()
        try:
            self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body)))
            self.send_header("Cache-Control","no-store"); self.end_headers(); self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError): pass

def run(args, *, success=True, timeout=10):
    result=subprocess.run(args,cwd=ROOT,capture_output=True,check=False,timeout=timeout)
    if (result.returncode==0)!=success: raise RuntimeError(f"http-json-e2e: unexpected exit {result.returncode}: {result.stderr.decode(errors='replace')[-4096:]}")
    return result

def credential(path, token):
    path.write_text(json.dumps({"schema_version":"telosieve.http-json-credentials/v1","bearer_token":token},separators=(",",":"))); path.chmod(0o600)

def producer_material(work,binary,port,credentials,transport="http"):
    keys=[]; sources=[]; configs=[]
    for index,name in enumerate(("producer-a","producer-b")):
        seed=("41" if index==0 else "42")*32; key=work/f"{name}.key"; key.write_text(seed); key.chmod(0o600)
        public=run([str(binary),"observation-public-key",str(key)]).stdout.decode().strip()
        domain=f"http-reader-{name[-1]}"
        keys.append({"producer":name,"key_id":f"key-{name[-1]}","fault_domain":domain,"public_key":public,
                     "not_before":1750000000,"not_after":1750001000})
        config=work/f"{name}.json"; config.write_text(json.dumps({"host":"127.0.0.1","port":port,"path":PATH,"transport":transport,
            "credentials":str(credentials[index]),"integration_id":"http-json","resource_kind":"replicated-key-value",
            "target_id":"http/qualification","subject":"kv/research","evaluation_time":1750000000,
            "telosieve":str(binary),"key":str(key),"producer":name,"key_id":f"key-{name[-1]}","domain":domain,
            "issued":1750000000,"expires":1750000300},separators=(",",":")))
        configs.append(config); sources.append({"executable_path":str(PRODUCER),"arguments":["--config",str(config)]})
    trust=work/"trust.json"; trust.write_text(json.dumps({"schema_version":"telosieve.observation-trust/v1",
        "evaluation_time":1750000100,"required_distinct_domains":2,"keys":keys},separators=(",",":")))
    return trust,sources,configs

def make_config(work,binary,port,credentials,stem,transport="http"):
    trust,sources,producer_configs=producer_material(work,binary,port,credentials[1:],transport)
    value={"schema_version":"telosieve.evaluation-config/v7","mode":"external-read-only",
        "scenario_path":str((ROOT/"scenarios/benign.json").resolve()),"certificate_path":str(work/f"{stem}-certificate.json"),
        "ledger_path":str(work/f"{stem}-ledger.jsonl"),"observation_trust_path":str(trust),"observation_sources":sources,
        "adapter":{"executable_path":str(ADAPTER),"arguments":["--host","127.0.0.1","--port",str(port),"--path",PATH,"--transport",transport,
          "--credentials",str(credentials[0])],"integration_id":"http-json","resource_kind":"replicated-key-value",
          "target_id":"http/qualification"}}
    path=work/f"{stem}-evaluation.json"; path.write_text(json.dumps(value,separators=(",",":")))
    return path,value,producer_configs

def certificates(work):
    openssl="openssl"
    def command(*args): run([openssl,*args],timeout=10)
    ca_key=work/"ca.key"; ca=work/"ca.pem"; rogue_key=work/"rogue-ca.key"; rogue_ca=work/"rogue-ca.pem"
    command("req","-x509","-newkey","rsa:2048","-nodes","-subj","/CN=Telosieve Qualification CA","-days","1","-keyout",str(ca_key),"-out",str(ca))
    command("req","-x509","-newkey","rsa:2048","-nodes","-subj","/CN=Rogue Qualification CA","-days","1","-keyout",str(rogue_key),"-out",str(rogue_ca))
    extensions=work/"server.ext"; extensions.write_text("subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n")
    def signed(name,authority,authority_key,usage):
        key=work/f"{name}.key"; csr=work/f"{name}.csr"; certificate=work/f"{name}.pem"
        command("req","-new","-newkey","rsa:2048","-nodes","-subj",f"/CN={name}","-keyout",str(key),"-out",str(csr))
        ext=extensions if usage=="serverAuth" else work/f"{name}.ext"
        if usage!="serverAuth": ext.write_text("extendedKeyUsage=clientAuth\n")
        command("x509","-req","-in",str(csr),"-CA",str(authority),"-CAkey",str(authority_key),"-CAcreateserial","-days","1","-extfile",str(ext),"-out",str(certificate))
        key.chmod(0o600); return certificate,key
    server_pair=signed("server",ca,ca_key,"serverAuth")
    clients={name:signed(f"mtls-client-{name}",ca,ca_key,"clientAuth") for name in TOKENS}
    clients["rogue"]=signed("mtls-client-rogue",rogue_ca,rogue_key,"clientAuth")
    ca_key.chmod(0o600); rogue_key.chmod(0o600)
    return ca,rogue_ca,server_pair,clients

def tls_credential(path,token,ca,certificate,key):
    path.write_text(json.dumps({"schema_version":"telosieve.http-json-mtls-credentials/v1","bearer_token":token,
        "ca_certificate":str(ca),"client_certificate":str(certificate),"client_key":str(key)},separators=(",",":"))); path.chmod(0o600)

def main():
    binary=(ROOT/"target/debug/telosieve").resolve()
    if not binary.is_file(): raise SystemExit("http-json-e2e: build target/debug/telosieve first")
    started=time.monotonic(); state=State(); server=QualificationHTTPServer(("127.0.0.1",0),Handler); server.state=state
    server.daemon_threads=True; thread=threading.Thread(target=server.serve_forever); thread.start()
    failures=0
    try:
      with tempfile.TemporaryDirectory(prefix="telosieve-http-json-e2e-") as raw:
        work=pathlib.Path(raw); credentials=[]
        for name in ("adapter","producer-a","producer-b"):
            path=work/f"{name}-credential.json"; credential(path,TOKENS[name]); credentials.append(path)
        config_path,base,producer_configs=make_config(work,binary,server.server_port,credentials,"valid")
        report=json.loads(run([str(binary),"evaluate",str(config_path)]).stdout)
        certificate=json.loads((work/"valid-certificate.json").read_bytes())
        if report["target_mutated"] or certificate["integration"]["target_revision"]!="revision-81": raise RuntimeError("http-json-e2e: invalid success")
        def evaluate_case(index):
            case=work/f"load-{index}"; case.mkdir(); value=json.loads(json.dumps(base)); value["certificate_path"]=str(case/"certificate.json"); value["ledger_path"]=str(case/"ledger.jsonl")
            path=case/"evaluation.json"; path.write_text(json.dumps(value)); run([str(binary),"evaluate",str(path)])
        load_started=time.monotonic()
        with ThreadPoolExecutor(max_workers=LOAD_CONCURRENCY) as pool:
            for future in [pool.submit(evaluate_case,i) for i in range(LOAD_EVALUATIONS)]: future.result(timeout=20)
        load_elapsed=time.monotonic()-load_started
        denied=0
        for method in ("POST","PUT","PATCH","DELETE"):
            connection=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=1)
            connection.request(method,PATH,body=b"{}",headers={"Authorization":f"Bearer {TOKENS['adapter']}"})
            if connection.getresponse().status!=405: raise RuntimeError("http-json-e2e: mutation method was not denied")
            connection.close(); denied+=1
        def fault(stem,token=None,mode=None,config=None):
            nonlocal failures
            if token:
                with state.lock: state.modes[token]=mode
            try:
                value=json.loads(json.dumps(config or base)); value["certificate_path"]=str(work/f"{stem}-certificate.json"); value["ledger_path"]=str(work/f"{stem}-ledger.jsonl")
                path=work/f"{stem}-evaluation.json"; path.write_text(json.dumps(value)); run([str(binary),"evaluate",str(path)],success=False)
                if (work/f"{stem}-certificate.json").exists() or (work/f"{stem}-ledger.jsonl").exists(): raise RuntimeError(f"http-json-e2e: {stem} emitted evidence")
            finally:
                if token:
                    with state.lock: state.modes[token]="valid"
            failures+=1
        for stem,mode in (("redirect","redirect"),("malformed","malformed"),("oversized","oversized"),("incomplete","incomplete"),("timeout","timeout")):
            fault(stem,TOKENS["adapter"],mode)
        fault("unauthorized",TOKENS["adapter"],"unauthorized")
        fault("producer-disagreement",TOKENS["producer-a"],"disagreement")
        server.shutdown(); server.server_close(); thread.join(timeout=3)
        fault("outage")
        ca,rogue_ca,(server_cert,server_key),clients=certificates(work)
        state=State(); server=QualificationHTTPServer(("127.0.0.1",0),Handler); server.state=state; server.daemon_threads=True
        server_context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server_context.minimum_version=ssl.TLSVersion.TLSv1_3
        server_context.maximum_version=ssl.TLSVersion.TLSv1_3; server_context.verify_mode=ssl.CERT_REQUIRED
        server_context.load_cert_chain(server_cert,server_key); server_context.load_verify_locations(cafile=ca)
        server.socket=server_context.wrap_socket(server.socket,server_side=True)
        thread=threading.Thread(target=server.serve_forever); thread.start()
        tls_credentials=[]
        for name in ("adapter","producer-a","producer-b"):
            path=work/f"mtls-{name}-credential.json"; tls_credential(path,TOKENS[name],ca,*clients[name]); tls_credentials.append(path)
        tls_path,tls_base,tls_producer_configs=make_config(work,binary,server.server_port,tls_credentials,"mtls-valid","https")
        tls_report=json.loads(run([str(binary),"evaluate",str(tls_path)]).stdout)
        if tls_report["target_mutated"]: raise RuntimeError("http-json-e2e: mTLS success reported mutation")
        client_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); client_context.minimum_version=ssl.TLSVersion.TLSv1_3
        client_context.maximum_version=ssl.TLSVersion.TLSv1_3; client_context.load_verify_locations(cafile=ca)
        client_context.load_cert_chain(*clients["adapter"])
        tls_denied=0
        for method in ("POST","PUT","PATCH","DELETE"):
            connection=http.client.HTTPSConnection("127.0.0.1",server.server_port,timeout=1,context=client_context)
            connection.request(method,PATH,body=b"{}",headers={"Authorization":f"Bearer {TOKENS['adapter']}"})
            if connection.getresponse().status!=405: raise RuntimeError("http-json-e2e: mTLS mutation method was not denied")
            connection.close(); tls_denied+=1
        original=tls_credentials[0].read_text()
        bad=json.loads(original); bad["ca_certificate"]=str(rogue_ca); tls_credentials[0].write_text(json.dumps(bad))
        try: fault("mtls-wrong-ca",config=tls_base)
        finally: tls_credentials[0].write_text(original)
        bad=json.loads(original); bad["client_key"]=str(work/"missing.key"); tls_credentials[0].write_text(json.dumps(bad))
        try: fault("mtls-missing-key",config=tls_base)
        finally: tls_credentials[0].write_text(original)
        clients["adapter"][1].chmod(0o644)
        try: fault("mtls-unsafe-key-permissions",config=tls_base)
        finally: clients["adapter"][1].chmod(0o600)
        bad=json.loads(original); bad["client_certificate"]=str(clients["rogue"][0]); bad["client_key"]=str(clients["rogue"][1]); tls_credentials[0].write_text(json.dumps(bad))
        try: fault("mtls-untrusted-client",config=tls_base)
        finally: tls_credentials[0].write_text(original)
        downgrade=json.loads(json.dumps(tls_base)); arguments=downgrade["adapter"]["arguments"]
        arguments[arguments.index("https")]="http"; fault("mtls-plaintext-downgrade",config=downgrade)
        fault("mtls-producer-disagreement",TOKENS["producer-a"],"disagreement",tls_base)
        fault("mtls-timeout",TOKENS["adapter"],"timeout",tls_base)
        server.shutdown(); server.server_close(); thread.join(timeout=3); fault("mtls-outage",config=tls_base)
        elapsed=time.monotonic()-started; peak=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        if os.uname().sysname=="Linux": peak*=1024
        if elapsed>60 or load_elapsed>20 or thread.is_alive(): raise RuntimeError("http-json-e2e: resource or cleanup bound exceeded")
        print(json.dumps({"schema_version":"telosieve.http-json-integration-qualification/v2","transports":["http/1.1","https-tls1.3-mtls"],
          "orchestrated_endpoints":True,"external_endpoints":False,"loopback_only":True,"bearer_identities":3,
          "mtls_client_identities":3,"mutation_methods_refused":denied+tls_denied,"observation_producers":2,"separate_control_planes":False,
          "successful_evaluations":2,"load_evaluations":LOAD_EVALUATIONS,"load_concurrency":LOAD_CONCURRENCY,
          "load_elapsed_seconds":round(load_elapsed,3),"fail_closed_evaluations":failures,"target_mutated":False,
          "elapsed_seconds":round(elapsed,3),"peak_child_rss_bytes":peak,"independent_evidence":False,"status":"passed"},separators=(",",":")))
    finally:
      try: server.shutdown(); server.server_close()
      except Exception: pass
      thread.join(timeout=3)

if __name__=="__main__": main()
