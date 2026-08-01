#!/usr/bin/env python3
"""Qualify Telosieve against a disposable real PostgreSQL server."""
from __future__ import annotations
import json, os, pathlib, resource, shutil, subprocess, tempfile, threading, time
from concurrent.futures import ThreadPoolExecutor

ROOT = pathlib.Path(__file__).resolve().parents[1]
IMAGE = "postgres@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
PSQL = pathlib.Path("/opt/homebrew/opt/libpq/bin/psql").resolve()
ADAPTER = (ROOT / "scripts/postgresql-integration-adapter.py").resolve()
PRODUCER = (ROOT / "scripts/postgresql-observation-producer.py").resolve()
SCHEMA = "telosieve_state"
DATABASE = "postgres"
LOAD_EVALUATIONS, LOAD_CONCURRENCY = 8, 4

def run(args, *, input_bytes=None, success=True, timeout=30, env=None):
    result = subprocess.run(args, cwd=ROOT, input=input_bytes, capture_output=True,
                            check=False, timeout=timeout, env=env)
    if (result.returncode == 0) != success:
        raise RuntimeError(f"postgresql-e2e: unexpected exit {result.returncode}: {args[0]}\n"
                           + result.stderr.decode(errors="replace")[-4096:])
    return result

def credential(path, username, password):
    path.write_text(json.dumps({"schema_version": "telosieve.postgresql-credentials/v1",
                                "username": username, "password": password}, separators=(",", ":")))
    path.chmod(0o600)

def sql(port, username, password, statement, *, success=True, timeout=10):
    with tempfile.TemporaryDirectory(prefix="telosieve-postgresql-admin-") as raw:
        passfile = pathlib.Path(raw) / "pgpass"
        passfile.write_text(f"127.0.0.1:{port}:{DATABASE}:{username}:{password}\n"); passfile.chmod(0o600)
        return run([str(PSQL), "--no-psqlrc", "--quiet", "--set", "ON_ERROR_STOP=1",
                    "--host", "127.0.0.1", "--port", str(port), "--dbname", DATABASE,
                    "--username", username], input_bytes=statement.encode(), success=success,
                   timeout=timeout, env={"LC_ALL": "C", "PGPASSFILE": str(passfile),
                                         "PGCONNECT_TIMEOUT": "1"})

def producer_material(work, binary, port, credentials):
    specs = (("producer-a", "key-a", "postgresql-reader-a", "31"*32),
             ("producer-b", "key-b", "postgresql-reader-b", "32"*32))
    keys, sources, configs = [], [], []
    for index, (producer, key_id, domain, seed) in enumerate(specs):
        key = work / f"{producer}.key"; key.write_text(seed); key.chmod(0o600)
        public = run([str(binary), "observation-public-key", str(key)]).stdout.decode().strip()
        keys.append({"producer": producer, "key_id": key_id, "fault_domain": domain,
                     "public_key": public, "not_before": 1750000000, "not_after": 1750001000})
        config = work / f"{producer}.json"
        config.write_text(json.dumps({"psql": str(PSQL), "host": "127.0.0.1", "port": port,
            "database": DATABASE, "credentials": str(credentials[index]), "schema": SCHEMA,
            "integration_id": "postgresql", "resource_kind": "replicated-key-value",
            "target_id": "postgresql/qualification", "subject": "kv/research",
            "evaluation_time": 1750000000, "telosieve": str(binary), "key": str(key),
            "producer": producer, "key_id": key_id, "domain": domain,
            "issued": 1750000000, "expires": 1750000300}, separators=(",", ":")))
        configs.append(config)
        sources.append({"executable_path": str(PRODUCER), "arguments": ["--config", str(config)]})
    trust = work / "trust.json"
    trust.write_text(json.dumps({"schema_version": "telosieve.observation-trust/v1",
        "evaluation_time": 1750000100, "required_distinct_domains": 2, "keys": keys}, separators=(",", ":")))
    return trust, sources, configs

def make_config(work, binary, port, adapter_credential, producer_credentials, stem):
    trust, sources, producer_configs = producer_material(work, binary, port, producer_credentials)
    value = {"schema_version": "telosieve.evaluation-config/v7", "mode": "external-read-only",
        "scenario_path": str((ROOT / "scenarios/benign.json").resolve()),
        "certificate_path": str(work / f"{stem}-certificate.json"),
        "ledger_path": str(work / f"{stem}-ledger.jsonl"),
        "observation_trust_path": str(trust), "observation_sources": sources,
        "adapter": {"executable_path": str(ADAPTER), "arguments": ["--psql", str(PSQL),
            "--host", "127.0.0.1", "--port", str(port), "--database", DATABASE,
            "--credentials", str(adapter_credential), "--schema", SCHEMA],
            "integration_id": "postgresql", "resource_kind": "replicated-key-value",
            "target_id": "postgresql/qualification"}}
    path = work / f"{stem}-evaluation.json"; path.write_text(json.dumps(value, separators=(",", ":")))
    return path, value, producer_configs

def assert_no_evidence(work, binary, path, stem):
    run([str(binary), "evaluate", str(path)], success=False, timeout=10)
    if (work/f"{stem}-certificate.json").exists() or (work/f"{stem}-ledger.jsonl").exists():
        raise RuntimeError(f"postgresql-e2e: {stem} emitted evidence")

def setup_sql(passwords):
    roles = "\n".join(
        f"CREATE ROLE {role} LOGIN PASSWORD '{passwords[role]}'; "
        f"ALTER ROLE {role} SET default_transaction_read_only=on; "
        f"ALTER ROLE {role} SET statement_timeout='2s';"
        for role in ("reader_adapter", "reader_producer_a", "reader_producer_b"))
    grants = "\n".join(
        f"GRANT CONNECT ON DATABASE postgres TO {role}; GRANT USAGE ON SCHEMA {SCHEMA} TO {role}; GRANT SELECT ON ALL TABLES IN SCHEMA {SCHEMA} TO {role};"
        for role in ("reader_adapter", "reader_producer_a", "reader_producer_b"))
    return f"""
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC; REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA {SCHEMA}; CREATE SCHEMA secret_state;
CREATE TABLE {SCHEMA}.metadata(singleton boolean PRIMARY KEY CHECK(singleton),revision text NOT NULL);
CREATE TABLE {SCHEMA}.desired(key text PRIMARY KEY,value text NOT NULL);
CREATE TABLE {SCHEMA}.replicas(replica_id text PRIMARY KEY);
CREATE TABLE {SCHEMA}.observed(replica_id text REFERENCES {SCHEMA}.replicas, key text, value text NOT NULL, PRIMARY KEY(replica_id,key));
CREATE TABLE secret_state.must_not_read(value text); INSERT INTO secret_state.must_not_read VALUES('secret');
INSERT INTO {SCHEMA}.metadata VALUES(true,'revision-73');
INSERT INTO {SCHEMA}.desired VALUES('cluster/epoch','7'),('user/message','new');
INSERT INTO {SCHEMA}.replicas VALUES('replica-a'),('replica-b'),('replica-c');
INSERT INTO {SCHEMA}.observed SELECT replica_id,key,value FROM {SCHEMA}.replicas CROSS JOIN (VALUES('cluster/epoch','7'),('user/message','old')) v(key,value);
{roles}\n{grants}
CREATE SCHEMA telosieve_disagreement;
CREATE TABLE telosieve_disagreement.metadata (LIKE {SCHEMA}.metadata INCLUDING ALL);
CREATE TABLE telosieve_disagreement.desired (LIKE {SCHEMA}.desired INCLUDING ALL);
CREATE TABLE telosieve_disagreement.replicas (LIKE {SCHEMA}.replicas INCLUDING ALL);
CREATE TABLE telosieve_disagreement.observed (LIKE {SCHEMA}.observed INCLUDING ALL);
INSERT INTO telosieve_disagreement.metadata VALUES(true,'revision-74');
INSERT INTO telosieve_disagreement.desired SELECT * FROM {SCHEMA}.desired;
INSERT INTO telosieve_disagreement.replicas SELECT * FROM {SCHEMA}.replicas;
INSERT INTO telosieve_disagreement.observed SELECT * FROM {SCHEMA}.observed;
GRANT USAGE ON SCHEMA telosieve_disagreement TO reader_producer_a;
GRANT SELECT ON ALL TABLES IN SCHEMA telosieve_disagreement TO reader_producer_a;
"""

def main():
    if not PSQL.is_file() or shutil.which("docker") is None: raise SystemExit("postgresql-e2e: psql and docker are required")
    binary = (ROOT/"target/debug/telosieve").resolve()
    if not binary.is_file(): raise SystemExit("postgresql-e2e: build target/debug/telosieve first")
    run(["docker", "image", "inspect", IMAGE])
    started=time.monotonic(); container=f"telosieve-postgresql-{os.getpid()}"; created=False
    passwords={"postgres":"A"*32,"reader_adapter":"B"*32,"reader_producer_a":"C"*32,"reader_producer_b":"D"*32}
    try:
      with tempfile.TemporaryDirectory(prefix="telosieve-postgresql-e2e-") as raw:
        work=pathlib.Path(raw)
        run(["docker","run","--detach","--rm","--name",container,"--read-only","--user","70:70",
             "--tmpfs","/var/lib/postgresql:rw,noexec,nosuid,size=128m,uid=70,gid=70,mode=700",
             "--tmpfs","/var/run/postgresql:rw,noexec,nosuid,size=1m,uid=70,gid=70,mode=700",
             "--tmpfs","/tmp:rw,noexec,nosuid,size=16m,uid=70,gid=70,mode=700",
             "--cap-drop=ALL","--security-opt","no-new-privileges","--memory","256m","--pids-limit","128","--cpus","1",
             "--publish","127.0.0.1::5432","--env",f"POSTGRES_PASSWORD={passwords['postgres']}",IMAGE])
        created=True; port=int(run(["docker","port",container,"5432/tcp"]).stdout.decode().strip().rsplit(":",1)[1])
        deadline=time.monotonic()+10
        while True:
            try:
                if sql(port,"postgres",passwords["postgres"],"SELECT 1;").returncode==0: break
            except Exception:
                if time.monotonic()>=deadline: raise
                time.sleep(.1)
        sql(port,"postgres",passwords["postgres"],setup_sql(passwords))
        credential_paths=[]
        for role in ("reader_adapter","reader_producer_a","reader_producer_b"):
            path=work/f"{role}.json"; credential(path,role,passwords[role]); credential_paths.append(path)
        denied=("INSERT INTO telosieve_state.desired VALUES('x','y');",
                "UPDATE telosieve_state.desired SET value='x';","DELETE FROM telosieve_state.desired;",
                "CREATE TABLE telosieve_state.forbidden(x int);","DROP TABLE telosieve_state.desired;",
                "SELECT * FROM secret_state.must_not_read;")
        for statement in denied: sql(port,"reader_adapter",passwords["reader_adapter"],statement,success=False)
        config_path,base,producer_configs=make_config(work,binary,port,credential_paths[0],credential_paths[1:],"valid")
        result=run([str(binary),"evaluate",str(config_path)],timeout=10); report=json.loads(result.stdout)
        certificate=json.loads((work/"valid-certificate.json").read_bytes())
        if report["target_mutated"] or certificate["integration"]["target_revision"]!="revision-73": raise RuntimeError("postgresql-e2e: invalid success")
        def load(index):
            case=work/f"load-{index}"; case.mkdir(); value=json.loads(json.dumps(base))
            value["certificate_path"]=str(case/"certificate.json"); value["ledger_path"]=str(case/"ledger.jsonl")
            path=case/"evaluation.json"; path.write_text(json.dumps(value)); run([str(binary),"evaluate",str(path)],timeout=10)
        load_started=time.monotonic()
        with ThreadPoolExecutor(max_workers=LOAD_CONCURRENCY) as pool:
            for future in [pool.submit(load,i) for i in range(LOAD_EVALUATIONS)]: future.result(timeout=30)
        load_elapsed=time.monotonic()-load_started
        writer_errors=[]
        def writer():
            try:
                for _ in range(8):
                    sql(port,"postgres",passwords["postgres"],
                        f"BEGIN; UPDATE {SCHEMA}.desired SET value='tampered' WHERE key='user/message'; "
                        f"UPDATE {SCHEMA}.metadata SET revision='race-bad'; COMMIT;")
                    time.sleep(.02)
                    sql(port,"postgres",passwords["postgres"],
                        f"BEGIN; UPDATE {SCHEMA}.desired SET value='new' WHERE key='user/message'; "
                        f"UPDATE {SCHEMA}.metadata SET revision='revision-73'; COMMIT;")
                    time.sleep(.02)
            except BaseException as error:
                writer_errors.append(error)
        writer_thread=threading.Thread(target=writer); writer_thread.start(); race_refusals=0
        for index in range(4):
            case=work/f"race-{index}"; case.mkdir(); value=json.loads(json.dumps(base))
            value["certificate_path"]=str(case/"certificate.json"); value["ledger_path"]=str(case/"ledger.jsonl")
            path=case/"evaluation.json"; path.write_text(json.dumps(value))
            raced=subprocess.run([str(binary),"evaluate",str(path)],cwd=ROOT,capture_output=True,check=False,timeout=10)
            if raced.returncode==0:
                if json.loads(raced.stdout)["target_mutated"] or not (case/"certificate.json").is_file():
                    raise RuntimeError("postgresql-e2e: race success evidence is invalid")
            else:
                race_refusals+=1
                if (case/"certificate.json").exists() or (case/"ledger.jsonl").exists():
                    raise RuntimeError("postgresql-e2e: race refusal emitted evidence")
        writer_thread.join(timeout=10)
        if writer_thread.is_alive() or writer_errors: raise RuntimeError("postgresql-e2e: writer failed or exceeded deadline")
        sql(port,"postgres",passwords["postgres"],
            f"UPDATE {SCHEMA}.desired SET value='new' WHERE key='user/message'; UPDATE {SCHEMA}.metadata SET revision='revision-73';")
        failures=0
        def fault(stem,value):
            nonlocal failures
            value["certificate_path"]=str(work/f"{stem}-certificate.json"); value["ledger_path"]=str(work/f"{stem}-ledger.jsonl")
            path=work/f"{stem}-evaluation.json"; path.write_text(json.dumps(value)); assert_no_evidence(work,binary,path,stem); failures+=1
        unsafe=json.loads(json.dumps(base)); credential_paths[0].chmod(0o644)
        try: fault("unsafe-credential",unsafe)
        finally: credential_paths[0].chmod(0o600)
        sql(port,"postgres",passwords["postgres"],"ALTER ROLE reader_adapter NOLOGIN;")
        try: fault("revoked",json.loads(json.dumps(base)))
        finally: sql(port,"postgres",passwords["postgres"],"ALTER ROLE reader_adapter LOGIN;")
        extra=",".join(f"('extra-{i}')" for i in range(62)); sql(port,"postgres",passwords["postgres"],f"INSERT INTO {SCHEMA}.replicas VALUES {extra};")
        try: fault("oversized",json.loads(json.dumps(base)))
        finally: sql(port,"postgres",passwords["postgres"],f"DELETE FROM {SCHEMA}.replicas WHERE replica_id LIKE 'extra-%';")
        disagree=json.loads(json.dumps(base)); pc=json.loads(producer_configs[0].read_text()); pc["schema"]="telosieve_disagreement"; producer_configs[0].write_text(json.dumps(pc))
        try: fault("disagreement",disagree)
        finally: pc["schema"]=SCHEMA; producer_configs[0].write_text(json.dumps(pc))
        stale=json.loads(json.dumps(base)); pc=json.loads(producer_configs[0].read_text()); pc["issued"]=1749999900; producer_configs[0].write_text(json.dumps(pc))
        try: fault("stale",stale)
        finally: pc["issued"]=1750000000; producer_configs[0].write_text(json.dumps(pc))
        locker=threading.Thread(target=lambda: sql(port,"postgres",passwords["postgres"],f"BEGIN; LOCK TABLE {SCHEMA}.metadata IN ACCESS EXCLUSIVE MODE; SELECT pg_sleep(2); COMMIT;",timeout=5))
        locker.start(); time.sleep(.2); fault("lock-timeout",json.loads(json.dumps(base))); locker.join(timeout=5)
        run(["docker","stop","--time","1",container]); created=False
        fault("outage",json.loads(json.dumps(base)))
        elapsed=time.monotonic()-started; peak=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
        if os.uname().sysname=="Linux": peak*=1024
        if elapsed>90 or load_elapsed>30: raise RuntimeError("postgresql-e2e: resource bound exceeded")
        print(json.dumps({"schema_version":"telosieve.postgresql-integration-qualification/v1",
          "postgresql_version":"18.4","libpq_version":"18.1","image":IMAGE,"real_database":True,
          "loopback_only":True,"read_only_roles":3,"forbidden_operations_refused":len(denied),
          "observation_producers":2,"separate_control_planes":False,"successful_evaluations":1,
          "load_evaluations":LOAD_EVALUATIONS,"load_concurrency":LOAD_CONCURRENCY,
          "load_elapsed_seconds":round(load_elapsed,3),"race_evaluations":4,
          "race_refusals":race_refusals,"fail_closed_evaluations":failures,
          "target_mutated":False,"elapsed_seconds":round(elapsed,3),"peak_child_rss_bytes":peak,
          "independent_evidence":False,"status":"passed"},separators=(",",":")))
    finally:
      if created: subprocess.run(["docker","stop","--time","1",container],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False,timeout=5)

if __name__=="__main__": main()
