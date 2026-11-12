#!/usr/bin/env python3
"""
Scenario 5 Trial 0-R -- Autonomous Two-Stage Recovery Pilot Harness (revision 3)

Black-box traffic generation plus passive, read-only observation of the deployed controller.
The harness never modifies controller state, never calls controller functions, and never
patches VirtualServices or Leases. All recovery transitions must be produced autonomously by
the long-running defender daemon (PID 1, uvicorn defender:app).

Revision 3 changes (reviewer "final four corrections" + security audit hardening):
  1. ML replay authentication: per-request HMAC-SHA256 signatures (#ts=, #sig=). The shared key
     is never transmitted or logged. REQUIRES the proposed defender patch
     (SCENARIO_5_PROPOSED_REPLAY_HMAC_PATCH.diff). A preflight gate aborts before any traffic
     is sent unless the deployed defender reports replay_auth_mode == "hmac-sha256-v2" and its
     key hash matches the Kubernetes Secret. Attribution (BOTH / RPS_ONLY) and ML authorization
     are recorded from controller logs.
  2. Decoy telemetry: /decoy-stats counter deltas measured inside the decoy pod with
     time.monotonic(); matched attacker request IDs taken from the decoy request buffer.
     (The kubectl-log set-difference method is removed.)
  3. Continuous benign traffic: one tagged benign generator runs from Phase A start until
     10 s after the Stage 2 transition; every request is recorded (JSONL) and the record count is
     reconciled against the generator's own sent counter.
  4. Strict verification: the final status is PASSED only if every critical assertion holds
     (see build_checklist()). Any exception or timeout preserves partial evidence and is
     followed by a read-only cluster audit.

Timing notes (derived from deployed cic-v5.3 source, not assumed):
  * Recovery checks run 60 s after mitigation (DDOS_REVERT_SECONDS=60) and every 60 s thereafter.
  * check_decoy_abatement() needs K=2 distinct non-overlapping windows. Because the decoy is
    still active at the Stage 1 check, the window counter resets there; the first qualifying
    window is recorded at Stage1+60 s and the second at Stage1+120 s. Stage 2 is therefore
    expected roughly 100 s after the attacker is stopped, so the Phase C timeout is 170 s
    (the previous 75 s timeout would have produced a false failure).
  * Polling cadence: 300 ms sleep + one SSH/kubectl round trip per poll (measured and recorded
    per poll as poll_interval_s; not assumed to be 350 ms).
  * Reference clock: the cluster VM (date +%s.%N), returned in the same SSH call as each poll.
    Pod-to-VM clock skew is measured in preflight and must be < 0.5 s.

Trust boundary: traffic is East-West, sent from in-mesh client pods directly to
http://details:9080. The x-trusted-client-ip header is supplied by the test client. This trial does
NOT exercise or validate Istio Ingress Gateway header sanitization.

Telemetry demarcation: Phase A ML inference uses authenticated CIC-IDS2017 replay feature vectors
carried in x-request-id and parsed from Envoy access logs. Volumetric detection uses live
Envoy/Prometheus request rates (> 15 RPS). Phase B/C attacker traffic carries no replay vector.
"""

import base64
import datetime
import hashlib
import hmac
import json
import math
import os
import re
import sys
import time
import traceback

import paramiko

sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
SSH_HOST = os.getenv("SSH_HOST", "192.168.160.129")
SSH_USER = os.getenv("SSH_USER", "osu")
SSH_PASS = os.getenv("SSH_PASS")
SSH_KEY = os.getenv("SSH_KEY")

NS = "default"
TARGET = "details"
DEFENDER = "deployment/ddos-defender-details"
DECOY = "deployment/details-decoy"
ATTACKER_POD = "client-attacker"
BENIGN_POD = "client-benign"
ATTACKER_IDENTITY = "10.244.0.131"
FEAT_DETAILS = "4.0,3.0,239.0,0.0,59.75,0.0,0.75"
REQUIRED_REPLAY_AUTH_MODE = "hmac-sha256-v2"

EXPECTED_LEASES = {
    "details-dataset-mitigation-lock", "details-mitigation-lock",
    "product-canary-mitigation-lock", "product-mitigation-lock",
    "ratings-dataset-mitigation-lock", "ratings-decoy-mitigation-lock", "ratings-mitigation-lock",
    "reviews-dataset-mitigation-lock", "reviews-decoy-mitigation-lock", "reviews-mitigation-lock",
}
SIBLINGS = ["bookinfo", "reviews", "ratings"]  # names of the other VirtualServices in the testbed

PHASE_A_RATE_RPS = 25.0
PHASE_A_SIGNED_REQUESTS = 375          # up to 15 s at 25 RPS; generator is stopped at quarantine commit
PHASE_B_RATE_RPS = 5.0
BENIGN_RATE_RPS = 4.0
POLL_SLEEP_S = 0.300
PHASE_A_TIMEOUT_S = 20.0
STAGE1_TIMEOUT_S = 90.0                # measured from Phase A commit (expected ~60 s)
ANTI_OSC_HOLD_S = 15.0
DECOY_MEASURE_S = 5.0
STAGE2_TIMEOUT_S = 170.0               # measured from attacker stop (expected ~100 s)
POST_STAGE2_BENIGN_S = 10.0
MAX_CLOCK_SKEW_S = 0.5
TRANSITION_COVERAGE_S = 2.0            # benign requests must exist within +/- this of each transition
MIN_BENIGN_IN_COVERAGE = 4
BENIGN_MIN_SUCCESS_RATE = 0.95         # reviewer-visible threshold; reported, not hidden

RAW_DIR = "PAPER/Backup/SCENARIO_5_PILOT_RESULTS/raw_trial_0R"


class CommandExecutionError(RuntimeError):
    pass


class InvalidKubernetesResponseError(ValueError):
    pass


class PreflightGateError(RuntimeError):
    pass


# ------------------------------------------------------------------------------
# SSH helpers (exit status checked, stderr captured)
# ------------------------------------------------------------------------------
if not SSH_PASS and not SSH_KEY:
    raise SystemExit("Set SSH_PASS or SSH_KEY. No credential fallbacks are provided.")

# Strict Host Key Verification (rejects unknown/unverified host keys)
KNOWN_HOST_KEY_ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIDwJXIiNCBAeT9k44sEljUxhJAh+YQXfymsl/pTBTjEf"
KNOWN_HOST_KEY_RSA = "AAAAB3NzaC1yc2EAAAADAQABAAABgQC+VU3i7qVE4LvCtmfoRam5y25HrbiYvTLXb+g9t9WC/z/Xceawf0oo049FtHTjq3zvr/5COVrb5OvIRWOE9Z3EXiNJ79X+d//CVII9S6HdZsnrdeLiokjt/tG66hkbblODae7PrbSv91Nm7R4K3KB1cfYn0Md6vp8YWGEm+L0KOVDqZRXAemYR7TmUGjEnDvGzTuzEeSls44YOANIxTXKw6GegaAff1RAiF24yZUnMsJUjvpNV+VMmcnxjMEBqPEKWdPqgAGCusT6RgrZnqO/xsmtCGYh3lpkVOQ6xDZ5eaS4EqYL7/l+NEJ7lOXbUDv6yXzxnkLUpIGqzbtqGc3wZepXg9voWEOEXiumSkL3JiPwkAnBDTDsNCgAVkvrkMDVjYGigXHBZ/lU/xVLk0vsPcfT1R1D42VdRWetkYkb3If932fNqRGwme6Du0X5TVfW9AyhHl2PPpl4hKpSfmz5ffIdtl4DORST6bBevCRD7HmgY+GFM6cNeXW1C4XeikiM="

ssh = paramiko.SSHClient()
ssh.get_host_keys().add(SSH_HOST, "ssh-ed25519", paramiko.Ed25519Key(data=base64.b64decode(KNOWN_HOST_KEY_ED25519)))
ssh.get_host_keys().add(SSH_HOST, "ssh-rsa", paramiko.RSAKey(data=base64.b64decode(KNOWN_HOST_KEY_RSA)))
ssh.set_missing_host_key_policy(paramiko.RejectPolicy())

_kw = {"hostname": SSH_HOST, "username": SSH_USER, "timeout": 15}
if SSH_KEY:
    _kw["key_filename"] = SSH_KEY
if SSH_PASS:
    _kw["password"] = SSH_PASS
ssh.connect(**_kw)


def run_ssh_checked(cmd: str, timeout: int = 60, check: bool = True, stdin_data: str = None) -> tuple[str, str, int]:
    """
    Executes a command via Paramiko SSH, safely drains both stdout and stderr channel buffers
    to prevent window deadlocks on large outputs, captures return code, and raises on error.
    """
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    if stdin_data is not None:
        stdin.write(stdin_data)
        stdin.channel.shutdown_write()

    channel = stdout.channel
    out_chunks = []
    err_chunks = []
    start_t = time.time()

    while True:
        if channel.recv_ready():
            chunk = channel.recv(65536)
            if chunk:
                out_chunks.append(chunk)

        if channel.recv_stderr_ready():
            chunk = channel.recv_stderr(65536)
            if chunk:
                err_chunks.append(chunk)

        if channel.exit_status_ready():
            while channel.recv_ready():
                c = channel.recv(65536)
                if c:
                    out_chunks.append(c)
            while channel.recv_stderr_ready():
                c = channel.recv_stderr(65536)
                if c:
                    err_chunks.append(c)
            break

        if time.time() - start_t > timeout:
            channel.close()
            raise TimeoutError(f"Command timed out after {timeout}s: {cmd[:200]!r}")

        time.sleep(0.01)

    rc = channel.recv_exit_status()
    out = b"".join(out_chunks).decode("utf-8", errors="ignore").strip()
    err = b"".join(err_chunks).decode("utf-8", errors="ignore").strip()

    if check and rc != 0:
        raise CommandExecutionError(f"rc={rc} cmd={cmd[:200]!r} stderr={err[:800]!r}")
    return out, err, rc


def run_ssh(cmd, timeout=60, stdin_data=None):
    return run_ssh_checked(cmd, timeout=timeout, stdin_data=stdin_data)[0]


def pod_python(target, code, container=None, timeout=60):
    """Runs a Python snippet inside a pod; the snippet is passed on stdin (no shell quoting)."""
    c = f" -c {container}" if container else ""
    return run_ssh(f"kubectl exec -i -n {NS} {target}{c} -- python -", timeout=timeout, stdin_data=code)


# ------------------------------------------------------------------------------
# Kubernetes read-only accessors with schema validation
# ------------------------------------------------------------------------------
def _parse(out, kind, name):
    try:
        data = json.loads(out)
    except Exception as e:
        raise InvalidKubernetesResponseError(f"{kind} {name}: unparseable JSON ({e})")
    if data.get("kind") != kind:
        raise InvalidKubernetesResponseError(f"{name}: expected kind {kind}, got {data.get('kind')}")
    return data


def get_vs_with_clock(name=TARGET):
    """Returns (vm_epoch, VirtualService) from a single SSH round trip."""
    out = run_ssh(f"date +%s.%N && kubectl get virtualservice {name} -n {NS} -o json")
    first, _, rest = out.partition("\n")
    vs = _parse(rest, "VirtualService", name)
    http = vs.get("spec", {}).get("http")
    if not isinstance(http, list) or not http:
        raise InvalidKubernetesResponseError(f"VirtualService {name}: spec.http missing or empty")
    return float(first.strip()), vs


def get_vs(name):
    return get_vs_with_clock(name)[1]


def get_lease(name):
    return _parse(run_ssh(f"kubectl get lease {name} -n {NS} -o json"), "Lease", name)


def get_all_leases():
    data = _parse(run_ssh(f"kubectl get leases -n {NS} -o json"), "List", "leases") \
        if '"kind": "List"' in (raw := run_ssh(f"kubectl get leases -n {NS} -o json")) \
        else _parse(raw, "LeaseList", "leases")
    return {i["metadata"]["name"]: i.get("spec", {}).get("holderIdentity") for i in data.get("items", [])}


def vm_now():
    return float(run_ssh("date +%s.%N"))


# ------------------------------------------------------------------------------
# Routing interpretation
# ------------------------------------------------------------------------------
def describe_routes(vs):
    http = vs["spec"]["http"]
    q_idx = [i for i, r in enumerate(http) if r.get("name") == "quarantine-malicious"]
    q_rule = http[q_idx[0]] if q_idx else None
    prod = next((r for r in http if r.get("name") != "quarantine-malicious"), None)
    prod_routes = sorted(
        (d.get("destination", {}).get("subset"), d.get("weight", 100 if len(prod.get("route", [])) == 1 else 0))
        for d in (prod or {}).get("route", [])
    )
    q_dest_hosts = [d.get("destination", {}).get("host", "") for d in (q_rule or {}).get("route", [])]
    q_match = json.dumps((q_rule or {}).get("match", []), sort_keys=True)
    return {
        "resource_version": vs["metadata"].get("resourceVersion"),
        "fencing_token": vs["metadata"].get("annotations", {}).get("ddos.defender/fencing-token"),
        "n_rules": len(http),
        "quarantine_present": bool(q_idx),
        "quarantine_index": q_idx[0] if q_idx else None,
        "quarantine_to_decoy": any(f"{TARGET}-decoy" in h for h in q_dest_hosts),
        "quarantine_matches_attacker": ATTACKER_IDENTITY in q_match,
        "production_routes": prod_routes,
    }


def state_key(d):
    return (d["quarantine_present"], tuple(map(tuple, d["production_routes"])))


# ------------------------------------------------------------------------------
# Evidence containers
# ------------------------------------------------------------------------------
timeline, transitions, polls = [], [], []
evidence = {
    "trial_id": "0-R",
    "harness_revision": 3,
    "target_service": TARGET,
    "status": "INITIALIZING",
    "trust_boundary": ("East-West in-mesh traffic to http://details:9080; x-trusted-client-ip supplied by the "
                       "test client. Istio Ingress Gateway sanitization is NOT exercised."),
    "telemetry_demarcation": {
        "ml_inference": "Authenticated (HMAC-SHA256) CIC-IDS2017 replay vectors in x-request-id, parsed from Envoy access logs",
        "volumetric_detection": "Live Envoy/Prometheus request rate (threshold 15 RPS)",
        "phase_B_C_attacker": "Plain HTTP requests without replay vectors",
    },
    "reference_clock": "cluster VM epoch (date +%s.%N)",
    "timeline": timeline,
    "routing_transitions": transitions,
    "poll_cadence": {},
}


def log_event(name, phase, details=None, t_vm=None):
    entry = {"event": name, "phase": phase,
             "t_vm": t_vm if t_vm is not None else vm_now(),
             "utc_harness": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "details": details or {}}
    timeline.append(entry)
    print(f"[{entry['utc_harness']}] [{phase}] {name}")
    for k, v in (details or {}).items():
        print(f"    - {k}: {v}")
    return entry


_last_poll_t = [None]


def poll(phase):
    t_vm, vs = get_vs_with_clock(TARGET)
    d = describe_routes(vs)
    interval = None if _last_poll_t[0] is None else round(t_vm - _last_poll_t[0], 3)
    _last_poll_t[0] = t_vm
    polls.append({"t_vm": t_vm, "phase": phase, "interval_s": interval, "rv": d["resource_version"]})
    if not transitions or transitions[-1]["resource_version"] != d["resource_version"]:
        transitions.append({"t_vm": t_vm, "phase": phase, **d})
    return t_vm, vs, d


# ------------------------------------------------------------------------------
# Client-side generators (uploaded as files; launched with nohup; PIDs captured)
# ------------------------------------------------------------------------------
BENIGN_SCRIPT = f"""
import urllib.request, urllib.error, time, json, uuid, os
OUT, STOP = '/tmp/s5r_benign.jsonl', '/tmp/s5r_benign.stop'
period = 1.0 / {BENIGN_RATE_RPS}
sent = 0
with open(OUT, 'w', buffering=1) as out:
    while not os.path.exists(STOP):
        rid = 's5r-ben-%d-%s' % (sent, uuid.uuid4().hex[:6])
        req = urllib.request.Request('http://details:9080/details/0',
                                     headers={{'x-request-id': rid, 'x-client-type': 'benign'}})
        m0 = time.monotonic()
        rec = {{'rid': rid, 't_send': time.time()}}
        try:
            with urllib.request.urlopen(req, timeout=2) as r:
                r.read()
                rec['status'] = r.status
                rec['served_by_decoy'] = r.headers.get('X-Decoy-Service') is not None
        except urllib.error.HTTPError as e:
            rec['status'] = e.code
            rec['served_by_decoy'] = e.headers.get('X-Decoy-Service') is not None if e.headers else False
            rec['err'] = 'HTTPError'
        except Exception as e:
            rec['status'] = None
            rec['served_by_decoy'] = False
            rec['err'] = (type(e).__name__ + ': ' + str(e))[:160]
        rec['lat_ms'] = round((time.monotonic() - m0) * 1000.0, 3)
        out.write(json.dumps(rec) + '\\n')
        sent += 1
        time.sleep(max(0.0, period - (time.monotonic() - m0)))
    out.write(json.dumps({{'summary': True, 'sent': sent}}) + '\\n')
"""

ATTACK_A_SCRIPT = f"""
import urllib.request, time, os, json
STOP = '/tmp/s5r_atkA.stop'
period = 1.0 / {PHASE_A_RATE_RPS}
rids = [l.strip() for l in open('/tmp/s5r_phaseA_rids.txt') if l.strip()]
sent = 0
for rid in rids:
    if os.path.exists(STOP):
        break
    m0 = time.monotonic()
    req = urllib.request.Request('http://details:9080/details/0', headers={{
        'x-request-id': rid, 'x-trusted-client-ip': '{ATTACKER_IDENTITY}', 'x-bench-attack': 'details'}})
    try:
        with urllib.request.urlopen(req, timeout=2) as r: r.read()
    except Exception:
        pass
    sent += 1
    time.sleep(max(0.0, period - (time.monotonic() - m0)))
json.dump({{'sent': sent}}, open('/tmp/s5r_atkA_summary.json', 'w'))
"""

ATTACK_B_SCRIPT = f"""
import urllib.request, time, os, json
STOP = '/tmp/s5r_atkB.stop'
period = 1.0 / {PHASE_B_RATE_RPS}
sent = 0
while not os.path.exists(STOP):
    m0 = time.monotonic()
    req = urllib.request.Request('http://details:9080/details/0', headers={{
        'x-request-id': 's5r-atk-B-%d' % sent, 'x-trusted-client-ip': '{ATTACKER_IDENTITY}',
        'x-bench-attack': 'details'}})
    try:
        with urllib.request.urlopen(req, timeout=2) as r: r.read()
    except Exception:
        pass
    sent += 1
    time.sleep(max(0.0, period - (time.monotonic() - m0)))
json.dump({{'sent': sent, 't_stop': time.time()}}, open('/tmp/s5r_atkB_summary.json', 'w'))
"""

DECOY_MEASURE_SCRIPT = f"""
import urllib.request, json, time
def g():
    return json.loads(urllib.request.urlopen('http://localhost:8080/decoy-stats', timeout=3).read())
w0 = time.time(); m0 = time.monotonic(); s0 = g()
time.sleep({DECOY_MEASURE_S})
s1 = g(); m1 = time.monotonic(); w1 = time.time()
matched = [e for e in s1.get('recent_attacker_logs', [])
           if w0 <= e.get('timestamp', 0) < w1 and str(e.get('request_id', '')).startswith('s5r-atk-B-')]
d_att = s1['attacker_requests'] - s0['attacker_requests']
print(json.dumps({{
    'wall_start': w0, 'wall_end': w1,
    'attacker_counter_before': s0['attacker_requests'], 'attacker_counter_after': s1['attacker_requests'],
    'benign_counter_before': s0['benign_requests'], 'benign_counter_after': s1['benign_requests'],
    'monotonic_elapsed_s': m1 - m0,
    'attacker_delta': d_att,
    'benign_delta': s1['benign_requests'] - s0['benign_requests'],
    'attacker_rps': d_att / (m1 - m0),
    'matched_request_ids': [e['request_id'] for e in matched],
    'matched_count': len(matched),
}}))
"""

DECOY_COUNTERS_SCRIPT = """
import urllib.request, json, time
s = json.loads(urllib.request.urlopen('http://localhost:8080/decoy-stats', timeout=3).read())
print(json.dumps({'t': time.time(), 'attacker_requests': s['attacker_requests'], 'benign_requests': s['benign_requests']}))
"""


def upload(pod, path, content):
    run_ssh(f"kubectl exec -i -n {NS} {pod} -- sh -c 'cat > {path}'", stdin_data=content)


def launch(pod, script_path, log_path):
    pid = run_ssh(f"kubectl exec -n {NS} {pod} -- sh -c 'nohup python {script_path} > {log_path} 2>&1 & echo $!'")
    if not pid.strip().isdigit():
        raise CommandExecutionError(f"could not obtain PID for {script_path} on {pod}: {pid!r}")
    return int(pid.strip())


def is_process_terminated(pod, pid):
    """
    Checks if a process has terminated. In containers where PID 1 does not reap children,
    terminated processes become zombies (State: Z). Both non-existent PIDs (kill -0 fails)
    and zombies indicate that the target generator process has stopped executing.
    """
    cmd = f"kubectl exec -n {NS} {pod} -- sh -c '! kill -0 {pid} 2>/dev/null || grep -q \"State:.*[ZX]\" /proc/{pid}/status 2>/dev/null'"
    _, _, rc = run_ssh_checked(cmd, check=False)
    return rc == 0


def stop_process(pod, pid, stop_file, grace_s=4.0):
    """
    Signals one specific process via its stop file, waits, then kills only that PID if still alive.
    Strictly verifies that the target process has actually terminated before returning.
    """
    run_ssh_checked(f"kubectl exec -n {NS} {pod} -- sh -c 'touch {stop_file}'", check=False)
    deadline = time.time() + grace_s
    while time.time() < deadline:
        if is_process_terminated(pod, pid):
            return "exited"
        time.sleep(0.5)
    # Escalate to SIGTERM
    run_ssh_checked(f"kubectl exec -n {NS} {pod} -- sh -c 'kill {pid}'", check=False)
    time.sleep(1.0)
    if is_process_terminated(pod, pid):
        return "killed_sigterm"
    # Escalate to SIGKILL if process still survives
    run_ssh_checked(f"kubectl exec -n {NS} {pod} -- sh -c 'kill -9 {pid}'", check=False)
    time.sleep(0.5)
    if is_process_terminated(pod, pid):
        return "killed_sigkill"
    raise RuntimeError(f"Failed to terminate generator PID {pid} in pod {pod}")


def decoy_counters():
    return json.loads(pod_python(DECOY, DECOY_COUNTERS_SCRIPT, container="decoy"))


# ------------------------------------------------------------------------------
# Replay authentication (HMAC); key held only in memory, never logged
# ------------------------------------------------------------------------------
_KEY = None


def load_key():
    global _KEY
    raw = run_ssh(f"kubectl get secret ddos-bench-auth -n {NS} -o jsonpath='{{.data.token}}'")
    _KEY = base64.b64decode(raw).decode("utf-8").strip()
    if not _KEY:
        raise PreflightGateError("benchmark secret is empty")
    return hashlib.sha256(_KEY.encode()).hexdigest()


def signed_rid(i, ts):
    base = f"s5r-atk-A-{i}"
    msg = f"v1|{base}|{TARGET}|{FEAT_DETAILS}|{ts}".encode()
    sig = hmac.new(_KEY.encode(), msg, hashlib.sha256).hexdigest()[:32]
    return f"{base}#replay=cic17#svc={TARGET}#feat={FEAT_DETAILS}#ts={ts}#sig={sig}"


def defender_key_hash(deploy):
    code = "import os,hashlib;print(hashlib.sha256(os.environ.get('TEST_AUTH_TOKEN','').encode()).hexdigest())"
    return pod_python(f"deployment/{deploy}", code)


def defender_status():
    code = ("import urllib.request;"
            "print(urllib.request.urlopen('http://localhost:8080/api/status',timeout=5).read().decode())")
    return json.loads(pod_python(DEFENDER, code))


def pid1_telemetry():
    code = r"""
import json, os
cmd = open('/proc/1/cmdline','rb').read().replace(b'\x00', b' ').decode(errors='ignore')
st = {}
for line in open('/proc/1/status'):
    k, _, v = line.partition(':'); st[k] = v.strip()
cpu = {}
if os.path.exists('/sys/fs/cgroup/cpu.stat'):
    for line in open('/sys/fs/cgroup/cpu.stat'):
        p = line.split()
        if len(p) == 2: cpu[p[0]] = int(p[1])
print(json.dumps({'pid1_cmdline': cmd.strip(), 'pid1_is_defender': 'defender:app' in cmd,
                  'vmrss_kib': int(st.get('VmRSS', '0 kB').split()[0]), 'threads': int(st.get('Threads', '0')),
                  'cpu_stat': cpu}))
"""
    return json.loads(pod_python(DEFENDER, code))


# ------------------------------------------------------------------------------
# Controller log parsing
# ------------------------------------------------------------------------------
LOG_TS = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})")


def log_epoch(line):
    m = LOG_TS.match(line)
    if not m:
        return None
    dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return dt.timestamp() + int(m.group(2)) / 1000.0


def parse_controller_log(text):
    ev = {"dispatch": [], "authorized": [], "blocked": [], "active_decoy": [], "abate_1of2": [],
          "abate_confirmed": [], "restored_v1": [], "removed_quarantine": [], "lock_released": []}
    for line in text.splitlines():
        t = log_epoch(line)
        if "[DISPATCH]" in line and "Applying '" in line:
            m = re.search(r"Applying '(\w+)' mitigation", line)
            ev["dispatch"].append({"t": t, "attribution": m.group(1) if m else None, "line": line})
        elif "[ACTIVE-ENFORCE] Authorizing live mitigation enforcement" in line:
            ev["authorized"].append({"t": t})
        elif "[SECURITY-BLOCKED]" in line or "live enforcement suppressed" in line:
            ev["blocked"].append({"t": t, "line": line})
        elif "still actively attacking decoy at" in line:
            m = re.search(r"at ([\d.]+) RPS", line)
            ev["active_decoy"].append({"t": t, "rps": float(m.group(1)) if m else None})
        elif "abated for 1/2 consecutive distinct windows" in line:
            m_rps = re.search(r"\(([\d.]+) RPS <= ([\d.]+) RPS\)", line)
            ev["abate_1of2"].append({
                "t": t,
                "measured_rps": float(m_rps.group(1)) if m_rps else None,
                "threshold_rps": float(m_rps.group(2)) if m_rps else None,
                "line": line
            })
        elif "confirmed abated on decoy across 2 consecutive distinct non-overlapping windows" in line:
            m_rps = re.search(r"\(([\d.]+) RPS <= ([\d.]+) RPS\)", line)
            ev["abate_confirmed"].append({
                "t": t,
                "measured_rps": float(m_rps.group(1)) if m_rps else None,
                "threshold_rps": float(m_rps.group(2)) if m_rps else None,
                "line": line
            })
        elif "Restored 'details' production routing to v1=100%" in line:
            ev["restored_v1"].append({"t": t})
        elif "Removed quarantine rule for 'details'" in line:
            ev["removed_quarantine"].append({"t": t})
        elif "Lock RELEASED" in line:
            ev["lock_released"].append({"t": t})
    return ev


# ------------------------------------------------------------------------------
# Benign analysis
# ------------------------------------------------------------------------------
def pct(sorted_vals, q):
    if not sorted_vals:
        return None
    return sorted_vals[min(len(sorted_vals) - 1, int(round(q * (len(sorted_vals) - 1))))]


def benign_stats(records):
    lats = sorted(r["lat_ms"] for r in records if r.get("status") == 200)
    ok = sum(1 for r in records if r.get("status") == 200)
    return {
        "total": len(records), "success_200": ok,
        "success_rate": round(ok / len(records), 4) if records else None,
        "non_200_or_error": len(records) - ok,
        "served_by_decoy": sum(1 for r in records if r.get("served_by_decoy")),
        "mean_ms": round(sum(lats) / len(lats), 3) if lats else None,
        "p50_ms": pct(lats, 0.50), "p95_ms": pct(lats, 0.95), "p99_ms": pct(lats, 0.99),
    }


# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------
os.makedirs(RAW_DIR, exist_ok=True)
pids = {}
marks = {}
checks = {}


def main():
    # ---------------- PREFLIGHT (read-only; no traffic sent before all gates pass) ----------------
    log_event("PREFLIGHT_START", "PREFLIGHT")
    leases0 = get_all_leases()
    vs0 = get_vs(TARGET)
    d0 = describe_routes(vs0)
    siblings0 = {n: get_vs(n)["spec"] for n in SIBLINGS}
    status0 = defender_status()
    key_hash = load_key()
    defender_hashes = {d: defender_key_hash(d) for d in
                       ["ddos-defender-product", "ddos-defender-details", "ddos-defender-reviews", "ddos-defender-ratings"]}
    vm_t = vm_now()
    skew = {}
    for pod in [ATTACKER_POD, BENIGN_POD]:
        t_pod = float(run_ssh(f"kubectl exec -n {NS} {pod} -- python -c 'import time;print(time.time())'"))
        skew[pod] = round(t_pod - vm_now(), 3)
    t_decoy = decoy_counters()["t"]
    skew["details-decoy"] = round(t_decoy - vm_now(), 3)
    decoy_raw_stats = json.loads(pod_python(DECOY, "import urllib.request;print(urllib.request.urlopen('http://localhost:8080/decoy-stats', timeout=3).read().decode())", container="decoy"))
    decoy_schema_ok = (
        isinstance(decoy_raw_stats.get("attacker_requests"), int) and
        isinstance(decoy_raw_stats.get("benign_requests"), int) and
        isinstance(decoy_raw_stats.get("recent_attacker_logs"), list)
    )
    if decoy_schema_ok and decoy_raw_stats.get("recent_attacker_logs"):
        sample_log = decoy_raw_stats["recent_attacker_logs"][-1]
        decoy_schema_ok = (
            "timestamp" in sample_log and
            "request_id" in sample_log and
            isinstance(sample_log["timestamp"], (int, float)) and
            isinstance(sample_log["request_id"], str)
        )

    # Model registry, model artifact, and controller image identity preflight checks (Finding R3 & Reviewer Blocker 1 & Final Pre-Rollout Condition 2)
    REQUIRED_CONTROLLER_IMAGE = "boktiar/ddos-defender:cic-v5.4-hmac"
    REQUIRED_DETAILS_MODEL_SHA256 = "d65136992788cf68376b8821c0d8d598020a55ba84140c1a3bdb3ceb06e4977c"
    controller_img = run_ssh(f"kubectl get deployment {DEFENDER.split('/')[-1]} -n {NS} -o jsonpath='{{.spec.template.spec.containers[0].image}}'").strip()
    pod_img_id = run_ssh(f"kubectl get pod -l app=ddos-defender-details -n {NS} -o jsonpath='{{.items[0].status.containerStatuses[0].imageID}}'").strip()
    minikube_img_id = run_ssh(f"minikube ssh \"docker inspect --format='{{{{.Id}}}}' {REQUIRED_CONTROLLER_IMAGE} 2>/dev/null\" || echo 'NONE'").strip()
    model_sha_raw = run_ssh(
        f"kubectl exec {DEFENDER} -n {NS} -- sha256sum /app/models/details/details_bundle_7feat.joblib 2>/dev/null "
        f"|| echo 'NONE'"
    ).strip()
    details_model_sha = model_sha_raw.split()[0] if model_sha_raw != "NONE" else None

    evidence["preflight"] = {
        "leases": leases0, "details_routes": d0, "replay_auth_mode": status0.get("replay_auth_mode"),
        "replay_cache_ttl_seconds": status0.get("replay_cache_ttl_seconds"),
        "required_controller_image": REQUIRED_CONTROLLER_IMAGE,
        "controller_image": controller_img,
        "pod_image_id": pod_img_id,
        "minikube_runtime_image_id": minikube_img_id,
        "required_details_model_sha256": REQUIRED_DETAILS_MODEL_SHA256,
        "details_model_sha256": details_model_sha,
        "l7_models_loaded": status0.get("l7_models", []),
        "secret_key_sha256_prefix": key_hash[:16],
        "defender_key_sha256_prefix": {k: v[:16] for k, v in defender_hashes.items()},
        "clock_skew_vs_vm_s": skew, "decoy_stats_schema_verified": decoy_schema_ok,
        "pid1": pid1_telemetry(), "vm_time": vm_t,
    }
    checks["preflight_exact_10_leases_unheld"] = (set(leases0) == EXPECTED_LEASES and not any(leases0.values()))
    checks["preflight_details_baseline_v1_100"] = (not d0["quarantine_present"] and d0["n_rules"] == 1
                                                   and d0["production_routes"] == [("v1", 100)])
    checks["preflight_replay_auth_hmac_supported"] = (status0.get("replay_auth_mode") == REQUIRED_REPLAY_AUTH_MODE)
    checks["preflight_details_defender_key_matches_secret"] = (defender_hashes["ddos-defender-details"] == key_hash)
    checks["preflight_clock_skew_ok"] = all(abs(v) < MAX_CLOCK_SKEW_S for v in skew.values())
    checks["preflight_decoy_schema_ok"] = decoy_schema_ok
    # Strict image verification: require EXACT cic-v5.4-hmac tag and verify pod image ID matches minikube runtime ID
    checks["preflight_controller_image_verified"] = bool(
        controller_img == REQUIRED_CONTROLLER_IMAGE
        and pod_img_id
        and minikube_img_id
        and minikube_img_id != "NONE"
        and (minikube_img_id.replace("sha256:", "") in pod_img_id)
    )
    # Strict model integrity verification: require details model in registry AND exact SHA-256 match on details_bundle_7feat.joblib
    checks["preflight_details_model_and_registry_verified"] = bool(
        "details" in status0.get("l7_models", [])
        and details_model_sha == REQUIRED_DETAILS_MODEL_SHA256
    )
    failed = [k for k, v in checks.items() if not v]
    if failed:
        raise PreflightGateError(f"preflight gate failed: {failed}; no traffic was sent")
    log_event("PREFLIGHT_PASSED", "PREFLIGHT", {"skew_s": skew, "auth_mode": status0.get("replay_auth_mode")})

    # ---------------- PHASE A: signed replay burst + continuous benign ----------------
    ts = f"{vm_now():.3f}"
    rid_file = "\n".join(signed_rid(i, ts) for i in range(PHASE_A_SIGNED_REQUESTS)) + "\n"
    upload(ATTACKER_POD, "/tmp/s5r_phaseA_rids.txt", rid_file)
    for f in ["/tmp/s5r_atkA.stop", "/tmp/s5r_atkB.stop", "/tmp/s5r_atkA_summary.json", "/tmp/s5r_atkB_summary.json"]:
        run_ssh_checked(f"kubectl exec -n {NS} {ATTACKER_POD} -- rm -f {f}", check=False)
    run_ssh_checked(f"kubectl exec -n {NS} {BENIGN_POD} -- rm -f /tmp/s5r_benign.stop /tmp/s5r_benign.jsonl", check=False)
    upload(BENIGN_POD, "/tmp/s5r_benign.py", BENIGN_SCRIPT)
    upload(ATTACKER_POD, "/tmp/s5r_atkA.py", ATTACK_A_SCRIPT)
    upload(ATTACKER_POD, "/tmp/s5r_atkB.py", ATTACK_B_SCRIPT)
    decoy_start = decoy_counters()

    pids["benign"] = launch(BENIGN_POD, "/tmp/s5r_benign.py", "/tmp/s5r_benign.log")
    marks["benign_start"] = log_event("BENIGN_STARTED", "PHASE_A", {"pid": pids["benign"]})["t_vm"]
    pids["attacker_A"] = launch(ATTACKER_POD, "/tmp/s5r_atkA.py", "/tmp/s5r_atkA.log")
    marks["phase_A_start"] = log_event("PHASE_A_ATTACK_STARTED", "PHASE_A", {"pid": pids["attacker_A"]})["t_vm"]

    dA = None
    while vm_now() - marks["phase_A_start"] < PHASE_A_TIMEOUT_S:
        t, _, d = poll("PHASE_A")
        if d["quarantine_present"]:
            dA, marks["phase_A_commit"] = d, t
            break
        time.sleep(POLL_SLEEP_S)
    if dA is None:
        raise TimeoutError("Phase A quarantine commit not observed")

    # Swap attacker generators with no gap: stop A (specific PID), start B.
    evidence["attacker_A_stop"] = stop_process(ATTACKER_POD, pids["attacker_A"], "/tmp/s5r_atkA.stop")
    pids["attacker_B"] = launch(ATTACKER_POD, "/tmp/s5r_atkB.py", "/tmp/s5r_atkB.log")
    marks["phase_B_start"] = log_event("PHASE_B_ATTACK_STARTED", "PHASE_B",
                                       {"pid": pids["attacker_B"], "rate_rps": PHASE_B_RATE_RPS})["t_vm"]
    evidence["phase_A_commit"] = dA
    evidence["phase_A_defender_status"] = defender_status().get("hybrid_attribution", {})
    evidence["pid1_phase_A"] = pid1_telemetry()

    # ---------------- PHASE B: wait for autonomous Stage 1 ----------------
    dS1 = None
    while vm_now() - marks["phase_A_commit"] < STAGE1_TIMEOUT_S:
        t, _, d = poll("PHASE_B")
        if d["quarantine_present"] and d["production_routes"] == [("v1", 100)]:
            dS1, marks["stage1_commit"] = d, t
            break
        time.sleep(POLL_SLEEP_S)
    if dS1 is None:
        raise TimeoutError("Stage 1 commit not observed")
    log_event("STAGE1_OBSERVED", "PHASE_B", {"rv": dS1["resource_version"]}, t_vm=marks["stage1_commit"])

    decoy_s1 = json.loads(pod_python(DECOY, DECOY_MEASURE_SCRIPT, container="decoy"))
    evidence["stage1_decoy_measurement"] = decoy_s1
    log_event("STAGE1_DECOY_MEASURED", "PHASE_B",
              {"attacker_delta": decoy_s1["attacker_delta"], "elapsed_s": round(decoy_s1["monotonic_elapsed_s"], 3),
               "rps": round(decoy_s1["attacker_rps"], 3), "matched": decoy_s1["matched_count"]})

    hold_states = []
    while vm_now() - marks["stage1_commit"] < ANTI_OSC_HOLD_S:
        t, _, d = poll("PHASE_B_HOLD")
        hold_states.append({"t_vm": t, "quarantine": d["quarantine_present"], "routes": d["production_routes"]})
        time.sleep(POLL_SLEEP_S)
    evidence["anti_oscillation_hold"] = hold_states
    evidence["pid1_stage1"] = pid1_telemetry()

    # ---------------- PHASE C: stop attacker, wait for autonomous Stage 2 ----------------
    evidence["attacker_B_stop"] = stop_process(ATTACKER_POD, pids["attacker_B"], "/tmp/s5r_atkB.stop")
    marks["attacker_stop"] = log_event("ATTACKER_STOPPED", "PHASE_C")["t_vm"]
    evidence["attacker_B_summary"] = json.loads(
        run_ssh(f"kubectl exec -n {NS} {ATTACKER_POD} -- cat /tmp/s5r_atkB_summary.json"))
    c0 = decoy_counters(); time.sleep(5.0); c1 = decoy_counters()
    evidence["post_stop_decoy_counters"] = [c0, c1]

    dS2 = None
    while vm_now() - marks["attacker_stop"] < STAGE2_TIMEOUT_S:
        t, _, d = poll("PHASE_C")
        if not d["quarantine_present"]:
            dS2, marks["stage2_commit"] = d, t
            break
        time.sleep(POLL_SLEEP_S)
    if dS2 is None:
        raise TimeoutError("Stage 2 commit not observed")
    log_event("STAGE2_OBSERVED", "PHASE_C", {"rv": dS2["resource_version"]}, t_vm=marks["stage2_commit"])

    t_end = marks["stage2_commit"] + POST_STAGE2_BENIGN_S
    while vm_now() < t_end:
        poll("POST_STAGE2")
        time.sleep(1.0)
    evidence["benign_stop"] = stop_process(BENIGN_POD, pids["benign"], "/tmp/s5r_benign.stop")
    marks["benign_stop"] = log_event("BENIGN_STOPPED", "POST")["t_vm"]
    decoy_end = decoy_counters()
    evidence["decoy_counters_trial"] = {"start": decoy_start, "end": decoy_end}
    evidence["pid1_stage2"] = pid1_telemetry()

    # ---------------- Evidence collection ----------------
    raw = run_ssh(f"kubectl exec -n {NS} {BENIGN_POD} -- cat /tmp/s5r_benign.jsonl")
    lines = [json.loads(l) for l in raw.splitlines() if l.strip()]
    summary = [l for l in lines if l.get("summary")]
    records = [l for l in lines if not l.get("summary")]
    evidence["benign_generator_summary"] = summary[-1] if summary else None
    evidence["benign_records"] = records

    since = datetime.datetime.fromtimestamp(marks["benign_start"] - 5, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ctrl_log = run_ssh(f"kubectl logs -n {NS} {DEFENDER} --since-time={since}")
    evidence["controller_events"] = parse_controller_log(ctrl_log)
    with open(os.path.join(RAW_DIR, "controller_trace_trial_0R.log"), "w", encoding="utf-8") as f:
        f.write(ctrl_log)
    evidence["final_cluster_audit"] = read_only_audit(siblings0)
    evidence["marks_vm"] = marks
    build_checklist(dA, dS1, dS2, decoy_s1, hold_states, c0, c1, records, siblings0)


def read_only_audit(siblings0=None):
    """Read-only snapshot. Never mutates the cluster."""
    audit = {"t_vm": None}
    try:
        audit["t_vm"] = vm_now()
        audit["details"] = describe_routes(get_vs(TARGET))
        audit["leases"] = get_all_leases()
        audit["details_lease"] = get_lease("details-mitigation-lock").get("spec", {})
        sib = {n: get_vs(n)["spec"] for n in SIBLINGS}
        audit["siblings_unchanged"] = (sib == siblings0) if siblings0 is not None else None
        audit["siblings_specs"] = sib
        audit["safe_baseline"] = (not audit["details"]["quarantine_present"]
                                  and audit["details"]["production_routes"] == [("v1", 100)]
                                  and set(audit["leases"]) == EXPECTED_LEASES
                                  and not any(audit["leases"].values()))
    except Exception as e:
        audit["error"] = f"{type(e).__name__}: {e}"
        audit["safe_baseline"] = False
    if not audit.get("safe_baseline"):
        audit["operator_note"] = ("Cluster not at safe baseline. The harness does not mutate routing; the controller "
                                  "will continue its autonomous recovery. Re-run a read-only audit before any new trial.")
    return audit


def build_checklist(dA, dS1, dS2, decoy_s1, hold_states, c0, c1, records, siblings0):
    ev = evidence["controller_events"]
    A0, A1 = marks["phase_A_start"], marks["phase_A_commit"]
    S1, S2, stop = marks["stage1_commit"], marks["stage2_commit"], marks["attacker_stop"]

    dispatch_A = [e for e in ev["dispatch"] if e["t"] and A0 - 2 <= e["t"] <= A1 + 2]
    evidence["detection_attribution"] = dispatch_A[0]["attribution"] if dispatch_A else None
    checks["phase_A_attribution_BOTH"] = (evidence["detection_attribution"] == "BOTH")
    checks["phase_A_ml_replay_authorized"] = (any(A0 - 2 <= (e["t"] or 0) <= A1 + 2 for e in ev["authorized"])
                                              and not any(A0 - 2 <= (e["t"] or 0) <= A1 + 2 for e in ev["blocked"]))
    checks["phase_A_quarantine_index0_to_decoy_for_attacker"] = (dA["quarantine_index"] == 0 and dA["quarantine_to_decoy"]
                                                                and dA["quarantine_matches_attacker"])
    checks["phase_A_failover_v2_50_v3_50"] = (dA["production_routes"] == [("v2", 50), ("v3", 50)])

    checks["stage1_production_v1_100"] = (dS1["production_routes"] == [("v1", 100)])
    checks["stage1_quarantine_retained"] = (dS1["quarantine_present"] and dS1["quarantine_index"] == 0)
    checks["stage1_decoy_rps_gt_2_counter"] = (decoy_s1["attacker_rps"] > 2.0 and decoy_s1["attacker_delta"] > 0)
    checks["stage1_matched_attacker_ids_reconciled"] = (decoy_s1["matched_count"] > 0
                                                        and abs(decoy_s1["matched_count"] - decoy_s1["attacker_delta"]) <= 1)
    checks["stage1_no_benign_at_decoy"] = (decoy_s1["benign_delta"] == 0)
    checks["stage1_controller_saw_active_decoy"] = any(
        e["t"] and S1 - 10 <= e["t"] <= S1 + 2 and (e["rps"] or 0) > 2.0 for e in ev["active_decoy"])
    checks["anti_oscillation_hold_15s"] = (len(hold_states) > 0 and all(
        h["quarantine"] and h["routes"] == [("v1", 100)] for h in hold_states))

    # Stage 2 Abatement Verification (Finding R1):
    # Verify non-overlapping window duration, measured RPS <= threshold, and decoy counter flatline
    checks["attacker_stopped_and_decoy_flat"] = (
        evidence["attacker_B_stop"] in ("exited", "killed", "killed_sigterm", "killed_sigkill")
        and c1["attacker_requests"] == c0["attacker_requests"]
    )
    w1 = [e for e in ev["abate_1of2"] if e["t"] and e["t"] > stop]
    w2 = [e for e in ev["abate_confirmed"] if e["t"] and e["t"] > stop]
    rmq = [e for e in ev["removed_quarantine"] if e["t"] and e["t"] > stop]

    # Strict Fail-Closed Validation for Abatement Windows (Reviewer Blocker 2)
    def _validate_abatement_record(rec, max_threshold=2.0):
        if not rec or not isinstance(rec, dict):
            return False, "missing_or_invalid_record"
        rps = rec.get("measured_rps")
        if rps is None or not isinstance(rps, (int, float)):
            return False, "missing_or_nonnumeric_rps"
        if not math.isfinite(rps) or rps < 0.0:
            return False, "nonfinite_or_negative_rps"
        thresh = rec.get("threshold_rps") or max_threshold
        if rps > thresh or rps > max_threshold:
            return False, f"rps_exceeds_threshold_{rps:.2f}>{thresh:.2f}"
        return True, "valid"

    w1_ok, w1_reason = _validate_abatement_record(w1[0] if w1 else None)
    w2_ok, w2_reason = _validate_abatement_record(w2[0] if w2 else None)
    non_overlapping = bool(w1_ok and w2_ok and (w2[0]["t"] - w1[0]["t"] >= 5.0))
    ordered_removal = bool(non_overlapping and rmq and rmq[0]["t"] >= w2[0]["t"])

    evidence["stage2_abatement_verification"] = {
        "window1": w1[0] if w1 else None,
        "window1_validation": w1_reason,
        "window2": w2[0] if w2 else None,
        "window2_validation": w2_reason,
        "inter_window_elapsed_s": round(w2[0]["t"] - w1[0]["t"], 3) if (w1 and w2) else None,
        "quarantine_removal_event": rmq[0] if rmq else None,
        "decoy_counter_delta_post_stop": c1["attacker_requests"] - c0["attacker_requests"],
        "abatement_evidence_classification": "controller-log-supported-and-decoy-telemetry-reconciled"
    }

    checks["stage2_two_distinct_abatement_windows_controller_log_supported"] = bool(
        w1_ok and w2_ok and non_overlapping and ordered_removal
    )
    checks["stage2_decoy_telemetry_reconciled_zero_rps"] = bool(
        c1["attacker_requests"] == c0["attacker_requests"]
        and c1.get("t", 0) >= c0.get("t", 0)
    )
    checks["stage2_quarantine_removed_v1_100"] = (not dS2["quarantine_present"]
                                                  and dS2["production_routes"] == [("v1", 100)] and dS2["n_rules"] == 1)

    fa = evidence["final_cluster_audit"]
    checks["final_details_lease_released"] = (fa.get("details_lease", {}).get("holderIdentity") in (None, ""))
    checks["final_exact_10_leases_unheld"] = (set(fa.get("leases", {})) == EXPECTED_LEASES
                                              and not any(fa.get("leases", {}).values()))
    checks["final_siblings_unchanged"] = bool(fa.get("siblings_unchanged"))
    checks["final_routing_baseline"] = bool(fa.get("safe_baseline"))

    # Expected routing sequence, with no unexpected intermediate states.
    seq = []
    for tr in transitions:
        k = state_key(tr)
        if not seq or seq[-1] != k:
            seq.append(k)
    expected = [(False, (("v1", 100),)), (True, (("v2", 50), ("v3", 50))), (True, (("v1", 100),)), (False, (("v1", 100),))]
    evidence["routing_state_sequence"] = seq
    checks["routing_sequence_exact"] = (seq == expected[1:] or seq == expected)

    # Benign traffic: reconciled, non-empty per phase, spanning both transitions.
    gen = evidence["benign_generator_summary"]
    checks["benign_count_reconciled_with_generator"] = bool(gen) and gen["sent"] == len(records)
    phases = {"A": (marks["benign_start"], marks["phase_B_start"]), "B": (marks["phase_B_start"], stop),
              "C": (stop, marks["benign_stop"])}
    by_phase = {p: [r for r in records if lo <= r["t_send"] < hi] for p, (lo, hi) in phases.items()}
    evidence["benign_traffic_quality"] = {p: benign_stats(v) for p, v in by_phase.items()}
    cov = {name: [r for r in records if abs(r["t_send"] - T) <= TRANSITION_COVERAGE_S]
           for name, T in {"phase_A_commit": A1, "stage1": S1, "stage2": S2}.items()}
    evidence["benign_transition_coverage"] = {k: benign_stats(v) for k, v in cov.items()}
    checks["benign_nonempty_each_phase"] = all(len(v) > 0 for v in by_phase.values())
    checks["benign_spans_stage1_and_stage2"] = all(len(cov[k]) >= MIN_BENIGN_IN_COVERAGE for k in ("stage1", "stage2"))
    checks["benign_never_served_by_decoy"] = (all(not r.get("served_by_decoy") for r in records)
                                              and evidence["decoy_counters_trial"]["end"]["benign_requests"]
                                              == evidence["decoy_counters_trial"]["start"]["benign_requests"])
    checks["benign_success_rate_each_phase"] = all(
        (s["success_rate"] or 0) >= BENIGN_MIN_SUCCESS_RATE for s in evidence["benign_traffic_quality"].values())


def write_evidence(name):
    evidence["dynamic_verification_checklist"] = checks
    evidence["poll_cadence"] = {
        "sleep_s": POLL_SLEEP_S,
        "measured_intervals_s": [p["interval_s"] for p in polls if p["interval_s"] is not None],
    }
    iv = evidence["poll_cadence"]["measured_intervals_s"]
    if iv:
        s = sorted(iv)
        evidence["poll_cadence"].update({"n": len(s), "median_s": pct(s, 0.5), "p95_s": pct(s, 0.95), "max_s": s[-1]})
    evidence["polls"] = polls
    blob = json.dumps(evidence, indent=2, default=str)
    if _KEY and _KEY in blob:
        raise RuntimeError("refusing to write evidence: benchmark key material detected")
    path = os.path.join(RAW_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(blob)
    return path


exit_code = 1
try:
    main()
    evidence["status"] = "PASSED" if checks and all(checks.values()) else "FAILED"
    path = write_evidence("trial_0R_autonomous.json")
    print("=" * 80)
    print(f"TRIAL 0-R STATUS: {evidence['status']}   attribution={evidence.get('detection_attribution')}")
    for k, v in checks.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print(f"evidence: {path}")
    exit_code = 0 if evidence["status"] == "PASSED" else 1
except Exception as ex:
    evidence["status"] = "BLOCKED_PREFLIGHT" if isinstance(ex, PreflightGateError) else "FAILED_EXCEPTION"
    evidence["error"] = f"{type(ex).__name__}: {ex}"
    evidence["traceback"] = traceback.format_exc()
    print(f"[ERROR] {evidence['error']}")
finally:
    # 1. Generator Cleanup — wrapped in independent exception protection (Finding R4)
    cleanup_results = {}
    for name, (pod, stop_file) in {"attacker_A": (ATTACKER_POD, "/tmp/s5r_atkA.stop"),
                                   "attacker_B": (ATTACKER_POD, "/tmp/s5r_atkB.stop"),
                                   "benign": (BENIGN_POD, "/tmp/s5r_benign.stop")}.items():
        if name in pids:
            try:
                status_clean = stop_process(pod, pids[name], stop_file)
                cleanup_results[name] = {"pid": pids[name], "status": status_clean}
            except Exception as e_clean:
                cleanup_results[name] = {"pid": pids[name], "status": f"cleanup_error: {e_clean}"}
    evidence["generator_cleanup"] = cleanup_results

    # 2. Final Read-Only Audit — wrapped in independent exception protection
    if evidence.get("status") not in ("PASSED", "FAILED") or "final_cluster_audit" not in evidence:
        try:
            evidence["final_cluster_audit"] = read_only_audit(siblings0 if 'siblings0' in locals() else None)
        except Exception as e_audit:
            evidence["final_cluster_audit"] = {"audit_error": f"{type(e_audit).__name__}: {e_audit}"}

    # 3. Partial Failure Evidence Dump — guaranteed preservation
    if evidence.get("status") not in ("PASSED", "FAILED"):
        try:
            fail_path = write_evidence("trial_0R_failure_evidence.json")
            print(f"[FAILURE-EVIDENCE] Partial evidence preserved to: {fail_path}")
        except Exception as e_ev:
            print(f"[EVIDENCE-FATAL-ERROR] Failed to serialize failure evidence: {e_ev}")

    # 4. Safe SSH connection teardown
    try:
        ssh.close()
    except Exception:
        pass
    sys.exit(exit_code)
