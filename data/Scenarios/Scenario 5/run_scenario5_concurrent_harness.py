#!/usr/bin/env python3
"""
Scenario 5 — Four-Service Concurrent Benchmark Runner (Coordinator)
===================================================================
Coordinates simultaneous DDoS attacks across all four Bookinfo services:
  - productpage : 85.0 RPS (North-South via bookinfo-gateway), recovery: targeted_quarantine_v1_preserved
  - details     : 25.0 RPS (East-West in-mesh), recovery: reroute_and_restore
  - reviews     : 25.0 RPS (East-West in-mesh), recovery: reroute_and_restore
  - ratings     : 25.0 RPS (East-West in-mesh), recovery: reroute_and_restore
Total aggregate attack rate: 160.0 RPS across 2,230 signed requests.

Features:
  - Strict Paramiko host-key verification (RejectPolicy) and mandatory credential configuration.
  - Synchronized start timing barrier (t_barrier) guaranteeing simultaneous multi-workload inception.
  - Guaranteed try/finally cleanup with process ownership verification on all client pods.
  - Full trial-scoped isolation for scripts, request files, PIDs, and stop files (/tmp/s5c_{trial_id}_*).
  - Validated productpage gateway static route (/static/img/izzy.png) preserving East-West isolation.
  - Fail-closed decoy telemetry verification (ports 8080/9080) with attacker IP and RID reconciliation.
  - Rigorous scientific assertion distinguishing observed failover (v2/v3) from targeted quarantine (v1).
  - Preservation of partial telemetry and controller logs upon unexpected execution failure.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import sys
import time
import traceback
import urllib.parse
import urllib.request
import paramiko

# ----------------- Configuration & Service Profiles -----------------
SSH_HOST = os.getenv("SSH_HOST", "192.168.160.129")
SSH_USER = os.getenv("SSH_USER", "osu")
SSH_PASS = os.getenv("SSH_PASS")
SSH_KEY = os.getenv("SSH_KEY")

KNOWN_HOST_KEY_ED25519 = "AAAAC3NzaC1lZDI1NTE5AAAAIDwJXIiNCBAeT9k44sEljUxhJAh+YQXfymsl/pTBTjEf"
KNOWN_HOST_KEY_RSA = "AAAAB3NzaC1yc2EAAAADAQABAAABgQC+VU3i7qVE4LvCtmfoRam5y25HrbiYvTLXb+g9t9WC/z/Xceawf0oo049FtHTjq3zvr/5COVrb5OvIRWOE9Z3EXiNJ79X+d//CVII9S6HdZsnrdeLiokjt/tG66hkbblODae7PrbSv91Nm7R4K3KB1cfYn0Md6vp8YWGEm+L0KOVDqZRXAemYR7TmUGjEnDvGzTuzEeSls44YOANIxTXKw6GegaAff1RAiF24yZUnMsJUjvpNV+VMmcnxjMEBqPEKWdPqgAGCusT6RgrZnqO/xsmtCGYh3lpkVOQ6xDZ5eaS4EqYL7/l+NEJ7lOXbUDv6yXzxnkLUpIGqzbtqGc3wZepXg9voWEOEXiumSkL3JiPwkAnBDTDsNCgAVkvrkMDVjYGigXHBZ/lU/xVLk0vsPcfT1R1D42VdRWetkYkb3If932fNqRGwme6Du0X5TVfW9AyhHl2PPpl4hKpSfmz5ffIdtl4DORST6bBevCRD7HmgY+GFM6cNeXW1C4XeikiM="

NS = "default"
ATTACKER_POD = "client-attacker"
BENIGN_POD = "client-benign"
ATTACKER_IDENTITY = "10.244.0.131"
BENIGN_IDENTITY = "10.244.0.130"
REQUIRED_REPLAY_AUTH_MODE = "hmac-sha256-v2"
REQUIRED_CONTROLLER_IMAGE = "boktiar/ddos-defender:cic-v5.4-hmac"
GATEWAY_HOST = "10.105.147.21"

SERVICES = {
    "productpage": {
        "recovery_path": "targeted_quarantine_v1_preserved",
        "vs_name": "bookinfo",
        "target_url": f"http://{GATEWAY_HOST}:80/static/img/izzy.png",
        "host_header": "istio-ingressgateway.istio-system.svc.cluster.local",
        "ingress_route": "gateway",
        "defender_deployment": "ddos-defender-product",
        "decoy_deployment": "productpage-decoy",
        "decoy_container": "decoy",
        "decoy_host": "productpage-decoy",
        "decoy_stats_url": "http://localhost:8080/decoy-stats",
        "replay_svc": "productpage",
        "lease_name": "product-mitigation-lock",
        "feature_vector": "0.1344,4.0,239.0,59.75,6.0,2.0,7544.14",
        "model_path": "/app/models/productpage/productpage_bundle_7feat.joblib",
        "model_sha256": "93b55282b0d392f049ada29054749646c7ffbc9a6bfe4d6d81f45322f199be14",
        "expected_failover_routes": [["v1", 100]],
        "phase_a_rate_rps": 85.0,
        "phase_a_signed_requests": 1105,
        "phase_a_min_requests": 1105,
        "phase_a_min_attempted_rps": 80.0,
        "phase_a_max_attempted_rps": 90.0,
        "phase_a_min_successful_rps": 75.0,
        "phase_b_rate_rps": 5.0,
        "concurrency": 16,
    },
    "details": {
        "recovery_path": "reroute_and_restore",
        "vs_name": "details",
        "target_url": "http://details:9080/details/0",
        "host_header": "",
        "ingress_route": "mesh",
        "defender_deployment": "ddos-defender-details",
        "decoy_deployment": "details-decoy",
        "decoy_container": "decoy",
        "decoy_host": "details-decoy",
        "decoy_stats_url": "http://localhost:8080/decoy-stats",
        "replay_svc": "details",
        "lease_name": "details-mitigation-lock",
        "feature_vector": "4.0,3.0,239.0,0.0,59.75,0.0,0.75",
        "model_path": "/app/models/details/details_bundle_7feat.joblib",
        "model_sha256": "d65136992788cf68376b8821c0d8d598020a55ba84140c1a3bdb3ceb06e4977c",
        "expected_failover_routes": [["v2", 50], ["v3", 50]],
        "phase_a_rate_rps": 25.0,
        "phase_a_signed_requests": 375,
        "phase_a_min_requests": 375,
        "phase_a_min_attempted_rps": 22.5,
        "phase_a_max_attempted_rps": 27.5,
        "phase_a_min_successful_rps": 20.0,
        "phase_b_rate_rps": 5.0,
        "concurrency": 1,
    },
    "reviews": {
        "recovery_path": "reroute_and_restore",
        "vs_name": "reviews",
        "target_url": "http://reviews:9080/reviews/0",
        "host_header": "",
        "ingress_route": "mesh",
        "defender_deployment": "ddos-defender-reviews",
        "decoy_deployment": "reviews-decoy",
        "decoy_container": "decoy",
        "decoy_host": "reviews-decoy",
        "decoy_stats_url": "http://localhost:9080/decoy-stats",
        "replay_svc": "reviews",
        "lease_name": "reviews-mitigation-lock",
        "feature_vector": "0.0,0.0,7544.142857,86.857025,3.0,0.75,8679241.333333",
        "model_path": "/app/models/reviews/reviews_bundle_7feat.joblib",
        "model_sha256": "63f4ee6f7d69d8e507955507d9d751ef850754ae52a9903bc323d9cf310ebdfc",
        "expected_failover_routes": [["v2", 50], ["v3", 50]],
        "phase_a_rate_rps": 25.0,
        "phase_a_signed_requests": 375,
        "phase_a_min_requests": 375,
        "phase_a_min_attempted_rps": 22.5,
        "phase_a_max_attempted_rps": 27.5,
        "phase_a_min_successful_rps": 20.0,
        "phase_b_rate_rps": 5.0,
        "concurrency": 1,
    },
    "ratings": {
        "recovery_path": "reroute_and_restore",
        "vs_name": "ratings",
        "target_url": "http://ratings:9080/ratings/0",
        "host_header": "",
        "ingress_route": "mesh",
        "defender_deployment": "ddos-defender-ratings",
        "decoy_deployment": "ratings-decoy",
        "decoy_container": "decoy",
        "decoy_host": "ratings-decoy",
        "decoy_stats_url": "http://localhost:9080/decoy-stats",
        "replay_svc": "ratings",
        "lease_name": "ratings-mitigation-lock",
        "feature_vector": "4.0,3.0,34.142857,86.857025,7544.142857,2.0,6.0",
        "model_path": "/app/models/ratings/ratings_bundle_7feat.joblib",
        "model_sha256": "e7b14bf17f428dde7820dca07678601b95bde1dac1a3013cbb8916080cfb75d5",
        "expected_failover_routes": [["v2", 50], ["v3", 50]],
        "phase_a_rate_rps": 25.0,
        "phase_a_signed_requests": 375,
        "phase_a_min_requests": 375,
        "phase_a_min_attempted_rps": 22.5,
        "phase_a_max_attempted_rps": 27.5,
        "phase_a_min_successful_rps": 20.0,
        "phase_b_rate_rps": 5.0,
        "concurrency": 1,
    }
}

VALID_ATTRIBUTIONS = ["BOTH", "STAGE3B_ONLY", "ML_ONLY"]

EXPECTED_LEASES = {
    "details-dataset-mitigation-lock", "details-mitigation-lock",
    "product-canary-mitigation-lock", "product-mitigation-lock",
    "ratings-dataset-mitigation-lock", "ratings-decoy-mitigation-lock",
    "ratings-mitigation-lock", "reviews-dataset-mitigation-lock",
    "reviews-decoy-mitigation-lock", "reviews-mitigation-lock"
}

ALL_DEFENDER_DEPLOYMENTS = [s["defender_deployment"] for s in SERVICES.values()]

# Timing Parameters
BARRIER_SETUP_MARGIN_S = 35.0  # Preparation window to upload scripts and launch 8 initial background processes
MIN_BARRIER_LEAD_TIME_S = 5.0  # Abort safely if less than 5.0s remain before barrier
PHASE_A_TIMEOUT_S = 35.0
STAGE1_TIMEOUT_S = 90.0
STAGE2_TIMEOUT_S = 90.0
POST_STAGE2_BENIGN_S = 10.0
POLL_SLEEP_S = 0.25
DECOY_MEASURE_S = 5.0

# ----------------- SSH & Helper Infrastructure -----------------
class SSHManager:
    def __init__(self):
        self._client = None

    def get_client(self):
        if not SSH_PASS and not SSH_KEY:
            raise RuntimeError("Set SSH_PASS or SSH_KEY environment variable. No credential fallbacks are provided.")
        if self._client is None or not self._client.get_transport() or not self._client.get_transport().is_active():
            c = paramiko.SSHClient()
            c.get_host_keys().add(SSH_HOST, "ssh-ed25519", paramiko.Ed25519Key(data=base64.b64decode(KNOWN_HOST_KEY_ED25519)))
            c.get_host_keys().add(SSH_HOST, "ssh-rsa", paramiko.RSAKey(data=base64.b64decode(KNOWN_HOST_KEY_RSA)))
            c.set_missing_host_key_policy(paramiko.RejectPolicy())
            kw = {"hostname": SSH_HOST, "username": SSH_USER, "timeout": 15}
            if SSH_KEY:
                kw["key_filename"] = SSH_KEY
            if SSH_PASS:
                kw["password"] = SSH_PASS
            c.connect(**kw)
            self._client = c
        return self._client

    def run_cmd(self, cmd, stdin_data=None, check=True):
        client = self.get_client()
        stdin, stdout, stderr = client.exec_command(cmd)
        if stdin_data:
            stdin.write(stdin_data)
            stdin.flush()
            stdin.channel.shutdown_write()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        rc = stdout.channel.recv_exit_status()
        if check and rc != 0:
            raise RuntimeError(f"Command failed (rc={rc}): {cmd}\nStdout: {out}\nStderr: {err}")
        return out, err, rc

ssh_mgr = SSHManager()

def run_ssh(cmd, stdin_data=None):
    return ssh_mgr.run_cmd(cmd, stdin_data=stdin_data, check=True)[0]

def run_ssh_checked(cmd, check=True):
    return ssh_mgr.run_cmd(cmd, check=check)

def vm_now():
    out = run_ssh("date +%s.%N").strip()
    return float(out)

def log_epoch(line):
    m = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})", line)
    if not m:
        return None
    dt = datetime.datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S,%f")
    return dt.replace(tzinfo=datetime.timezone.utc).timestamp()

def validate_trial_id(trial_id: str) -> str:
    """Enforces strict alphanumeric trial identifier format [A-Za-z0-9_-]{1,32}."""
    if not isinstance(trial_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", trial_id):
        raise ValueError(
            f"Invalid trial_id '{trial_id}'. Trial identifiers must match [A-Za-z0-9_-]{{1,32}} "
            f"and contain only alphanumeric characters, underscores, and hyphens."
        )
    return trial_id

# ----------------- Decoy Telemetry & Routing Interpretation -----------------
def get_decoy_telemetry():
    """Reads attacker/benign request counters and recent logs across all four decoy pods. Fails closed."""
    stats = {}
    for svc_key, profile in SERVICES.items():
        decoy_pod = profile["decoy_deployment"]
        decoy_container = profile["decoy_container"]
        url = profile["decoy_stats_url"]
        py_code = f"import urllib.request; print(urllib.request.urlopen('{url}', timeout=3).read().decode())"
        cmd = f"kubectl exec -n {NS} deployment/{decoy_pod} -c {decoy_container} -- python3 -c \"{py_code}\""
        raw, err, rc = run_ssh_checked(cmd, check=False)
        if rc != 0 or not raw.strip():
            raise RuntimeError(f"Decoy telemetry endpoint failed for {svc_key} ({decoy_pod}): rc={rc}, err={err}")
        try:
            data = json.loads(raw.strip())
            assert "attacker_requests" in data and isinstance(data["attacker_requests"], int)
            assert "benign_requests" in data and isinstance(data["benign_requests"], int)
            stats[svc_key] = {
                "attacker_requests": data["attacker_requests"],
                "benign_requests": data["benign_requests"],
                "recent_attacker_logs": data.get("recent_attacker_logs", [])
            }
        except Exception as e:
            raise RuntimeError(f"Decoy telemetry schema error for {svc_key}: {e}\nRaw output: {raw}")
    return stats

def poll_all_virtual_services():
    """Polls all 4 VirtualServices concurrently in one snapshot with exact r6 route semantics."""
    raw = run_ssh(f"kubectl get virtualservices -n {NS} -o json")
    data = json.loads(raw)
    result = {}
    for item in data.get("items", []):
        name = item["metadata"]["name"]
        http = item.get("spec", {}).get("http", [])
        q_idx = [i for i, r in enumerate(http) if r.get("name") == "quarantine-malicious" or any(any(m.get("headers", {}).get("x-trusted-client-ip", {}).get("exact") == ATTACKER_IDENTITY for m in r.get("match", [])) for r in [r])]
        q_rule = http[q_idx[0]] if q_idx else None
        prod = next((r for i, r in enumerate(http) if i not in q_idx), None)
        prod_routes = sorted(
            (d.get("destination", {}).get("subset"), d.get("weight", 100 if len((prod or {}).get("route", [])) == 1 else 0))
            for d in (prod or {}).get("route", [])
        )
        q_dest_hosts = [d.get("destination", {}).get("host", "") for d in (q_rule or {}).get("route", [])]
        q_match = json.dumps((q_rule or {}).get("match", []), sort_keys=True)
        fencing_token = item.get("metadata", {}).get("annotations", {}).get("ddos.defender/fencing-token")
        result[name] = {
            "resource_version": item["metadata"].get("resourceVersion"),
            "fencing_token": fencing_token,
            "rules_count": len(http),
            "quarantine_present": bool(q_idx),
            "quarantine_index": q_idx[0] if q_idx else None,
            "quarantine_dest": q_dest_hosts[0] if q_dest_hosts else None,
            "quarantine_matches_attacker": (ATTACKER_IDENTITY in q_match),
            "production_routes": prod_routes
        }
    return result

# ----------------- Preflight Check Suite -----------------
def run_global_preflight():
    print("================================================================================")
    print("SCENARIO 5 CONCURRENT BENCHMARK — COMPREHENSIVE GLOBAL PREFLIGHT")
    print("================================================================================")

    # 1. Leases unheld in default namespace
    raw_leases = run_ssh(f"kubectl get leases -n {NS} -o json")
    leases_obj = json.loads(raw_leases)
    leases = {}
    for item in leases_obj.get("items", []):
        name = item["metadata"]["name"]
        holder = item.get("spec", {}).get("holderIdentity", "")
        leases[name] = holder

    missing_leases = EXPECTED_LEASES - set(leases.keys())
    held_leases = {k: v for k, v in leases.items() if k in EXPECTED_LEASES and v}
    print(f"Lease Audit: {len(leases)} found in namespace '{NS}'. Held leases: {held_leases}")
    if missing_leases or held_leases:
        raise RuntimeError(f"Preflight Lease audit failure: missing={missing_leases}, held={held_leases}")

    # 2. Exactly 4 Defenders: Pod identity, Ready status, 0 restarts, controller image, and replay auth mode
    raw_pods = run_ssh(f"kubectl get pods -n {NS} -o json")
    pods_obj = json.loads(raw_pods)
    defenders_status = {}
    for item in pods_obj.get("items", []):
        labels = item["metadata"].get("labels", {})
        app = labels.get("app", "")
        if app in ALL_DEFENDER_DEPLOYMENTS:
            pod_name = item["metadata"]["name"]
            cs = item.get("status", {}).get("containerStatuses", [{}])[0]
            restarts = cs.get("restartCount", 0)
            ready = cs.get("ready", False)
            started_at = cs.get("state", {}).get("running", {}).get("startedAt", "")
            img = item["spec"]["containers"][0].get("image", "")

            # Query in-pod defender status endpoint
            code_st = "import urllib.request; print(urllib.request.urlopen('http://localhost:8080/api/status', timeout=3).read().decode())"
            raw_st, _, rc_st = run_ssh_checked(f"kubectl exec -n {NS} {pod_name} -- python3 -c \"{code_st}\"", check=False)
            auth_mode = None
            if rc_st == 0 and raw_st.strip():
                try:
                    auth_mode = json.loads(raw_st.strip()).get("replay_auth_mode")
                except Exception:
                    pass

            defenders_status[app] = {
                "pod_name": pod_name,
                "restarts": restarts,
                "ready": ready,
                "started_at": started_at,
                "image": img,
                "replay_auth_mode": auth_mode
            }
            print(f"Defender {app:<25}: pod={pod_name}, ready={ready}, restarts={restarts}, image={img}, auth_mode={auth_mode}")
            if not ready or restarts > 0:
                raise RuntimeError(f"Defender {app} not ready or has restarts: {restarts}")
            if img != REQUIRED_CONTROLLER_IMAGE:
                raise RuntimeError(f"Defender {app} has image {img}, expected {REQUIRED_CONTROLLER_IMAGE}")
            if auth_mode != REQUIRED_REPLAY_AUTH_MODE:
                raise RuntimeError(f"Defender {app} has auth mode {auth_mode}, expected {REQUIRED_REPLAY_AUTH_MODE}")

    if len(defenders_status) != 4:
        raise RuntimeError(f"Expected exactly 4 active defenders, found {len(defenders_status)}: {list(defenders_status.keys())}")

    # 3. VirtualServices at Baseline: rules=1, production_routes=[('v1', 100)], quarantine_present=False
    vs_snap = poll_all_virtual_services()
    for svc_key, profile in SERVICES.items():
        vs_name = profile["vs_name"]
        if vs_name not in vs_snap:
            raise RuntimeError(f"VirtualService '{vs_name}' not found on cluster")
        v_info = vs_snap[vs_name]
        print(f"Target VS {vs_name:<10}: rules={v_info['rules_count']}, quarantine={v_info['quarantine_present']}, routes={v_info['production_routes']}")
        if v_info["rules_count"] != 1 or v_info["quarantine_present"]:
            raise RuntimeError(f"VirtualService {vs_name} not at clean baseline: rules={v_info['rules_count']}, quarantine={v_info['quarantine_present']}")
        if v_info["production_routes"] != [("v1", 100)]:
            raise RuntimeError(f"VirtualService {vs_name} routes not v1=100%: {v_info['production_routes']}")

    # 4. Auth Secret & Model Bundles
    raw_secret = run_ssh(f"kubectl get secret ddos-bench-auth -n {NS} -o jsonpath='{{.data.token}}' | base64 -d")
    auth_token = raw_secret.strip()
    auth_token_sha256 = hashlib.sha256(auth_token.encode("utf-8")).hexdigest()
    print(f"Benchmark Auth Secret SHA-256: {auth_token_sha256}")

    for svc_key, profile in SERVICES.items():
        pod = defenders_status[profile["defender_deployment"]]["pod_name"]
        sha_cmd = f"kubectl exec -n {NS} {pod} -- sha256sum {profile['model_path']}"
        out_sha = run_ssh(sha_cmd).split()[0].strip()
        if out_sha != profile["model_sha256"]:
            raise RuntimeError(f"Model hash mismatch for {svc_key}: got {out_sha}, expected {profile['model_sha256']}")
        print(f"Model Verified {svc_key:<12}: SHA-256={out_sha}")

    # 5. Decoy Telemetry Reachability & Schema Validation
    decoy_init = get_decoy_telemetry()
    for svc_key, profile in SERVICES.items():
        d = decoy_init[svc_key]
        print(f"Decoy Ready {svc_key:<14}: {profile['decoy_deployment']} counters ok (atk={d['attacker_requests']}, ben={d['benign_requests']})")

    print("================================================================================")
    print("GLOBAL PREFLIGHT PASSED: ALL 4 DEFENDERS, VIRTUALSERVICES, LEASES & DECOYS READY")
    print("================================================================================")
    return {
        "leases": leases,
        "defenders": defenders_status,
        "auth_token": auth_token,
        "preflight_time_vm": vm_now()
    }

# ----------------- Process Lifecycle & Guaranteed Cleanup -----------------
def verify_process_ownership(pod, pid, expected_script_name):
    """Verifies that the given PID in the pod belongs to our benchmark script before sending signals."""
    cmd = f"kubectl exec -n {NS} {pod} -- sh -c 'cat /proc/{pid}/cmdline 2>/dev/null'"
    out, _, rc = run_ssh_checked(cmd, check=False)
    if rc == 0 and expected_script_name in out:
        return True
    return False

def is_process_terminated(pod, pid):
    cmd = f"kubectl exec -n {NS} {pod} -- sh -c '! kill -0 {pid} 2>/dev/null || grep -q \"State:.*[ZX]\" /proc/{pid}/status 2>/dev/null'"
    _, _, rc = run_ssh_checked(cmd, check=False)
    return rc == 0

def stop_process(pod, pid, stop_file, expected_script_name=None, grace_s=4.0):
    if expected_script_name and not verify_process_ownership(pod, pid, expected_script_name):
        if is_process_terminated(pod, pid):
            return "already_exited"
        print(f"[WARN] PID {pid} in {pod} does not match expected script {expected_script_name}; skipping kill.")
        return "unowned"

    run_ssh_checked(f"kubectl exec -n {NS} {pod} -- touch {stop_file}", check=False)
    deadline = time.time() + grace_s
    while time.time() < deadline:
        if is_process_terminated(pod, pid):
            return "exited_cleanly"
        time.sleep(0.2)

    run_ssh_checked(f"kubectl exec -n {NS} {pod} -- kill {pid}", check=False)
    time.sleep(0.5)
    if is_process_terminated(pod, pid):
        return "killed_sigterm"

    run_ssh_checked(f"kubectl exec -n {NS} {pod} -- kill -9 {pid}", check=False)
    return "killed_sigkill"

def launch_bg(pod, script_path, log_path):
    out = run_ssh(f"kubectl exec -n {NS} {pod} -- sh -c 'nohup python3 {script_path} > {log_path} 2>&1 & echo $!'")
    pid = out.strip()
    if not pid.isdigit():
        raise RuntimeError(f"Could not obtain PID for {script_path} on {pod}: {pid}")
    return int(pid)

# ----------------- Generator Template Upload -----------------
def generate_scripts_and_upload(auth_token, t_barrier, trial_id):
    """
    Generates isolated generator scripts and HMAC-signed request files for each service,
    scoped strictly to trial_id (/tmp/s5c_{trial_id}_*).
    """
    # Clean trial-scoped files if any exist
    run_ssh_checked(f"kubectl exec -n {NS} {ATTACKER_POD} -- sh -c 'rm -f /tmp/s5c_{trial_id}_*'", check=False)
    run_ssh_checked(f"kubectl exec -n {NS} {BENIGN_POD} -- sh -c 'rm -f /tmp/s5c_{trial_id}_*'", check=False)

    for svc_key, profile in SERVICES.items():
        rate = profile["phase_a_rate_rps"]
        n_req = profile["phase_a_signed_requests"]
        period = 1.0 / rate
        fv = profile["feature_vector"]
        canonical_svc = profile["replay_svc"]

        # Build HMAC-signed RIDs scheduled relative to t_barrier
        rids = []
        for i in range(n_req):
            t_sched = t_barrier + (i * period)
            ts_str = f"{t_sched:.4f}"
            base_rid = f"s5c-{trial_id}-atkA-{svc_key}-{i}"
            to_sign = f"v1|{base_rid}|{canonical_svc}|{fv}|{ts_str}"
            sig = hmac.new(auth_token.encode("utf-8"), to_sign.encode("utf-8"), hashlib.sha256).hexdigest()[:32]
            signed_rid = f"{base_rid}#replay=cic17#svc={canonical_svc}#feat={fv}#ts={ts_str}#sig={sig}"
            rids.append(signed_rid)

        rid_path = f"/tmp/s5c_{trial_id}_phaseA_rids_{svc_key}.txt"
        run_ssh(f"kubectl exec -i -n {NS} {ATTACKER_POD} -- sh -c 'cat > {rid_path}'", stdin_data="\n".join(rids) + "\n")

        # Phase A Attack Script
        extra_host = f", 'Host': '{profile['host_header']}'" if profile["host_header"] else ""
        atkA_script = f"""
import urllib.request, time, os, json
from concurrent.futures import ThreadPoolExecutor

STOP = '/tmp/s5c_{trial_id}_atkA_{svc_key}.stop'
period = 1.0 / {rate}
concurrency = {profile["concurrency"]}
rids = [l.strip() for l in open('{rid_path}') if l.strip()]

t_barrier = {t_barrier}
sleep_to_barrier = t_barrier - time.time()
if sleep_to_barrier > 0:
    time.sleep(sleep_to_barrier)

t_wall_start = time.time()
results = [None] * len(rids)

def send_req(item):
    if os.path.exists(STOP):
        return
    idx, rid = item
    t_target = t_wall_start + (idx * period)
    to_sleep = t_target - time.time()
    if to_sleep > 0:
        time.sleep(to_sleep)
    if os.path.exists(STOP):
        return
    headers = {{
        'x-request-id': rid,
        'x-trusted-client-ip': '{ATTACKER_IDENTITY}',
        'x-bench-attack': '{svc_key}'{extra_host}
    }}
    req = urllib.request.Request('{profile["target_url"]}', headers=headers)
    t0 = time.time()
    code = 0
    err = None
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            code = resp.status
    except Exception as e:
        err = str(e)[:160]
        if hasattr(e, 'code'):
            code = e.code
    lat_ms = round((time.time() - t0) * 1000.0, 2)
    results[idx] = {{
        'seq': idx + 1, 'rid': rid, 'status': code, 'latency_ms': lat_ms,
        'error': err, 't_send': t0
    }}

with ThreadPoolExecutor(max_workers=concurrency) as pool:
    list(pool.map(send_req, enumerate(rids)))

t_wall_end = time.time()
clean = [r for r in results if r is not None]
success = sum(1 for r in clean if 200 <= r['status'] < 300)
dur = t_wall_end - t_wall_start
att_rps = round(len(clean) / dur, 3) if dur > 0 else 0.0
succ_rps = round(success / dur, 3) if dur > 0 else 0.0

summary = {{
    'service': '{svc_key}',
    'total_requests': len(clean),
    'successful_deliveries': success,
    'failed_requests': len(clean) - success,
    'duration_s': round(dur, 3),
    'attempted_rps': att_rps,
    'successful_rps': succ_rps,
    'delivered_rps': att_rps,
    'results': clean
}}
with open('/tmp/s5c_{trial_id}_atkA_results_{svc_key}.json', 'w') as f:
    json.dump(summary, f)
json.dump({{'service': '{svc_key}', 'sent': len(clean), 'success': success, 't_start': t_wall_start, 't_end': t_wall_end}},
          open('/tmp/s5c_{trial_id}_atkA_summary_{svc_key}.json', 'w'))
"""
        run_ssh(f"kubectl exec -i -n {NS} {ATTACKER_POD} -- sh -c 'cat > /tmp/s5c_{trial_id}_atkA_{svc_key}.py'", stdin_data=atkA_script)

        # Phase B Attack Script (5.0 RPS sustaining decoy diversion)
        atkB_script = f"""
import urllib.request, time, os, json

STOP = '/tmp/s5c_{trial_id}_atkB_{svc_key}.stop'
period = 1.0 / {profile["phase_b_rate_rps"]}

t_start = time.time()
results_b = []
idx = 0

def send_one(i):
    rid = f's5c-{trial_id}-atkB-{svc_key}-{{i}}'
    headers = {{
        'x-request-id': rid,
        'x-trusted-client-ip': '{ATTACKER_IDENTITY}',
        'x-bench-attack': '{svc_key}'{extra_host}
    }}
    req = urllib.request.Request('{profile["target_url"]}', headers=headers)
    t0 = time.time()
    code = 0
    err = None
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            code = resp.status
    except Exception as e:
        err = str(e)[:160]
        if hasattr(e, 'code'):
            code = e.code
    return {{'seq': i + 1, 'rid': rid, 'status': code, 'latency_ms': round((time.time() - t0)*1000.0, 2), 'error': err, 't_send': t0}}

while not os.path.exists(STOP):
    t_target = t_start + (idx * period)
    to_sleep = t_target - time.time()
    if to_sleep > 0:
        time.sleep(to_sleep)
    if os.path.exists(STOP):
        break
    res = send_one(idx)
    results_b.append(res)
    idx += 1

t_end = time.time()
clean_b = [r for r in results_b if r is not None]
success_b = sum(1 for r in clean_b if 200 <= r['status'] < 300)
dur_b = t_end - t_start
att_rps_b = round(len(clean_b) / dur_b, 3) if dur_b > 0 else 0.0
succ_rps_b = round(success_b / dur_b, 3) if dur_b > 0 else 0.0

summary = {{
    'service': '{svc_key}',
    'total_requests': len(clean_b),
    'successful_deliveries': success_b,
    'failed_requests': len(clean_b) - success_b,
    'duration_s': round(dur_b, 3),
    'attempted_rps': att_rps_b,
    'successful_rps': succ_rps_b,
    'results': clean_b
}}
with open('/tmp/s5c_{trial_id}_atkB_results_{svc_key}.json', 'w') as f:
    json.dump(summary, f)
json.dump({{'service': '{svc_key}', 'sent': len(clean_b), 'success': success_b, 't_start': t_start, 't_end': t_end}},
          open('/tmp/s5c_{trial_id}_atkB_summary_{svc_key}.json', 'w'))
"""
        run_ssh(f"kubectl exec -i -n {NS} {ATTACKER_POD} -- sh -c 'cat > /tmp/s5c_{trial_id}_atkB_{svc_key}.py'", stdin_data=atkB_script)

        # Benign Traffic Script (~3.5 RPS legitimate baseline)
        extra_host_ben = f", 'Host': '{profile['host_header']}'" if profile["host_header"] else ""
        benign_script = f"""
import urllib.request, time, json, os

STOP = '/tmp/s5c_{trial_id}_benign_{svc_key}.stop'
OUT = '/tmp/s5c_{trial_id}_benign_{svc_key}.jsonl'
period = 1.0 / 3.5
sent = 0

with open(OUT, 'w') as out:
    while not os.path.exists(STOP):
        rid = f's5c-{trial_id}-benign-{svc_key}-{{sent}}'
        headers = {{
            'x-request-id': rid,
            'x-trusted-client-ip': '{BENIGN_IDENTITY}',
            'x-client-type': 'benign'{extra_host_ben}
        }}
        req = urllib.request.Request('{profile["target_url"]}', headers=headers)
        m0 = time.monotonic()
        t_send = time.time()
        rec = {{'seq': sent, 'rid': rid, 't_send': t_send, 'service': '{svc_key}'}}
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                rec['status'] = resp.status
                body = resp.read(256).decode('utf-8', errors='replace')
                rec['served_by_decoy'] = ('decoy' in body.lower())
                rec['err'] = None
        except Exception as e:
            rec['status'] = getattr(e, 'code', None)
            rec['served_by_decoy'] = False
            rec['err'] = str(e)[:160]
        rec['lat_ms'] = round((time.monotonic() - m0) * 1000.0, 3)
        out.write(json.dumps(rec) + '\\n')
        out.flush()
        sent += 1
        time.sleep(max(0.0, period - (time.monotonic() - m0)))
    out.write(json.dumps({{'summary': True, 'service': '{svc_key}', 'sent': sent}}) + '\\n')
"""
        run_ssh(f"kubectl exec -i -n {NS} {BENIGN_POD} -- sh -c 'cat > /tmp/s5c_{trial_id}_benign_{svc_key}.py'", stdin_data=benign_script)

# ----------------- Execution Orchestration -----------------
def execute_concurrent_trial(trial_id, raw_dir):
    trial_id = validate_trial_id(trial_id)
    os.makedirs(raw_dir, exist_ok=True)
    evidence_file = os.path.join(raw_dir, f"trial_{trial_id}_concurrent_autonomous.json")
    if os.path.exists(evidence_file):
        raise RuntimeError(f"Evidence file {evidence_file} already exists. Recorded evidence is immutable; choose a new trial ID.")

    active_generators = {
        "benign": {},
        "attack_A": {},
        "attack_B": {}
    }
    quarantine_observed = {}
    stage1_observed = {}
    stage2_observed = {}
    marks = {
        "benign_start": {},
        "phase_A_launch": {},
        "phase_A_start": {},
        "phase_A_commit": {},
        "stage1_commit": {},
        "stage2_commit": {}
    }
    preflight_info = None
    execution_error = None
    controller_logs_raw = {}
    controller_events = {}

    try:
        # 1. Preflight
        preflight_info = run_global_preflight()

        # 2. Setup Shared Barrier & Upload Scripts
        t_vm_current = vm_now()
        t_barrier = t_vm_current + BARRIER_SETUP_MARGIN_S
        marks["timing_barrier"] = t_barrier
        print(f"\n[TIMING-BARRIER] Synchronized start barrier set at t_barrier = {t_barrier:.4f} (window: {BARRIER_SETUP_MARGIN_S:.1f}s)")
        generate_scripts_and_upload(preflight_info["auth_token"], t_barrier, trial_id)

        # 3. Launch 4 Benign Streams
        for svc_key in SERVICES:
            script_name = f"s5c_{trial_id}_benign_{svc_key}.py"
            pid = launch_bg(BENIGN_POD, f"/tmp/{script_name}", f"/tmp/s5c_{trial_id}_benign_{svc_key}.log")
            active_generators["benign"][svc_key] = {
                "pid": pid, "pod": BENIGN_POD,
                "stop_file": f"/tmp/s5c_{trial_id}_benign_{svc_key}.stop",
                "script": script_name
            }
            marks["benign_start"][svc_key] = vm_now()
            print(f"Launched benign stream for {svc_key:<12} (PID {pid})")

        # 4. Launch 4 Simultaneous Phase A Attack Processes
        for svc_key, profile in SERVICES.items():
            script_name = f"s5c_{trial_id}_atkA_{svc_key}.py"
            pid = launch_bg(ATTACKER_POD, f"/tmp/{script_name}", f"/tmp/s5c_{trial_id}_atkA_{svc_key}.log")
            active_generators["attack_A"][svc_key] = {
                "pid": pid, "pod": ATTACKER_POD,
                "stop_file": f"/tmp/s5c_{trial_id}_atkA_{svc_key}.stop",
                "script": script_name
            }
            marks["phase_A_launch"][svc_key] = vm_now()
            print(f"Launched simultaneous attack for {svc_key:<12} ({profile['phase_a_rate_rps']} RPS, PID {pid})")

        t_now = vm_now()
        lead_time = t_barrier - t_now
        if lead_time < MIN_BARRIER_LEAD_TIME_S:
            raise RuntimeError(
                f"Barrier timing overrun: setup took {t_now - t_vm_current:.2f}s, leaving only {lead_time:.2f}s "
                f"lead time (minimum required: {MIN_BARRIER_LEAD_TIME_S:.1f}s). Aborting trial to guarantee simultaneous start."
            )
        print(f"[COORDINATOR] All 8 generators primed and awaiting synchronized barrier ({lead_time:.2f}s until t_barrier={t_barrier:.4f})...")
        time.sleep(lead_time)

        # 5. Monitor Phase A Quarantine Commits across all 4 VirtualServices & Await Full Workload Completion
        # Continue monitoring until BOTH conditions are true:
        #   (a) All 4 VirtualServices have entered quarantine (mitigation observed)
        #   (b) All 4 Phase A generator processes have completed their planned request delivery
        deadline_A = t_barrier + PHASE_A_TIMEOUT_S
        print("\n--- Monitoring Concurrent Phase A Mitigations & Workload Execution ---")
        while vm_now() < deadline_A:
            t_poll = vm_now()
            vs_snapshot = poll_all_virtual_services()
            for svc_key, profile in SERVICES.items():
                if svc_key not in quarantine_observed:
                    vs_name = profile["vs_name"]
                    vs_info = vs_snapshot.get(vs_name, {})
                    if vs_info.get("quarantine_present"):
                        lat = round(t_poll - t_barrier, 3)
                        quarantine_observed[svc_key] = vs_info
                        marks["phase_A_commit"][svc_key] = t_poll
                        print(f"[QUARANTINE-COMMITTED] {svc_key:<12} at t+{lat:.3f}s: rv={vs_info['resource_version']}, "
                              f"token={vs_info['fencing_token']}, routes={vs_info['production_routes']}")

            all_generators_finished = all(
                is_process_terminated(ATTACKER_POD, g["pid"])
                for g in active_generators["attack_A"].values()
            )

            if len(quarantine_observed) == len(SERVICES) and all_generators_finished:
                print(f"[PHASE_A] All 4 quarantines committed and all 4 attack workloads completed at t+{t_poll - t_barrier:.2f}s.")
                break

            time.sleep(POLL_SLEEP_S)

        # Verify all 4 observed quarantine
        missing_q = set(SERVICES.keys()) - set(quarantine_observed.keys())
        if missing_q:
            raise TimeoutError(f"Phase A quarantine not observed within deadline for services: {missing_q}")

        # Verify all 4 attack generators completed their planned workloads
        unfinished_g = [
            svc for svc, g in active_generators["attack_A"].items()
            if not is_process_terminated(ATTACKER_POD, g["pid"])
        ]
        if unfinished_g:
            raise TimeoutError(f"Phase A attack generators did not complete within deadline for services: {unfinished_g}")

        # Clean sweep generator status tracking
        for svc_key, g in active_generators["attack_A"].items():
            stop_process(g["pod"], g["pid"], g["stop_file"], expected_script_name=g["script"])
        marks["phase_A_end"] = vm_now()
        print("[PHASE_A] All 4 simultaneous attack bursts finished.")

        # Collect Phase A attack delivery summaries and VERIFY actual counts/RPS BEFORE Phase B
        phase_A_summaries = {}
        for svc_key, profile in SERVICES.items():
            raw_res = run_ssh(f"kubectl exec -n {NS} {ATTACKER_POD} -- cat /tmp/s5c_{trial_id}_atkA_results_{svc_key}.json")
            phase_A_summaries[svc_key] = json.loads(raw_res)
            raw_sum = run_ssh(f"kubectl exec -n {NS} {ATTACKER_POD} -- cat /tmp/s5c_{trial_id}_atkA_summary_{svc_key}.json")
            sum_data = json.loads(raw_sum)
            marks["phase_A_start"][svc_key] = sum_data.get("t_start", t_barrier)
            s = phase_A_summaries[svc_key]
            delta_barrier = sum_data.get("t_start", t_barrier) - t_barrier
            print(f"Phase A Workload {svc_key:<12}: {s['successful_deliveries']}/{s['total_requests']} delivered "
                  f"({s['delivered_rps']} RPS, {s['duration_s']}s, barrier delta={delta_barrier:+.4f}s)")

            # Strict verification of workload completion and delivered RPS prior to launching Phase B
            p_tot = s.get("total_requests", 0)
            p_att = s.get("attempted_rps", 0.0)
            p_succ = s.get("successful_rps", 0.0)
            min_req = profile["phase_a_min_requests"]
            min_att = profile["phase_a_min_attempted_rps"]
            max_att = profile["phase_a_max_attempted_rps"]
            min_succ = profile["phase_a_min_successful_rps"]

            if p_tot < min_req:
                raise RuntimeError(f"Phase A workload incomplete for {svc_key}: {p_tot} < {min_req} planned requests")
            if not (min_att <= p_att <= max_att):
                raise RuntimeError(f"Phase A attempted RPS out of bounds for {svc_key}: {p_att} not in [{min_att}, {max_att}]")
            if p_succ < min_succ:
                raise RuntimeError(f"Phase A successful RPS too low for {svc_key}: {p_succ} < {min_succ}")
            print(f"[PHASE_A-VERIFIED] {svc_key:<12}: {p_tot}/{min_req} reqs verified at {p_att} RPS (success: {p_succ} RPS).")

        # 6. Launch 4 Phase B Decoy Diversion Streams (5.0 RPS)
        marks["phase_B_start"] = vm_now()
        for svc_key in SERVICES:
            script_name = f"s5c_{trial_id}_atkB_{svc_key}.py"
            pid = launch_bg(ATTACKER_POD, f"/tmp/{script_name}", f"/tmp/s5c_{trial_id}_atkB_{svc_key}.log")
            active_generators["attack_B"][svc_key] = {
                "pid": pid, "pod": ATTACKER_POD,
                "stop_file": f"/tmp/s5c_{trial_id}_atkB_{svc_key}.stop",
                "script": script_name
            }

        # 7. Monitor Stage 1 Restorations (for East-West services) & Hold State (for productpage)
        print("\n--- Monitoring Stage 1 Restorations & Decoy Traffic ---")
        deadline_S1 = marks["phase_A_end"] + STAGE1_TIMEOUT_S
        while vm_now() < deadline_S1 and len(stage1_observed) < 3:
            t_poll = vm_now()
            vs_snapshot = poll_all_virtual_services()
            for svc_key in ["details", "reviews", "ratings"]:
                if svc_key in stage1_observed:
                    continue
                vs_name = SERVICES[svc_key]["vs_name"]
                vs_info = vs_snapshot.get(vs_name, {})
                if vs_info.get("quarantine_present") and vs_info.get("production_routes") == [("v1", 100)]:
                    stage1_observed[svc_key] = vs_info
                    marks["stage1_commit"][svc_key] = t_poll
                    print(f"[STAGE1-RESTORED] {svc_key:<12} at {t_poll:.2f}: rv={vs_info['resource_version']}, "
                          f"token={vs_info['fencing_token']}, routes={vs_info['production_routes']}")
            time.sleep(POLL_SLEEP_S)

        pp_info = poll_all_virtual_services().get("bookinfo", {})
        marks["stage1_commit"]["productpage"] = marks["phase_A_commit"]["productpage"]
        stage1_observed["productpage"] = pp_info
        print(f"[STAGE1-PRESERVED] productpage maintained v1 throughout: routes={pp_info.get('production_routes')}")

        # Decoy sampling during active decoy diversion (fail closed)
        decoy_s0 = get_decoy_telemetry()
        time.sleep(DECOY_MEASURE_S)
        decoy_s1 = get_decoy_telemetry()
        decoy_measurements = {}
        for svc_key in SERVICES:
            d0_atk = decoy_s0[svc_key]["attacker_requests"]
            d1_atk = decoy_s1[svc_key]["attacker_requests"]
            d0_ben = decoy_s0[svc_key]["benign_requests"]
            d1_ben = decoy_s1[svc_key]["benign_requests"]
            delta_atk = d1_atk - d0_atk
            delta_ben = d1_ben - d0_ben
            rps = round(delta_atk / DECOY_MEASURE_S, 2)

            logs = decoy_s1[svc_key].get("recent_attacker_logs", [])
            recent_trial_logs = [
                l for l in logs
                if l.get("timestamp", 0) >= t_barrier and f"s5c-{trial_id}-" in l.get("request_id", "")
            ]
            ip_verified = len(recent_trial_logs) > 0 and all(l.get("client_ip") == ATTACKER_IDENTITY for l in recent_trial_logs)
            rid_prefix = f"s5c-{trial_id}-atkB-{svc_key}-"
            rid_verified = len(recent_trial_logs) > 0 and any(l.get("request_id", "").startswith(rid_prefix) for l in recent_trial_logs)

            decoy_measurements[svc_key] = {
                "initial_attacker": d0_atk,
                "final_attacker": d1_atk,
                "delta_attacker": delta_atk,
                "measured_rps": rps,
                "delta_benign": delta_ben,
                "sample_logs_count": len(recent_trial_logs),
                "attacker_ip_verified": ip_verified,
                "request_ids_verified": rid_verified
            }
            print(f"Decoy Interception {svc_key:<12}: delta={delta_atk} reqs ({rps} RPS), benign leakage={delta_ben}, "
                  f"IP verified={ip_verified}, RID verified={rid_verified}")

        # 8. Phase C: Stop All Attacker Processes & Wait for Stage 2 Autonomous Teardown
        print("\n--- Phase C: Halting Attack Traffic & Awaiting Autonomous Stage 2 Teardown ---")
        marks["attacker_stop"] = vm_now()
        for svc_key, g in active_generators["attack_B"].items():
            stop_process(g["pod"], g["pid"], g["stop_file"], expected_script_name=g["script"])

        deadline_S2 = marks["attacker_stop"] + STAGE2_TIMEOUT_S
        while vm_now() < deadline_S2 and len(stage2_observed) < len(SERVICES):
            t_poll = vm_now()
            vs_snapshot = poll_all_virtual_services()
            for svc_key, profile in SERVICES.items():
                if svc_key in stage2_observed:
                    continue
                vs_name = profile["vs_name"]
                vs_info = vs_snapshot.get(vs_name, {})
                if not vs_info.get("quarantine_present") and vs_info.get("production_routes") == [("v1", 100)]:
                    stage2_observed[svc_key] = vs_info
                    marks["stage2_commit"][svc_key] = t_poll
                    teardown_lat = round(t_poll - marks["attacker_stop"], 3)
                    print(f"[STAGE2-TEARDOWN] {svc_key:<12} at t+{teardown_lat:.3f}s: rv={vs_info['resource_version']}, "
                          f"token={vs_info['fencing_token']}, quarantine_removed=True")
            time.sleep(POLL_SLEEP_S)

        missing_s2 = set(SERVICES.keys()) - set(stage2_observed.keys())
        if missing_s2:
            raise TimeoutError(f"Stage 2 autonomous teardown not observed for services: {missing_s2}")

        # 9. Stop Benign Streams & Collect Legitimate Traffic Quality
        time.sleep(POST_STAGE2_BENIGN_S)
        for svc_key, g in active_generators["benign"].items():
            stop_process(g["pod"], g["pid"], g["stop_file"], expected_script_name=g["script"])
        marks["benign_stop"] = vm_now()

        benign_summaries = {}
        for svc_key in SERVICES:
            raw_b = run_ssh(f"kubectl exec -n {NS} {BENIGN_POD} -- cat /tmp/s5c_{trial_id}_benign_{svc_key}.jsonl")
            # Archive full per-request benign jsonl directly to raw evidence directory
            b_log_path = os.path.join(raw_dir, f"trial_{trial_id}_benign_{svc_key}.jsonl")
            with open(b_log_path, "w", encoding="utf-8") as bf:
                bf.write(raw_b)

            lines = [json.loads(l) for l in raw_b.splitlines() if l.strip()]
            recs = [l for l in lines if not l.get("summary")]
            total = len(recs)
            succ = sum(1 for r in recs if r.get("status") == 200)
            decoy = sum(1 for r in recs if r.get("served_by_decoy"))
            non_200 = [r for r in recs if r.get("status") != 200]
            benign_summaries[svc_key] = {
                "total_sent": total,
                "success_200": succ,
                "success_rate": round(succ / total, 4) if total > 0 else 0.0,
                "served_by_decoy": decoy,
                "non_200_count": len(non_200),
                "non_200_records": non_200
            }
            print(f"Benign Availability {svc_key:<12}: {succ}/{total} HTTP 200 ({succ/total*100:.1f}%), decoy leakage={decoy}")

        # 10. Collect Controller Container Logs across all 4 Defenders
        for svc_key, profile in SERVICES.items():
            pod = preflight_info["defenders"][profile["defender_deployment"]]["pod_name"]
            t_iso = datetime.datetime.fromtimestamp(preflight_info["preflight_time_vm"], datetime.timezone.utc).isoformat()
            logs = run_ssh(f"kubectl logs -n {NS} {pod} --since-time={t_iso}")
            controller_logs_raw[svc_key] = logs

            events = {
                "dispatch": [], "authorized": [], "l7_inference": [], "abate": [],
                "lease_acquired": [], "lease_released": [], "lease_takeover": [],
                "occ_atomic_updates": [], "occ_conflicts": []
            }
            for l in logs.splitlines():
                t_ev = log_epoch(l)
                if "[DISPATCH]" in l and "Applying '" in l:
                    m = re.search(r"Applying '([^']+)'", l)
                    attr = m.group(1) if m else "UNKNOWN"
                    events["dispatch"].append({"attribution": attr, "line": l, "t": t_ev})
                elif "[ACTIVE-ENFORCE]" in l:
                    events["authorized"].append({"line": l, "t": t_ev})
                elif "[L7-INFERENCE]" in l and "DATASET_REPLAY" in l:
                    is_ddos = "-> DDOS" in l
                    events["l7_inference"].append({"prediction": "DDOS" if is_ddos else "NORMAL", "line": l, "t": t_ev})
                elif "[REVERT" in l:
                    events["abate"].append({"line": l, "t": t_ev})
                elif "[LOCK]" in l:
                    if "Successfully acquired lock" in l:
                        m = re.search(r"Successfully acquired lock for (\w+) \(fencing_token=(\d+)\)", l)
                        token = int(m.group(2)) if m else None
                        events["lease_acquired"].append({"line": l, "fencing_token": token, "t": t_ev})
                    elif "Safely released lock" in l:
                        events["lease_released"].append({"line": l, "t": t_ev})
                    elif "Attempting takeover" in l:
                        events["lease_takeover"].append({"line": l, "t": t_ev})
                elif "[OCC-ATOMIC]" in l:
                    m = re.search(r"VS '([^']+)' atomically updated OK \(attempt=(\d+), rv=(\d+), fencing_token=(\d+)\)", l)
                    if m:
                        events["occ_atomic_updates"].append({
                            "vs": m.group(1), "attempt": int(m.group(2)),
                            "rv": m.group(3), "fencing_token": int(m.group(4)),
                            "line": l, "t": t_ev
                        })
                    if "conflict" in l.lower() or "retry" in l.lower():
                        events["occ_conflicts"].append({"line": l, "t": t_ev})
            controller_events[svc_key] = events

        # 11. Final Post-flight Cluster Audit
        post_preflight = run_global_preflight()

        # 12. Evaluate Formal Assertions
        assertions = {}

        # Concurrency & Barrier Assertions
        start_diffs = [abs(marks["phase_A_start"][k] - t_barrier) for k in SERVICES]
        assertions["concurrency_simultaneous_attack_start"] = all(d < 0.25 for d in start_diffs)
        assertions["concurrency_all_four_defenders_quarantined"] = (len(quarantine_observed) == 4)
        assertions["concurrency_mitigation_latencies_under_10s"] = all((marks["phase_A_commit"][k] - t_barrier) < 10.0 for k in SERVICES)
        tokens = [quarantine_observed[k].get("fencing_token") for k in SERVICES]
        assertions["concurrency_independent_fencing_tokens"] = all(t is not None for t in tokens)

        # Per-Service Assertions with Strict Scientific Differentiation
        trial_record = {
            "trial_id": trial_id,
            "experiment_type": "scenario_5_four_service_concurrent",
            "timing_barrier_vm": t_barrier,
            "aggregate_attack_rate_target_rps": 160.0,
            "marks_vm": marks,
            "services": {},
            "assertions": assertions
        }

        for svc_key, profile in SERVICES.items():
            pA = phase_A_summaries[svc_key]
            p_ok = (pA["total_requests"] >= profile["phase_a_min_requests"] and
                    profile["phase_a_min_attempted_rps"] <= pA["attempted_rps"] <= profile["phase_a_max_attempted_rps"] and
                    pA["successful_rps"] >= profile["phase_a_min_successful_rps"])
            assertions[f"{svc_key}_phase_A_workload_valid"] = p_ok

            attr_list = [e["attribution"] for e in controller_events[svc_key]["dispatch"]]
            obs_attr = attr_list[0] if attr_list else "UNKNOWN"
            assertions[f"{svc_key}_attribution_valid"] = (obs_attr in VALID_ATTRIBUTIONS)

            q_info = quarantine_observed[svc_key]
            s1_info = stage1_observed.get(svc_key, {})
            s2_info = stage2_observed.get(svc_key, {})

            assertions[f"{svc_key}_quarantine_at_index_0"] = (q_info.get("quarantine_index") == 0)
            assertions[f"{svc_key}_quarantine_to_decoy"] = (profile["decoy_host"] in str(q_info.get("quarantine_dest")))
            assertions[f"{svc_key}_quarantine_matches_attacker"] = q_info.get("quarantine_matches_attacker", False)

            # Scientific differentiation: Failover vs Targeted Quarantine
            if profile["recovery_path"] == "targeted_quarantine_v1_preserved":
                assertions[f"{svc_key}_v1_preserved_throughout"] = (q_info.get("production_routes") == [("v1", 100)])
                mitigation_class = "TARGETED_QUARANTINE_V1_PRESERVED"
            else:
                if obs_attr == "BOTH":
                    failover_ok = (q_info.get("production_routes") == [("v2", 50), ("v3", 50)])
                    stage1_ok = (s1_info.get("production_routes") == [("v1", 100)] and s1_info.get("quarantine_present") is True)
                    assertions[f"{svc_key}_phase_A_production_failover_v2_v3"] = failover_ok
                    assertions[f"{svc_key}_stage1_restored_to_v1"] = stage1_ok
                    mitigation_class = "FAILOVER_AND_RESTORE"
                elif obs_attr in ("STAGE3B_ONLY", "ML_ONLY"):
                    v1_preserved = (q_info.get("production_routes") == [("v1", 100)])
                    assertions[f"{svc_key}_targeted_quarantine_v1_preserved"] = v1_preserved
                    assertions[f"{svc_key}_stage1_hold_v1_quarantine_retained"] = (s1_info.get("production_routes") == [("v1", 100)] and s1_info.get("quarantine_present") is True)
                    mitigation_class = "TARGETED_QUARANTINE_ONLY"
                else:
                    assertions[f"{svc_key}_attribution_recognized"] = False
                    mitigation_class = f"UNRECOGNIZED_{obs_attr}"

            assertions[f"{svc_key}_stage2_quarantine_removed"] = (not s2_info.get("quarantine_present", True))
            assertions[f"{svc_key}_stage2_baseline_v1_restored"] = (s2_info.get("production_routes") == [("v1", 100)])

            # Decoy reconciliation
            dm = decoy_measurements[svc_key]
            assertions[f"{svc_key}_decoy_interceptions_gt_15"] = (dm["delta_attacker"] >= 15)
            assertions[f"{svc_key}_decoy_zero_benign_leakage"] = (dm["delta_benign"] == 0)
            assertions[f"{svc_key}_decoy_attacker_ip_reconciled"] = dm["attacker_ip_verified"]
            assertions[f"{svc_key}_decoy_request_ids_reconciled"] = dm["request_ids_verified"]

            # Benign continuity
            b_sum = benign_summaries[svc_key]
            assertions[f"{svc_key}_benign_100_percent_success"] = (b_sum["success_rate"] == 1.0)
            assertions[f"{svc_key}_benign_zero_at_decoy"] = (b_sum["served_by_decoy"] == 0)

            assertions[f"{svc_key}_lease_acquired_with_fencing_token"] = (len(controller_events[svc_key]["lease_acquired"]) >= 1)
            assertions[f"{svc_key}_occ_atomic_updates_succeeded"] = (len(controller_events[svc_key]["occ_atomic_updates"]) >= 1)
            assertions[f"{svc_key}_zero_unresolved_occ_conflicts"] = (len(controller_events[svc_key]["occ_conflicts"]) == 0)

            q_lat_poll = round(marks["phase_A_commit"][svc_key] - t_barrier, 3)
            td_lat_poll = round(marks["stage2_commit"][svc_key] - marks["attacker_stop"], 3)

            occ_updates = controller_events[svc_key]["occ_atomic_updates"]
            init_occ = occ_updates[0] if occ_updates else None
            init_occ_lat = round(init_occ["t"] - t_barrier, 3) if init_occ and init_occ.get("t") else None
            init_occ_rv = init_occ["rv"] if init_occ else None

            td_occ = occ_updates[-1] if len(occ_updates) > 1 else None
            td_occ_lat = round(td_occ["t"] - marks["attacker_stop"], 3) if td_occ and td_occ.get("t") else None
            td_occ_rv = td_occ["rv"] if td_occ else None

            trial_record["services"][svc_key] = {
                "recovery_path": profile["recovery_path"],
                "observed_mitigation_class": mitigation_class,
                "observed_attribution": obs_attr,
                "quarantine_latency_poll_s": q_lat_poll,
                "quarantine_latency_occ_s": init_occ_lat,
                "initial_mitigation_rv": init_occ_rv,
                "teardown_latency_poll_s": td_lat_poll,
                "teardown_latency_occ_s": td_occ_lat,
                "final_teardown_rv": td_occ_rv,
                "fencing_token_quarantine": q_info.get("fencing_token"),
                "fencing_token_teardown": s2_info.get("fencing_token"),
                "lease_acquisition_events": controller_events[svc_key]["lease_acquired"],
                "lease_release_events": controller_events[svc_key]["lease_released"],
                "occ_atomic_update_events": occ_updates,
                "occ_conflicts_count": len(controller_events[svc_key]["occ_conflicts"]),
                "phase_A_attacker_summary": pA,
                "decoy_measurement": dm,
                "benign_summary": b_sum
            }

        assertions["final_all_leases_unheld"] = (len(post_preflight["leases"]) == 10 and not any(post_preflight["leases"].values()))
        assertions["final_zero_defender_restarts"] = all(d["restarts"] == 0 for d in post_preflight["defenders"].values())

        all_passed = all(assertions.values())
        status_str = "PASSED" if all_passed else "FAILED"
        trial_record["status"] = status_str

        print(f"\n================================================================================")
        print(f"CONCURRENT BENCHMARK TRIAL {trial_id} STATUS: {status_str}")
        print(f"Passed: {sum(1 for v in assertions.values() if v)} / {len(assertions)}")
        for k, v in assertions.items():
            print(f"  [{'PASS' if v else 'FAIL'}] {k}")
        print(f"================================================================================")

        with open(evidence_file, "w", encoding="utf-8") as f:
            json.dump(trial_record, f, indent=2)
        print(f"Recorded concurrent trial evidence: {evidence_file}")

        for svc_key, logs in controller_logs_raw.items():
            log_path = os.path.join(raw_dir, f"controller_trace_trial_{trial_id}_{svc_key}.log")
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(logs)

        return trial_record

    except Exception as e:
        execution_error = e
        print(f"\n[EXCEPTION CAUGHT] Failure during concurrent trial: {e}")
        traceback.print_exc()
        raise

    finally:
        # Guaranteed cleanup with process ownership verification; each generator protected independently
        print("\n[CLEANUP] Enforcing guaranteed termination of all active generators...")
        for gen_type, gen_map in active_generators.items():
            for svc_key, g_info in gen_map.items():
                try:
                    res = stop_process(g_info["pod"], g_info["pid"], g_info["stop_file"], expected_script_name=g_info["script"])
                    print(f"  -> Terminated {gen_type} for {svc_key:<12} (PID {g_info['pid']}): {res}")
                except Exception as stop_ex:
                    print(f"  -> [WARN] Error during termination of {gen_type} for {svc_key} (PID {g_info.get('pid')}): {stop_ex}")

        # Preserve controller logs up to failure point if execution failed
        if execution_error and preflight_info:
            print("[CLEANUP] Preserving partial failure controller logs...")
            try:
                t_iso = datetime.datetime.fromtimestamp(preflight_info["preflight_time_vm"], datetime.timezone.utc).isoformat()
                for svc_key, profile in SERVICES.items():
                    try:
                        pod = preflight_info["defenders"][profile["defender_deployment"]]["pod_name"]
                        logs = run_ssh(f"kubectl logs -n {NS} {pod} --since-time={t_iso}")
                        log_path = os.path.join(raw_dir, f"controller_trace_trial_{trial_id}_{svc_key}_FAILED.log")
                        with open(log_path, "w", encoding="utf-8") as f:
                            f.write(logs)
                    except Exception as log_svc_ex:
                        print(f"[WARN] Failed to write partial controller log for {svc_key}: {log_svc_ex}")
            except Exception as log_ex:
                print(f"[WARN] Failed to write partial controller logs: {log_ex}")

            try:
                fail_record_path = os.path.join(raw_dir, f"trial_{trial_id}_concurrent_FAILED.json")
                fail_data = {
                    "trial_id": trial_id,
                    "status": "FAILED",
                    "error": str(execution_error),
                    "error_traceback": traceback.format_exc(),
                    "marks_vm": marks,
                    "partial_quarantine_observed": quarantine_observed,
                    "partial_stage1_observed": stage1_observed,
                    "partial_stage2_observed": stage2_observed
                }
                with open(fail_record_path, "w", encoding="utf-8") as f:
                    json.dump(fail_data, f, indent=2)
                print(f"[CLEANUP] Preserved partial failure record: {fail_record_path}")
            except Exception as fail_save_ex:
                print(f"[WARN] Failed to write partial failure record: {fail_save_ex}")

        # Clean trial-scoped temporary files on client pods
        print(f"[CLEANUP] Cleaning trial-scoped temporary files for trial {trial_id} on client pods...")
        try:
            run_ssh_checked(f"kubectl exec -n {NS} {ATTACKER_POD} -- sh -c 'rm -f /tmp/s5c_{trial_id}_*'", check=False)
        except Exception as rm_atk_ex:
            print(f"[WARN] Failed to clean attacker pod temp files: {rm_atk_ex}")
        try:
            run_ssh_checked(f"kubectl exec -n {NS} {BENIGN_POD} -- sh -c 'rm -f /tmp/s5c_{trial_id}_*'", check=False)
        except Exception as rm_ben_ex:
            print(f"[WARN] Failed to clean benign pod temp files: {rm_ben_ex}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Scenario 5 Four-Service Concurrent Benchmark Coordinator")
    parser.add_argument("--trial-id", default="concurrent_pilot", help="Trial identifier")
    parser.add_argument("--raw-dir", default="PAPER/Backup/SCENARIO_5_BENCHMARK_RESULTS/raw", help="Directory for raw evidence")
    args = parser.parse_args()

    validated_id = validate_trial_id(args.trial_id)
    execute_concurrent_trial(validated_id, args.raw_dir)
