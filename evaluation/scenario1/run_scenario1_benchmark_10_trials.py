import paramiko
import json
import time
import uuid
import os
import sys
import base64
import re
import numpy as np
from datetime import datetime

sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.160.129', username='osu', password='osu', timeout=10)

def exec_cmd(cmd):
    stdin, stdout, stderr = ssh.exec_command(cmd)
    return stdout.read().decode('utf-8', errors='ignore').strip(), stderr.read().decode('utf-8', errors='ignore').strip()

results_dir = os.path.join("PAPER", "Backup", "SCENARIO_1_BENCHMARK_RESULTS")
os.makedirs(results_dir, exist_ok=True)

# Clean previous trial files
for f in os.listdir(results_dir):
    p = os.path.join(results_dir, f)
    if os.path.isfile(p):
        os.remove(p)
print(f"[+] Cleaned results directory: {results_dir}")

# 1. Retrieve Current Rotated Benchmark Auth Token from Kubernetes Secret
raw_b64, _ = exec_cmd("kubectl get secret ddos-bench-auth -n default -o jsonpath='{.data.token}'")
bench_auth_token = base64.b64decode(raw_b64).decode().strip()
print(f"[+] Retrieved active benchmark auth token from Secret (len={len(bench_auth_token)})")

# 2. Attack Vector: DoS Hulk against details from held-out catalog
feat_str = "6.0,6.0,349.0,11595.0,58.16666666666666,1932.5,1.0"

def parse_cgroup(pod_name):
    raw, _ = exec_cmd(f"kubectl exec {pod_name} -- cat /sys/fs/cgroup/cpu.stat")
    data = {}
    for line in raw.splitlines():
        parts = line.strip().split()
        if len(parts) == 2:
            try:
                data[parts[0]] = int(parts[1])
            except ValueError:
                data[parts[0]] = parts[1]
    return data

def wait_for_clean_baseline(timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        vs_raw, _ = exec_cmd("kubectl get vs details -o json")
        lease_raw, _ = exec_cmd("kubectl get lease details-mitigation-lock -o json")
        try:
            vs = json.loads(vs_raw)
            l = json.loads(lease_raw)
            http_rules = vs.get("spec", {}).get("http", [])
            holder = str(l.get("spec", {}).get("holderIdentity") or "").strip()
            if len(http_rules) == 1 and http_rules[0].get("name") == "normal-production" and not holder:
                return True, vs["metadata"]["resourceVersion"]
        except Exception:
            pass
        time.sleep(1)
    return False, None

def check_other_leases():
    other_leases = ["product-mitigation-lock", "reviews-mitigation-lock", "ratings-mitigation-lock"]
    holders = {}
    for lname in other_leases:
        raw, _ = exec_cmd(f"kubectl get lease {lname} -o json")
        try:
            lj = json.loads(raw)
            holders[lname] = str(lj.get("spec", {}).get("holderIdentity") or "").strip()
        except Exception:
            holders[lname] = "UNKNOWN"
    all_free = all(h == "" for h in holders.values())
    return all_free, holders

def parse_log_timestamp(line):
    m = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})", line)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S,%f")
            return dt.timestamp()
        except Exception:
            pass
    return None

def extract_controller_timings(pod_logs):
    t_detect = None
    t_lock = None
    t_occ = None
    t_revert = None
    t_release = None

    for line in pod_logs.splitlines():
        ts = parse_log_timestamp(line)
        if not ts:
            continue
        if ("[STAGE3B] Target identified" in line or "[ML]" in line or "DDoS Attack Detected" in line) and "details" in line:
            if t_detect is None:
                t_detect = ts
        if "[LOCK]" in line and "acquired lock for details" in line:
            if t_lock is None:
                t_lock = ts
        if ("[PATCH-OCC]" in line or "Successfully committed mitigation VirtualService" in line) and "details" in line:
            if t_occ is None:
                t_occ = ts
        if "[REVERT]" in line and "Executing recovery for 'details'" in line:
            if t_revert is None:
                t_revert = ts
        if "[REVERT]" in line and "Lock RELEASED" in line and "details" in line:
            if t_release is None:
                t_release = ts

    return {
        "t_detect": t_detect,
        "t_lock": t_lock,
        "t_occ": t_occ,
        "t_revert": t_revert,
        "t_release": t_release
    }

def run_single_trial(architecture, trial_num, controller_pod):
    print(f"\n" + "=" * 75)
    print(f"STARTING TRIAL {trial_num}/10 — ARCHITECTURE: {architecture.upper()}")
    print("=" * 75)
    sys.stdout.flush()

    # 1. Clean Baseline Verification
    ok, base_rv = wait_for_clean_baseline()
    assert ok, f"Cluster did not reach clean baseline for trial {trial_num}"
    print(f"  [+] Baseline confirmed. VirtualService details resourceVersion={base_rv}")

    # 2. Capture Pre-Trial Cgroup Stats
    cgroup_pre = parse_cgroup(controller_pod)

    # 3. Launch Benign Background Traffic Generator from client-benign (35 seconds, 4 services)
    benign_script = """python3 -c "
import urllib.request, time, json
services = ['productpage:9080/productpage', 'details:9080/details/0', 'reviews:9080/reviews/0', 'ratings:9080/ratings/0']
latencies = {s.split(':')[0]: [] for s in services}
errors = {s.split(':')[0]: 0 for s in services}
t_end = time.time() + 35.0
while time.time() < t_end:
    t_cycle = time.time()
    for s_url in services:
        s_name = s_url.split(':')[0]
        t0 = time.time()
        try:
            req = urllib.request.Request('http://' + s_url, headers={'x-bench-traffic': 'benign-client'})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    latencies[s_name].append((time.time() - t0) * 1000.0)
                else:
                    errors[s_name] += 1
        except Exception:
            errors[s_name] += 1
    elapsed = time.time() - t_cycle
    time.sleep(max(0.01, 0.5 - elapsed))

print('BENIGN_METRICS_START')
print(json.dumps({'latencies': latencies, 'errors': errors}))
print('BENIGN_METRICS_END')
" """

    cmd_bg = f"kubectl exec client-benign -c client-benign -- {benign_script}"
    stdin_bg, stdout_bg, stderr_bg = ssh.exec_command(cmd_bg)
    time.sleep(2.0)  # Establish benign background traffic baseline

    # 4. Transmit Attack Burst from client-attacker
    rid = f"{uuid.uuid4()}#replay=cic17#svc=details#auth={bench_auth_token}#feat={feat_str}"
    attack_script = f"""python3 -c "
import urllib.request, time
rid = '{rid}'
for _ in range(6):
    req = urllib.request.Request('http://details:9080/details/0', headers={{'x-request-id': rid}})
    try:
        with urllib.request.urlopen(req, timeout=3) as resp:
            pass
    except Exception:
        pass
    time.sleep(0.3)
" """
    t_attack_start = time.time()
    exec_cmd(f"kubectl exec client-attacker -c client-attacker -- {attack_script}")
    t_attack_end = time.time()
    print(f"  [+] Attack burst transmitted in {t_attack_end - t_attack_start:.2f}s (RID: {rid[:30]}...)")
    sys.stdout.flush()

    # 5. Monitor Detection, Lease Acquisition, OCC Commit, and Autonomic Recovery
    t_occ_mitigation = None
    t_recovery_complete = None
    mitigated_rv = None
    mitigation_token = None
    recovery_token = None
    mitigated_vs_snapshot = None
    restored_vs_snapshot = None
    other_leases_clean = True

    t_poll_start = time.time()
    while time.time() - t_poll_start < 55.0:
        vs_raw, _ = exec_cmd("kubectl get vs details -o json")
        try:
            vs_cur = json.loads(vs_raw)
            rv_cur = vs_cur["metadata"]["resourceVersion"]
            http_rules = vs_cur.get("spec", {}).get("http", [])
            token_cur = vs_cur.get("metadata", {}).get("annotations", {}).get("ddos.defender/fencing-token")
            
            # Check if mitigated (quarantine rule installed, 2 rules)
            if len(http_rules) >= 2 and t_occ_mitigation is None:
                t_occ_mitigation = time.time()
                mitigated_rv = rv_cur
                mitigation_token = token_cur
                mitigated_vs_snapshot = vs_cur
                # Verify other 3 leases are free
                leases_ok, holders = check_other_leases()
                if not leases_ok:
                    other_leases_clean = False
                print(f"      [EVENT] Mitigation OCC committed at +{t_occ_mitigation - t_attack_start:.2f}s (Token: {token_cur}, RV: {rv_cur})")
                sys.stdout.flush()

            # Check if recovered (quarantine rule removed, 1 rule)
            elif len(http_rules) == 1 and t_occ_mitigation is not None and t_recovery_complete is None:
                t_recovery_complete = time.time()
                recovery_token = token_cur
                restored_vs_snapshot = vs_cur
                print(f"      [EVENT] Recovery completed at +{t_recovery_complete - t_attack_start:.2f}s (Duration: {t_recovery_complete - t_occ_mitigation:.2f}s, Token: {token_cur})")
                sys.stdout.flush()
                break
        except Exception:
            pass
        time.sleep(0.3)

    # 6. Harvest Benign Traffic Metrics
    out_benign = stdout_bg.read().decode('utf-8', errors='ignore')
    benign_data = {}
    if "BENIGN_METRICS_START" in out_benign and "BENIGN_METRICS_END" in out_benign:
        try:
            json_str = out_benign.split("BENIGN_METRICS_START")[1].split("BENIGN_METRICS_END")[0].strip()
            benign_data = json.loads(json_str)
        except Exception as e:
            print("  [!] Error parsing benign traffic output:", e)

    # Calculate per-service performance metrics
    svc_metrics = {}
    all_lats = []
    total_reqs = 0
    total_errs = 0
    for s_name in ['productpage', 'details', 'reviews', 'ratings']:
        lats = benign_data.get("latencies", {}).get(s_name, [])
        errs = benign_data.get("errors", {}).get(s_name, 0)
        all_lats.extend(lats)
        req_count = len(lats) + errs
        total_reqs += req_count
        total_errs += errs
        svc_metrics[s_name] = {
            "requests": req_count,
            "success": len(lats),
            "errors": errs,
            "mean_latency_ms": round(float(np.mean(lats)), 2) if lats else None,
            "p95_latency_ms": round(float(np.percentile(lats, 95)), 2) if lats else None,
            "p99_latency_ms": round(float(np.percentile(lats, 99)), 2) if lats else None
        }

    throughput_rps = round(total_reqs / 35.0, 2)
    overall_mean_lat = round(float(np.mean(all_lats)), 2) if all_lats else None
    overall_p95_lat = round(float(np.percentile(all_lats, 95)), 2) if all_lats else None
    overall_p99_lat = round(float(np.percentile(all_lats, 99)), 2) if all_lats else None

    # 7. Capture Post-Trial Cgroup Stats
    cgroup_post = parse_cgroup(controller_pod)
    delta_periods = cgroup_post["nr_periods"] - cgroup_pre["nr_periods"]
    delta_throttled = cgroup_post["nr_throttled"] - cgroup_pre["nr_throttled"]
    delta_throttled_time_ms = round((cgroup_post["throttled_usec"] - cgroup_pre["throttled_usec"]) / 1000.0, 2)
    delta_usage_ms = round((cgroup_post["usage_usec"] - cgroup_pre["usage_usec"]) / 1000.0, 2)
    cgroup_throttling_rate = round((delta_throttled / delta_periods * 100.0), 4) if delta_periods > 0 else 0.0

    # 8. Pull Pod Logs for Internal Timings
    raw_logs, _ = exec_cmd(f"kubectl logs {controller_pod} --since=50s")
    timings = extract_controller_timings(raw_logs)

    # 9. Compute Latency Metrics
    attack_to_mitigation_sec = round(t_occ_mitigation - t_attack_start, 3) if t_occ_mitigation else None
    recovery_duration_sec = round(t_recovery_complete - t_occ_mitigation, 3) if (t_occ_mitigation and t_recovery_complete) else None
    
    # Internal component breakdown
    internal_detect_sec = None
    internal_lease_ms = None
    internal_occ_ms = None
    if timings["t_detect"]:
        internal_detect_sec = round(timings["t_detect"] - t_attack_start, 3)
        if timings["t_lock"]:
            internal_lease_ms = round((timings["t_lock"] - timings["t_detect"]) * 1000.0, 2)
            if timings["t_occ"]:
                internal_occ_ms = round((timings["t_occ"] - timings["t_lock"]) * 1000.0, 2)

    trial_record = {
        "architecture": architecture,
        "trial_id": trial_num,
        "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "controller_pod": controller_pod,
        "baseline_resource_version": base_rv,
        "mitigated_resource_version": mitigated_rv,
        "mitigation_fencing_token": int(mitigation_token) if mitigation_token else None,
        "recovery_fencing_token": int(recovery_token) if recovery_token else None,
        "latencies": {
            "attack_to_mitigation_sec": attack_to_mitigation_sec,
            "autonomic_recovery_duration_sec": recovery_duration_sec,
            "internal_detection_latency_sec": internal_detect_sec,
            "internal_lease_acquisition_ms": internal_lease_ms,
            "internal_occ_commit_ms": internal_occ_ms
        },
        "zero_cross_service_lease_contention": other_leases_clean,
        "traffic_metrics": {
            "total_requests": total_reqs,
            "total_errors": total_errs,
            "throughput_rps": throughput_rps,
            "overall_mean_latency_ms": overall_mean_lat,
            "overall_p95_latency_ms": overall_p95_lat,
            "overall_p99_latency_ms": overall_p99_lat,
            "per_service": svc_metrics
        },
        "cgroup_cpu_telemetry": {
            "delta_cpu_usage_ms": delta_usage_ms,
            "delta_cfs_periods": delta_periods,
            "delta_throttled_periods": delta_throttled,
            "delta_throttled_time_ms": delta_throttled_time_ms,
            "cgroup_throttling_rate_pct": cgroup_throttling_rate
        },
        "verdict": "PASS" if (t_occ_mitigation and t_recovery_complete and other_leases_clean) else "FAIL"
    }

    # Save per-trial JSON
    trial_file = os.path.join(results_dir, f"trial_{architecture}_{trial_num:02d}.json")
    with open(trial_file, "w", encoding="utf-8") as f:
        json.dump(trial_record, f, indent=2)

    # Save trial logs
    log_file = os.path.join(results_dir, f"trial_{architecture}_{trial_num:02d}.log")
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(raw_logs)

    # Save VirtualService snapshots
    if mitigated_vs_snapshot:
        with open(os.path.join(results_dir, f"vs_mitigated_{architecture}_{trial_num:02d}.json"), "w", encoding="utf-8") as f:
            json.dump(mitigated_vs_snapshot, f, indent=2)
    if restored_vs_snapshot:
        with open(os.path.join(results_dir, f"vs_restored_{architecture}_{trial_num:02d}.json"), "w", encoding="utf-8") as f:
            json.dump(restored_vs_snapshot, f, indent=2)

    print(f"  [+] Saved {trial_file} (Verdict: {trial_record['verdict']})")
    print(f"      Mitigation: {attack_to_mitigation_sec}s | Recovery: {recovery_duration_sec}s | Throughput: {throughput_rps} RPS | p95: {overall_p95_lat}ms")
    sys.stdout.flush()

    time.sleep(3.0)  # Settle between trials
    return trial_record

# ==============================================================================
# EXECUTE 10 TRIALS FOR DECENTRALIZED ARCHITECTURE
# ==============================================================================
print("\n" + "#" * 80)
print("PHASE 1: DECENTRALIZED CONTROLLER BENCHMARK (10 TRIALS)")
print("#" * 80)
sys.stdout.flush()

exec_cmd("kubectl scale deployment ddos-defender-product ddos-defender-details ddos-defender-reviews ddos-defender-ratings --replicas=1")
for _ in range(30):
    ready, _ = exec_cmd("kubectl get pods -l app=ddos-defender-details -o jsonpath='{.items[0].status.containerStatuses[0].ready}'")
    if ready == "true":
        break
    time.sleep(2)

pod_decent_details, _ = exec_cmd("kubectl get pods -l app=ddos-defender-details -o jsonpath='{.items[0].metadata.name}'")
print(f"[+] Decentralized pod {pod_decent_details} is READY")
sys.stdout.flush()
time.sleep(5)

decent_trials = []
for t in range(1, 11):
    rec = run_single_trial("decentralized", t, pod_decent_details)
    decent_trials.append(rec)

# ==============================================================================
# PHASE 2: TRANSITION & EXECUTE 10 TRIALS FOR CENTRALIZED ARCHITECTURE
# ==============================================================================
print("\n" + "#" * 80)
print("PHASE 2: CENTRALIZED CONTROLLER BENCHMARK (10 TRIALS)")
print("#" * 80)
sys.stdout.flush()

print("[*] Scaling decentralized controllers to 0...")
exec_cmd("kubectl scale deployment ddos-defender-product ddos-defender-details ddos-defender-reviews ddos-defender-ratings --replicas=0")
for _ in range(30):
    pods, _ = exec_cmd("kubectl get pods -l architecture=decentralized -o jsonpath='{.items[*].metadata.name}'")
    if not pods.strip():
        break
    time.sleep(1)

print("[*] Deploying centralized coordinator (deployment_central_active.yaml)...")
sftp = ssh.open_sftp()
sftp.put("manifests/deployment_central_active.yaml", "/home/osu/ddos_detector/manifests/deployment_central_active.yaml")
sftp.close()

exec_cmd("kubectl apply -f /home/osu/ddos_detector/manifests/deployment_central_active.yaml")

# Wait for central pod ready
for _ in range(30):
    ready, _ = exec_cmd("kubectl get pods -l app=ddos-defender-central -o jsonpath='{.items[0].status.containerStatuses[0].ready}'")
    if ready == "true":
        break
    time.sleep(2)

pod_central, _ = exec_cmd("kubectl get pods -l app=ddos-defender-central -o jsonpath='{.items[0].metadata.name}'")
print(f"[+] Centralized pod {pod_central} is READY")
print("[*] Allowing 12s settling delay for Prometheus scrape cache warmup...")
sys.stdout.flush()
time.sleep(12)

central_trials = []
for t in range(1, 11):
    rec = run_single_trial("centralized", t, pod_central)
    central_trials.append(rec)

# ==============================================================================
# RESTORE CLUSTER BASELINE
# ==============================================================================
print("\n[*] Tearing down centralized controller and restoring decentralized controllers...")
exec_cmd("kubectl delete -f /home/osu/ddos_detector/manifests/deployment_central_active.yaml")
exec_cmd("kubectl scale deployment ddos-defender-product ddos-defender-details ddos-defender-reviews ddos-defender-ratings --replicas=1")
wait_for_clean_baseline(timeout=60)
print("[+] Cluster baseline fully restored to decentralized mode.")

ssh.close()

# ==============================================================================
# COMPUTE AGGREGATE SUMMARY STATISTICS
# ==============================================================================
def compute_stats(arr):
    arr_clean = [x for x in arr if x is not None]
    if not arr_clean:
        return {"mean": None, "std": None, "median": None, "min": None, "max": None, "p95": None}
    return {
        "mean": round(float(np.mean(arr_clean)), 3),
        "std": round(float(np.std(arr_clean)), 3),
        "median": round(float(np.median(arr_clean)), 3),
        "min": round(float(np.min(arr_clean)), 3),
        "max": round(float(np.max(arr_clean)), 3),
        "p95": round(float(np.percentile(arr_clean, 95)), 3)
    }

def summarize_trials(trials):
    return {
        "attack_to_mitigation_sec": compute_stats([t["latencies"]["attack_to_mitigation_sec"] for t in trials]),
        "autonomic_recovery_sec": compute_stats([t["latencies"]["autonomic_recovery_duration_sec"] for t in trials]),
        "internal_detection_latency_sec": compute_stats([t["latencies"]["internal_detection_latency_sec"] for t in trials]),
        "internal_lease_acquisition_ms": compute_stats([t["latencies"]["internal_lease_acquisition_ms"] for t in trials]),
        "internal_occ_commit_ms": compute_stats([t["latencies"]["internal_occ_commit_ms"] for t in trials]),
        "throughput_rps": compute_stats([t["traffic_metrics"]["throughput_rps"] for t in trials]),
        "overall_mean_latency_ms": compute_stats([t["traffic_metrics"]["overall_mean_latency_ms"] for t in trials]),
        "overall_p95_latency_ms": compute_stats([t["traffic_metrics"]["overall_p95_latency_ms"] for t in trials]),
        "overall_p99_latency_ms": compute_stats([t["traffic_metrics"]["overall_p99_latency_ms"] for t in trials]),
        "cgroup_throttling_rate_pct": compute_stats([t["cgroup_cpu_telemetry"]["cgroup_throttling_rate_pct"] for t in trials]),
        "cgroup_throttled_time_ms": compute_stats([t["cgroup_cpu_telemetry"]["delta_throttled_time_ms"] for t in trials]),
        "pass_rate": sum(1 for t in trials if t["verdict"] == "PASS") / len(trials),
        "cross_service_lease_contention_count": sum(0 if t["zero_cross_service_lease_contention"] else 1 for t in trials)
    }

summary = {
    "benchmark_name": "Scenario 1: Centralized vs. Decentralized Performance Evaluation",
    "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "trials_per_architecture": 10,
    "total_trials": 20,
    "decentralized_summary": summarize_trials(decent_trials),
    "centralized_summary": summarize_trials(central_trials),
    "all_trials_decentralized": decent_trials,
    "all_trials_centralized": central_trials
}

summary_file = os.path.join(results_dir, "scenario1_final_benchmark_summary.json")
with open(summary_file, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

with open(os.path.join("PAPER", "Backup", "scenario1_final_benchmark_summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print(f"\n[+] Successfully saved benchmark summary to {summary_file}")
print("SCENARIO 1 BENCHMARK COMPLETE!")
