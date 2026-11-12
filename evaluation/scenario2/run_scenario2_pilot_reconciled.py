import paramiko
import json
import time
import uuid
import os
import sys
import base64
import re
import numpy as np
from datetime import datetime, timezone

sys.stdout.reconfigure(encoding='utf-8')

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('192.168.160.129', username='osu', password='osu', timeout=10)

def exec_cmd(cmd):
    stdin, stdout, stderr = ssh.exec_command(cmd)
    return stdout.read().decode('utf-8', errors='ignore').strip(), stderr.read().decode('utf-8', errors='ignore').strip()

results_dir = os.path.join("PAPER", "Backup", "SCENARIO_2_PILOT_RESULTS")
os.makedirs(results_dir, exist_ok=True)

print("=" * 80)
print("SCENARIO 2 PILOT: SIMULTANEOUS FOUR-SERVICE ATTACK UNDER ACTIVE ENFORCEMENT")
print("=" * 80)

# 1. Active Benchmark Auth Token from Kubernetes Secret
raw_b64, _ = exec_cmd("kubectl get secret ddos-bench-auth -n default -o jsonpath='{.data.token}'")
bench_auth_token = base64.b64decode(raw_b64).decode().strip()
print(f"[+] Active auth token loaded (length={len(bench_auth_token)})")

vs_map = {
    "productpage": "bookinfo",
    "details": "details",
    "reviews": "reviews",
    "ratings": "ratings"
}

lease_map = {
    "productpage": "product-mitigation-lock",
    "details": "details-mitigation-lock",
    "reviews": "reviews-mitigation-lock",
    "ratings": "ratings-mitigation-lock"
}

services = ["productpage", "details", "reviews", "ratings"]

def get_pod_names():
    pods = {}
    for s in ["product", "details", "reviews", "ratings"]:
        raw, _ = exec_cmd(f"kubectl get pods -n default -l app=ddos-defender-{s} -o jsonpath='{{.items[0].metadata.name}}'")
        pods[s] = raw.strip("'")
    return pods

defender_pods = get_pod_names()
print(f"[+] Active defender pods: {defender_pods}")

# 2. Four Held-Out Attack Vectors (from Wednesday CIC-IDS2017 catalog)
attack_config = {
    "productpage": {
        "catalog_id": "productpage_wed_9852",
        "attack_type": "DoS Slowloris",
        "source_dataset": "CIC-IDS2017 Wednesday.csv (row 9852)",
        "features_order": ['Flow Packets/s', 'Total Fwd Packet', 'Total Length of Fwd Packet', 'Fwd Packet Length Mean', 'ACK Flag Count', 'PSH Flag Count', 'Packet Length Variance'],
        "features_values": [0.1344203510260727, 4.0, 239.0, 59.75, 6.0, 2.0, 7544.142857142858],
        "feat_str": "0.1344203510260727,4.0,239.0,59.75,6.0,2.0,7544.142857142858",
        "url": "http://productpage:9080/productpage",
        "target_rps": 65.0,
        "threads": 4,
        "rid": f"{uuid.uuid4()}#replay=cic17#svc=productpage#auth={bench_auth_token}#feat=0.1344203510260727,4.0,239.0,59.75,6.0,2.0,7544.142857142858"
    },
    "details": {
        "catalog_id": "details_wed_9852",
        "attack_type": "DoS Slowloris",
        "source_dataset": "CIC-IDS2017 Wednesday.csv (row 9852)",
        "features_order": ['Total Fwd Packet', 'Total Bwd packets', 'Total Length of Fwd Packet', 'Total Length of Bwd Packet', 'Fwd Packet Length Mean', 'Bwd Packet Length Mean', 'Down/Up Ratio'],
        "features_values": [4.0, 3.0, 239.0, 0.0, 59.75, 0.0, 0.75],
        "feat_str": "4.0,3.0,239.0,0.0,59.75,0.0,0.75",
        "url": "http://details:9080/details/0",
        "target_rps": 20.0,
        "threads": 1,
        "rid": f"{uuid.uuid4()}#replay=cic17#svc=details#auth={bench_auth_token}#feat=4.0,3.0,239.0,0.0,59.75,0.0,0.75"
    },
    "reviews": {
        "catalog_id": "reviews_wed_9852",
        "attack_type": "DoS Slowloris",
        "source_dataset": "CIC-IDS2017 Wednesday.csv (row 9852)",
        "features_order": ['Total Length of Bwd Packet', 'Bwd Packet Length Mean', 'Packet Length Variance', 'Packet Length Std', 'Total Bwd packets', 'Down/Up Ratio', 'Flow IAT Mean'],
        "features_values": [0.0, 0.0, 7544.142857142858, 86.8570253758604, 3.0, 0.75, 8679241.333333334],
        "feat_str": "0.0,0.0,7544.142857142858,86.8570253758604,3.0,0.75,8679241.333333334",
        "url": "http://reviews:9080/reviews/0",
        "target_rps": 20.0,
        "threads": 1,
        "rid": f"{uuid.uuid4()}#replay=cic17#svc=reviews#auth={bench_auth_token}#feat=0.0,0.0,7544.142857142858,86.8570253758604,3.0,0.75,8679241.333333334"
    },
    "ratings": {
        "catalog_id": "ratings_wed_9852",
        "attack_type": "DoS Slowloris",
        "source_dataset": "CIC-IDS2017 Wednesday.csv (row 9852)",
        "features_order": ['Total Fwd Packet', 'Total Bwd packets', 'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'PSH Flag Count', 'ACK Flag Count'],
        "features_values": [4.0, 3.0, 34.142857142857146, 86.8570253758604, 7544.142857142858, 2.0, 6.0],
        "feat_str": "4.0,3.0,34.142857142857146,86.8570253758604,7544.142857142858,2.0,6.0",
        "url": "http://ratings:9080/ratings/0",
        "target_rps": 20.0,
        "threads": 1,
        "rid": f"{uuid.uuid4()}#replay=cic17#svc=ratings#auth={bench_auth_token}#feat=4.0,3.0,34.142857142857146,86.8570253758604,7544.142857142858,2.0,6.0"
    }
}

def check_baseline():
    vs_states = {}
    leases_clean = True
    for s, vs_name in vs_map.items():
        vs_raw, _ = exec_cmd(f"kubectl get vs {vs_name} -o json")
        try:
            vs = json.loads(vs_raw)
            routes = vs.get("spec", {}).get("http", [])
            has_quarantine = any(r.get("name") == "quarantine-malicious" for r in routes)
            is_failover = any(
                any(dest.get("destination", {}).get("subset") in ("v2", "v3") for dest in r.get("route", []))
                for r in routes if r.get("name") != "quarantine-malicious"
            )
            vs_states[s] = {
                "vs_name": vs_name,
                "rv": vs["metadata"]["resourceVersion"],
                "routes_count": len(routes),
                "quarantine": has_quarantine,
                "failover": is_failover
            }
        except Exception as e:
            vs_states[s] = {"error": str(e)}

    lease_states = {}
    for s, ln in lease_map.items():
        l_raw, _ = exec_cmd(f"kubectl get lease {ln} -o json")
        try:
            lj = json.loads(l_raw)
            holder = str(lj.get("spec", {}).get("holderIdentity") or "").strip()
            lease_states[ln] = holder
            if holder:
                leases_clean = False
        except Exception:
            lease_states[ln] = "UNKNOWN"
            leases_clean = False

    all_clean = (
        all(not v.get("quarantine") and not v.get("failover") and v.get("routes_count") == 1 for v in vs_states.values())
        and leases_clean
    )
    return vs_states, lease_states, all_clean

print("[+] Verifying clean baseline across all 4 services...")
vs_base, lease_base, clean_ok = check_baseline()
print(f"  VS Baseline: {vs_base}")
print(f"  Lease Baseline: {lease_base}")
assert clean_ok, "Cluster must be in clean baseline before starting pilot test"

# Capture Pre-Trial VirtualService snapshots
baseline_snapshots = {}
for s, vs_name in vs_map.items():
    raw, _ = exec_cmd(f"kubectl get vs {vs_name} -o json")
    baseline_snapshots[s] = json.loads(raw)
    with open(os.path.join(results_dir, f"vs_{s}_baseline.json"), "w", encoding="utf-8") as f:
        json.dump(baseline_snapshots[s], f, indent=2)

# 3. Start Benign Traffic Generator (Background, 95s)
print("\n[+] Launching continuous benign background traffic generator from client-benign (95s)...")
benign_script = """python3 -c "
import urllib.request, time, json
services = ['productpage:9080/productpage', 'details:9080/details/0', 'reviews:9080/reviews/0', 'ratings:9080/ratings/0']
latencies = {s.split(':')[0]: [] for s in services}
errors = {s.split(':')[0]: 0 for s in services}
t_end = time.time() + 95.0
while time.time() < t_end:
    t_start = time.time()
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
    elapsed = time.time() - t_start
    time.sleep(max(0.01, 0.5 - elapsed))

print('BENIGN_METRICS_START')
print(json.dumps({'latencies': latencies, 'errors': errors}))
print('BENIGN_METRICS_END')
" """

stdin_bg, stdout_bg, stderr_bg = ssh.exec_command(f"kubectl exec client-benign -c client-benign -- {benign_script}")
time.sleep(3.0)  # Establish benign baseline

# 4. Launch Synchronized 30-Second Parallel Attack Workload
print("\n[+] Launching synchronized 30-second parallel attack from client-attacker...")

b64_cfg = base64.b64encode(json.dumps(attack_config).encode()).decode()

attack_runner_code = f"""python3 -c "
import urllib.request, time, threading, json, base64

raw_json = base64.b64decode('{b64_cfg}').decode()
config = json.loads(raw_json)
results = {{}}
t_duration = 30.0

def run_pp(cfg):
    global pp_count, pp_errs
    url = cfg['url']
    rid = cfg['rid']
    t_end = t0 + t_duration
    while time.time() < t_end:
        try:
            req = urllib.request.Request(url, headers={{'x-request-id': rid, 'x-bench-attack': 'productpage'}})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status in (200, 302, 404): pp_count += 1
                else: pp_errs += 1
        except Exception:
            pp_errs += 1
        time.sleep(0.008)

def run_svc(s_name, cfg):
    url = cfg['url']
    target_rps = cfg['target_rps']
    rid = cfg['rid']
    interval = 1.0 / target_rps
    t_end = t0 + t_duration
    count = 0
    errs = 0
    while time.time() < t_end:
        t_req = time.time()
        try:
            req = urllib.request.Request(url, headers={{'x-request-id': rid, 'x-bench-attack': s_name}})
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status in (200, 302, 404): count += 1
                else: errs += 1
        except Exception:
            errs += 1
        elapsed = time.time() - t_req
        time.sleep(max(0.001, interval - elapsed))
    results[s_name] = {{'count': count, 'errs': errs, 'achieved_rps': round(count / (time.time() - t0), 2)}}

t0 = time.time()
pp_count = 0
pp_errs = 0
threads = []

# 4 threads for productpage
for _ in range(config['productpage']['threads']):
    t = threading.Thread(target=run_pp, args=(config['productpage'],))
    threads.append(t)
    t.start()

# 1 thread each for details, reviews, ratings
for s in ['details', 'reviews', 'ratings']:
    t = threading.Thread(target=run_svc, args=(s, config[s]))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

total_t = time.time() - t0
results['productpage'] = {{'count': pp_count, 'errs': pp_errs, 'achieved_rps': round(pp_count / total_t, 2)}}
results['total_duration'] = round(total_t, 2)
print('ATTACK_METRICS_START')
print(json.dumps(results))
print('ATTACK_METRICS_END')
" """

t_attack_start = time.time()
t_attack_start_iso = datetime.now(timezone.utc).isoformat()
print(f"  [*] Attack launch UTC timestamp: {t_attack_start_iso}")

stdin_att, stdout_att, stderr_att = ssh.exec_command(f"kubectl exec client-attacker -c client-attacker -- {attack_runner_code}")

# 5. Live Telemetry Monitoring across all 4 services
mitigation_events = {}
recovery_events = {}
mitigated_snapshots = {}
restored_snapshots = {}

t_monitor_start = time.time()
print("\n[+] Monitoring detection, OCC patches, and recovery across all 4 services...")

while time.time() - t_monitor_start < 85.0:
    for s, vs_name in vs_map.items():
        if s not in mitigation_events:
            vs_raw, _ = exec_cmd(f"kubectl get vs {vs_name} -o json")
            try:
                vs = json.loads(vs_raw)
                routes = vs.get("spec", {}).get("http", [])
                has_quarantine = any(r.get("name") == "quarantine-malicious" for r in routes)
                is_failover = any(
                    any(dest.get("destination", {}).get("subset") in ("v2", "v3") for dest in r.get("route", []))
                    for r in routes if r.get("name") != "quarantine-malicious"
                )
                
                # Check if mitigated (quarantine or failover active)
                if has_quarantine or is_failover or len(routes) >= 2:
                    t_mit = time.time()
                    rv = vs["metadata"]["resourceVersion"]
                    token = vs.get("metadata", {}).get("annotations", {}).get("ddos.defender/fencing-token")
                    mitigation_events[s] = {
                        "service": s,
                        "vs_name": vs_name,
                        "timestamp_epoch": t_mit,
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "relative_to_attack_sec": round(t_mit - t_attack_start, 3),
                        "resource_version": rv,
                        "fencing_token": token,
                        "has_quarantine": has_quarantine,
                        "is_failover": is_failover,
                        "policy_observed": "BOTH" if (has_quarantine and is_failover) else ("ML_ONLY" if has_quarantine else "RPS_ONLY"),
                        "routes_count": len(routes),
                        "routes_summary": [
                            f"{r.get('name')}: " + ", ".join(f"{d.get('destination', {}).get('host')}:{d.get('destination', {}).get('subset')} ({d.get('weight')}%)" for d in r.get("route", []))
                            for r in routes
                        ]
                    }
                    mitigated_snapshots[s] = vs
                    with open(os.path.join(results_dir, f"vs_{s}_mitigated.json"), "w", encoding="utf-8") as f:
                        json.dump(vs, f, indent=2)
                    print(f"      [EVENT] {s.upper()} ({vs_name}) MITIGATED at +{t_mit - t_attack_start:.2f}s | Policy: {mitigation_events[s]['policy_observed']} | Token: {token} | RV: {rv}")
                    sys.stdout.flush()
            except Exception:
                pass

        elif s in mitigation_events and s not in recovery_events:
            # Check if recovered (only 1 rule, no quarantine, 100% v1)
            vs_raw, _ = exec_cmd(f"kubectl get vs {vs_name} -o json")
            try:
                vs = json.loads(vs_raw)
                routes = vs.get("spec", {}).get("http", [])
                has_quarantine = any(r.get("name") == "quarantine-malicious" for r in routes)
                is_prod_v1 = (
                    len(routes) == 1 and
                    not has_quarantine and
                    all(dest.get("destination", {}).get("subset") == "v1" for dest in routes[0].get("route", []))
                )
                if is_prod_v1:
                    t_rec = time.time()
                    rv = vs["metadata"]["resourceVersion"]
                    token = vs.get("metadata", {}).get("annotations", {}).get("ddos.defender/fencing-token")
                    recovery_events[s] = {
                        "service": s,
                        "vs_name": vs_name,
                        "timestamp_epoch": t_rec,
                        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                        "relative_to_attack_sec": round(t_rec - t_attack_start, 3),
                        "duration_from_mitigation_sec": round(t_rec - mitigation_events[s]["timestamp_epoch"], 3),
                        "resource_version": rv,
                        "fencing_token": token,
                        "restored_state": "100% v1 normal-production"
                    }
                    restored_snapshots[s] = vs
                    with open(os.path.join(results_dir, f"vs_{s}_restored.json"), "w", encoding="utf-8") as f:
                        json.dump(vs, f, indent=2)
                    print(f"      [EVENT] {s.upper()} ({vs_name}) RECOVERED at +{t_rec - t_attack_start:.2f}s | Duration: {t_rec - mitigation_events[s]['timestamp_epoch']:.2f}s | Token: {token}")
                    sys.stdout.flush()
            except Exception:
                pass

    if len(recovery_events) == 4:
        print("[+] All 4 services have fully mitigated and recovered!")
        break

    time.sleep(0.3)

# 6. Harvest Attacker Output
out_att = stdout_att.read().decode('utf-8', errors='ignore')
attack_metrics = {}
if "ATTACK_METRICS_START" in out_att and "ATTACK_METRICS_END" in out_att:
    try:
        att_str = out_att.split("ATTACK_METRICS_START")[1].split("ATTACK_METRICS_END")[0].strip()
        attack_metrics = json.loads(att_str)
        print("\n[+] Attacker Traffic Metrics:")
        print(json.dumps(attack_metrics, indent=2))
    except Exception as e:
        print("[!] Error parsing attacker output:", e)

# 7. Harvest Benign Traffic Output
out_ben = stdout_bg.read().decode('utf-8', errors='ignore')
benign_metrics = {}
if "BENIGN_METRICS_START" in out_ben and "BENIGN_METRICS_END" in out_ben:
    try:
        ben_str = out_ben.split("BENIGN_METRICS_START")[1].split("BENIGN_METRICS_END")[0].strip()
        benign_raw = json.loads(ben_str)
        
        # Calculate per-service stats
        for s in services:
            lats = benign_raw.get("latencies", {}).get(s, [])
            errs = benign_raw.get("errors", {}).get(s, 0)
            reqs = len(lats) + errs
            benign_metrics[s] = {
                "requests": reqs,
                "success": len(lats),
                "errors": errs,
                "success_rate_pct": round(len(lats) / max(1, reqs) * 100.0, 2),
                "mean_latency_ms": round(float(np.mean(lats)), 2) if lats else 0.0,
                "median_latency_ms": round(float(np.median(lats)), 2) if lats else 0.0,
                "p95_latency_ms": round(float(np.percentile(lats, 95)), 2) if lats else 0.0,
                "p99_latency_ms": round(float(np.percentile(lats, 99)), 2) if lats else 0.0
            }
        # Aggregate mesh stats
        all_lats = [l for s in services for l in benign_raw.get("latencies", {}).get(s, [])]
        total_errs = sum(benign_raw.get("errors", {}).get(s, 0) for s in services)
        total_reqs = len(all_lats) + total_errs
        benign_metrics["aggregate_mesh"] = {
            "requests": total_reqs,
            "success": len(all_lats),
            "errors": total_errs,
            "success_rate_pct": round(len(all_lats) / max(1, total_reqs) * 100.0, 2),
            "mean_latency_ms": round(float(np.mean(all_lats)), 2) if all_lats else 0.0,
            "p95_latency_ms": round(float(np.percentile(all_lats, 95)), 2) if all_lats else 0.0,
            "p99_latency_ms": round(float(np.percentile(all_lats, 99)), 2) if all_lats else 0.0
        }
        print("\n[+] Benign Traffic Metrics:")
        print(json.dumps(benign_metrics, indent=2))
    except Exception as e:
        print("[!] Error parsing benign output:", e)

# 8. Harvest Defender Logs and Forensic Event Timestamps
print("\n[+] Harvesting controller logs and extracting forensic timestamps...")
controller_forensics = {}

for s_key in ["product", "details", "reviews", "ratings"]:
    canon_s = "productpage" if s_key == "product" else s_key
    pod_name = defender_pods[s_key]
    log_raw, _ = exec_cmd(f"kubectl logs {pod_name} --since=150s")
    
    # Save log with redacted auth token
    redacted_log = log_raw.replace(bench_auth_token, "<REDACTED_AUTH_TOKEN>")
    with open(os.path.join(results_dir, f"defender_{s_key}_pilot.log"), "w", encoding="utf-8") as f:
        f.write(redacted_log)
        
    ml_inf_events = []
    rps_cross_events = []
    detect_hybrid_events = []
    lock_events = []
    occ_events = []
    revert_events = []
    
    for line in log_raw.splitlines():
        if "[L7-INFERENCE]" in line and canon_s in line:
            ml_inf_events.append(line)
        if "[SCRAPE]" in line and "crossed threshold" in line and canon_s in line:
            rps_cross_events.append(line)
        if "[DETECT-HYBRID]" in line and canon_s in line:
            detect_hybrid_events.append(line)
        if "[LOCK]" in line and ("acquired lock" in line or "Successfully acquired" in line) and (canon_s in line or s_key in line):
            lock_events.append(line)
        if "[OCC-ATOMIC]" in line and "atomically updated OK" in line:
            occ_events.append(line)
        if "[REVERT]" in line and (canon_s in line or s_key in line):
            revert_events.append(line)

    controller_forensics[canon_s] = {
        "pod_name": pod_name,
        "ml_inference_events": ml_inf_events[-4:],
        "rps_cross_events": rps_cross_events[-4:],
        "detect_hybrid_events": detect_hybrid_events[-4:],
        "lock_events": lock_events[-4:],
        "occ_events": occ_events[-4:],
        "revert_events": revert_events[-6:]
    }

print("[+] Controller forensics parsed.")

# 9. Final Baseline and Lease Check
vs_final, final_leases, all_unheld = check_baseline()

# 10. Consolidate Pilot Trial Record
pilot_summary = {
    "scenario": "Scenario 2: Parallel Four-Service DDoS Evaluation",
    "evaluation_phase": "Controlled Pilot Trial",
    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    "attack_start_utc": t_attack_start_iso,
    "architecture": "decentralized",
    "cluster_environment": {
        "kubernetes_version": "v1.28+",
        "service_mesh": "Istio",
        "nodes": 1,
        "active_defenders": defender_pods
    },
    "attack_catalog": attack_config,
    "mitigation_events": mitigation_events,
    "recovery_events": recovery_events,
    "attacker_traffic": attack_metrics,
    "benign_traffic": benign_metrics,
    "final_virtualservices_status": vs_final,
    "final_leases_status": final_leases,
    "all_leases_unheld": all_unheld,
    "controller_forensics": controller_forensics,
    "pilot_verdict": "PASS" if len(mitigation_events) == 4 and len(recovery_events) == 4 and all_unheld else "FAIL"
}

summary_path = os.path.join(results_dir, "scenario2_pilot_trial.json")
with open(summary_path, "w", encoding="utf-8") as f:
    json.dump(pilot_summary, f, indent=2)

print(f"\n[+] Saved pilot trial record to {summary_path}")
print(f"PILOT VERDICT: {pilot_summary['pilot_verdict']}")

ssh.close()
