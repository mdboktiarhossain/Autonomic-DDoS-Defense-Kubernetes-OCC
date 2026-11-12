import json
import os
import glob
import re
import zipfile
import numpy as np
from datetime import datetime

results_dir = os.path.join("PAPER", "Backup", "SCENARIO_1_BENCHMARK_RESULTS")

def parse_log_ts(line):
    m = re.match(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})", line)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S,%f")
            return dt.timestamp()
        except Exception:
            pass
    return None

def process_trial_file(arch, t_id):
    json_path = os.path.join(results_dir, f"trial_{arch}_{t_id:02d}.json")
    log_path = os.path.join(results_dir, f"trial_{arch}_{t_id:02d}.log")
    if not os.path.exists(json_path):
        return None
    with open(json_path, "r", encoding="utf-8") as jf:
        data = json.load(jf)

    m_token = data.get("mitigation_fencing_token")
    r_token = data.get("recovery_fencing_token")
    ext_mit_sec = data.get("latencies", {}).get("attack_to_mitigation_sec")

    lease_ms = None
    occ_ms = None
    internal_detect_sec = None

    if m_token and os.path.exists(log_path):
        with open(log_path, "r", encoding="utf-8", errors="ignore") as lf:
            lines = lf.readlines()

        t_detect = None
        t_lock = None
        t_occ = None

        for i, line in enumerate(lines):
            if f"fencing_token={m_token}" in line and "Successfully acquired lock" in line:
                t_lock = parse_log_ts(line)
                for prev in reversed(lines[:i]):
                    if "[DETECT-HYBRID]" in prev:
                        t_detect = parse_log_ts(prev)
                        break
            elif f"fencing_token={m_token}" in line and "[OCC-ATOMIC]" in line:
                t_occ = parse_log_ts(line)

        if t_lock and t_detect:
            lease_ms = round((t_lock - t_detect) * 1000.0, 2)
        if t_occ and t_lock:
            occ_ms = round((t_occ - t_lock) * 1000.0, 2)
        if ext_mit_sec and lease_ms is not None and occ_ms is not None:
            internal_detect_sec = round(ext_mit_sec - (lease_ms + occ_ms) / 1000.0, 3)

    data.setdefault("latencies", {})
    data["latencies"]["internal_detection_latency_sec"] = internal_detect_sec
    data["latencies"]["internal_lease_acquisition_ms"] = lease_ms
    data["latencies"]["internal_occ_commit_ms"] = occ_ms

    with open(json_path, "w", encoding="utf-8") as jf:
        json.dump(data, jf, indent=2)

    return data

all_decent = []
all_central = []

for t in range(1, 11):
    d = process_trial_file("decentralized", t)
    if d:
        all_decent.append(d)

for t in range(1, 11):
    c = process_trial_file("centralized", t)
    if c:
        all_central.append(c)

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
    "timestamp_iso": datetime.now().astimezone().isoformat(),
    "trials_per_architecture": 10,
    "total_trials": 20,
    "decentralized_summary": summarize_trials(all_decent),
    "centralized_summary": summarize_trials(all_central),
    "all_trials_decentralized": all_decent,
    "all_trials_centralized": all_central
}

summary_file = os.path.join(results_dir, "scenario1_final_benchmark_summary.json")
with open(summary_file, "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

with open(os.path.join("PAPER", "Backup", "scenario1_final_benchmark_summary.json"), "w", encoding="utf-8") as f:
    json.dump(summary, f, indent=2)

print(f"[+] Reconciled summary saved to {summary_file}")

# Repackage raw archive
zip_path = os.path.join("PAPER", "Backup", "SCENARIO_1_BENCHMARK_RESULTS_RAW.zip")
with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
    for root, dirs, files in os.walk(results_dir):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, results_dir)
            zipf.write(full_path, arcname=rel_path)

print(f"[+] Repackaged raw archive: {zip_path}")
