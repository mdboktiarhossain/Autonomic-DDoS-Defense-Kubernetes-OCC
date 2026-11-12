import os
import sys
import json
import time
import math
import hashlib
import paramiko
import joblib
import numpy as np
import pandas as pd
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from sklearn.metrics import confusion_matrix, accuracy_score, precision_score, recall_score, f1_score

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
import functools
print = functools.partial(print, flush=True)

VM_IP = "192.168.160.129"
VM_USER = "osu"
VM_PASS = "osu"

RAW_OUT_DIR = r"PAPER\Backup\SCENARIO_4_BENCHMARK_RESULTS\raw"
os.makedirs(RAW_OUT_DIR, exist_ok=True)

EVAL_JSON = r"PAPER\Backup\models_global\eval_test_500.json"
with open(EVAL_JSON, "r") as f:
    eval_data = json.load(f)

union_records = eval_data["records"]
eval_labels = np.array(eval_data["labels"])

POD_SPECS = {
    "productpage": {
        "pod_name": "ddos-defender-product-5b5d95fc88-qmjp9",
        "bundle_file": "productpage_bundle_7feat.joblib",
        "model_type": "RandomForestClassifier",
        "threshold": 0.70,
        "features": [
            "Flow Packets/s", "Total Fwd Packet", "Total Length of Fwd Packet",
            "Fwd Packet Length Mean", "ACK Flag Count", "PSH Flag Count", "Packet Length Variance"
        ]
    },
    "details": {
        "pod_name": "ddos-defender-details-656c4f644d-nsxmr",
        "bundle_file": "details_bundle_7feat.joblib",
        "model_type": "HistGradientBoostingClassifier",
        "threshold": 0.80,
        "features": [
            "Total Fwd Packet", "Total Bwd packets", "Total Length of Fwd Packet",
            "Total Length of Bwd Packet", "Fwd Packet Length Mean", "Bwd Packet Length Mean", "Down/Up Ratio"
        ]
    },
    "reviews": {
        "pod_name": "ddos-defender-reviews-87c5895c8-whfs4",
        "bundle_file": "reviews_bundle_7feat.joblib",
        "model_type": "HistGradientBoostingClassifier",
        "threshold": 0.70,
        "features": [
            "Total Length of Bwd Packet", "Bwd Packet Length Mean", "Packet Length Variance",
            "Packet Length Std", "Total Bwd packets", "Down/Up Ratio", "Flow IAT Mean"
        ]
    },
    "ratings": {
        "pod_name": "ddos-defender-ratings-5c5d5f94cb-2f6n6",
        "bundle_file": "ratings_bundle_7feat.joblib",
        "model_type": "RandomForestClassifier",
        "threshold": 0.70,
        "features": [
            "Total Fwd Packet", "Total Bwd packets", "Packet Length Mean",
            "Packet Length Std", "Packet Length Variance", "PSH Flag Count", "ACK Flag Count"
        ]
    }
}

GLOBAL_MODELS_DIR = r"PAPER\Backup\models_global"
GLOBAL_SPECS = {
    "global_rf_7feat": {
        "bundle_file": "global_random_forest_7feat.joblib",
        "name": "Global Random Forest (7-Feature Budget)",
        "features": [
            'Packet Length Variance', 'Bwd Packet Length Mean', 'Packet Length Mean',
            'Packet Length Std', 'Total Bwd packets', 'Flow Packets/s', 'Total Length of Bwd Packet'
        ],
        "threshold": 0.70
    },
    "global_hgb_7feat": {
        "bundle_file": "global_hist_gradient_boosting_7feat.joblib",
        "name": "Global HistGradientBoosting (7-Feature Budget)",
        "features": [
            'Packet Length Variance', 'Bwd Packet Length Mean', 'Packet Length Mean',
            'Packet Length Std', 'Total Bwd packets', 'Flow Packets/s', 'Total Length of Bwd Packet'
        ],
        "threshold": 0.70
    },
    "global_rf_14feat": {
        "bundle_file": "global_random_forest_14feat.joblib",
        "name": "Global Random Forest (14-Feature Extended)",
        "features": eval_data["feature_names"],
        "threshold": 0.70
    },
    "global_hgb_14feat": {
        "bundle_file": "global_hist_gradient_boosting_14feat.joblib",
        "name": "Global HistGradientBoosting (14-Feature Extended)",
        "features": eval_data["feature_names"],
        "threshold": 0.70
    }
}

VECTORS_BY_GLOBAL = {}
for gkey, spec in GLOBAL_SPECS.items():
    feats = spec["features"]
    mat = [[rec[col] for col in feats] for rec in union_records]
    VECTORS_BY_GLOBAL[gkey] = mat

def calc_percentiles(lats):
    return {
        "mean_ms": float(np.mean(lats)),
        "p50_ms": float(np.percentile(lats, 50, method='inverted_cdf')),
        "p95_ms": float(np.percentile(lats, 95, method='inverted_cdf')),
        "p99_ms": float(np.percentile(lats, 99, method='inverted_cdf')),
        "min_ms": float(np.min(lats)),
        "max_ms": float(np.max(lats)),
        "std_ms": float(np.std(lats, ddof=1)) if len(lats) > 1 else 0.0
    }

def get_ssh_client():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(VM_IP, username=VM_USER, password=VM_PASS, timeout=15)
    return ssh

def execute_in_pod(svc):
    pod_name = POD_SPECS[svc]["pod_name"]
    cmd = f"kubectl exec {pod_name} -- python3 /tmp/pod_inference_runner.py {svc}"
    ssh = get_ssh_client()
    stdin, stdout, stderr = ssh.exec_command(cmd)
    out_text = stdout.read().decode('utf-8')
    err_text = stderr.read().decode('utf-8')
    ssh.close()
    if not out_text.strip():
        raise RuntimeError(f"Error executing in pod {pod_name}: {err_text}")
    return json.loads(out_text.strip())

def execute_global_model(gkey):
    spec = GLOBAL_SPECS[gkey]
    vectors = VECTORS_BY_GLOBAL[gkey]
    bundle_path = os.path.join(GLOBAL_MODELS_DIR, spec["bundle_file"])
    bundle = joblib.load(bundle_path)
    model = bundle["model"]
    scaler = bundle["scaler"]
    threshold = spec["threshold"]
    
    # Warmup
    for i in range(50):
        v = np.array([vectors[i % len(vectors)]])
        _ = model.predict_proba(scaler.transform(v))
        
    lats_ms = []
    preds = []
    t_start = time.perf_counter()
    for row in vectors:
        v = np.array([row])
        t_a = time.perf_counter_ns()
        p = model.predict_proba(scaler.transform(v))[0, 1]
        t_b = time.perf_counter_ns()
        lats_ms.append((t_b - t_a) / 1_000_000.0)
        preds.append(1 if p >= threshold else 0)
    t_end = time.perf_counter()
    duration = t_end - t_start
    
    return {
        "duration_sec": duration,
        "lats_ms": lats_ms,
        "preds": preds
    }

def run_trial(trial_num):
    print(f"\n==================================================")
    print(f"STARTING TRIAL {trial_num} / 10")
    print(f"==================================================")
    trial_start_ts = datetime.now(timezone.utc).isoformat()
    
    # Phase 1: Specialized In-Pod Single-Service
    print("[Phase 1] Specialized Single-Pod Execution...")
    specialized_results = {}
    for svc, spec in POD_SPECS.items():
        res = execute_in_pod(svc)
        preds = np.array(res["preds"])
        cm = confusion_matrix(eval_labels, preds)
        tn, fp, fn, tp = cm.ravel()
        acc = accuracy_score(eval_labels, preds)
        prec = precision_score(eval_labels, preds, zero_division=0)
        rec = recall_score(eval_labels, preds, zero_division=0)
        f1 = f1_score(eval_labels, preds, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        lat_stats = calc_percentiles(res["lats_ms"])
        rps = len(res["lats_ms"]) / res["duration_sec"]
        
        specialized_results[svc] = {
            "service": svc,
            "pod_name": spec["pod_name"],
            "model_type": spec["model_type"],
            "threshold": spec["threshold"],
            "sample_count": len(res["lats_ms"]),
            "duration_sec": res["duration_sec"],
            "throughput_rps": rps,
            "latencies_ms": res["lats_ms"],
            "percentiles": lat_stats,
            "memory": {
                "rss_bytes": res["rss_bytes"],
                "rss_mib": res["rss_bytes"] / (1024 * 1024),
                "hwm_bytes": res["hwm_bytes"],
                "hwm_mib": res["hwm_bytes"] / (1024 * 1024),
                "cgroup_bytes": res["cgroup_bytes"],
                "cgroup_mib": res["cgroup_bytes"] / (1024 * 1024)
            },
            "cpu_stat": res.get("cpu_stat", {}),
            "metrics": {
                "accuracy": float(acc), "precision": float(prec), "recall": float(rec), "f1": float(f1),
                "fpr": float(fpr), "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn)
            }
        }
        print(f"  * {svc:12s} ({spec['model_type'][:12]}): Mean={lat_stats['mean_ms']:.3f}ms | p95={lat_stats['p95_ms']:.3f}ms | RPS={rps:5.1f} | RSS={res['rss_bytes']/(1024*1024):.1f}MiB")

    # Phase 2: Global Baselines
    print("\n[Phase 2] Global Baselines...")
    global_results = {}
    for gkey, spec in GLOBAL_SPECS.items():
        res = execute_global_model(gkey)
        preds = np.array(res["preds"])
        cm = confusion_matrix(eval_labels, preds)
        tn, fp, fn, tp = cm.ravel()
        acc = accuracy_score(eval_labels, preds)
        prec = precision_score(eval_labels, preds, zero_division=0)
        rec = recall_score(eval_labels, preds, zero_division=0)
        f1 = f1_score(eval_labels, preds, zero_division=0)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        
        lat_stats = calc_percentiles(res["lats_ms"])
        rps = len(res["lats_ms"]) / res["duration_sec"]
        
        global_results[gkey] = {
            "key": gkey,
            "name": spec["name"],
            "features_count": len(spec["features"]),
            "threshold": spec["threshold"],
            "sample_count": len(res["lats_ms"]),
            "duration_sec": res["duration_sec"],
            "throughput_rps": rps,
            "latencies_ms": res["lats_ms"],
            "percentiles": lat_stats,
            "metrics": {
                "accuracy": float(acc), "precision": float(prec), "recall": float(rec), "f1": float(f1),
                "fpr": float(fpr), "tp": int(tp), "tn": int(tn), "fp": int(fp), "fn": int(fn)
            }
        }
        print(f"  * {gkey:17s}: Mean={lat_stats['mean_ms']:.3f}ms | p95={lat_stats['p95_ms']:.3f}ms | RPS={rps:5.1f} | Acc={acc:.4%}")

    # Phase 3: Concurrent 4-Pod Multi-Service
    print("\n[Phase 3] Concurrent 4-Pod Workload (True Multi-Pod Execution)...")
    worker_times = {}
    t_start_all = time.perf_counter()
    def concurrent_worker(svc):
        w_t0 = time.perf_counter()
        res = execute_in_pod(svc)
        w_t1 = time.perf_counter()
        return svc, res, w_t0, w_t1

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(concurrent_worker, svc) for svc in POD_SPECS.keys()]
        for fut in futures:
            svc, res, w_t0, w_t1 = fut.result()
            lat_stats = calc_percentiles(res["lats_ms"])
            worker_times[svc] = {
                "pod_name": POD_SPECS[svc]["pod_name"],
                "start": w_t0,
                "end": w_t1,
                "duration": w_t1 - w_t0,
                "samples_completed": len(res["lats_ms"]),
                "worker_rps": len(res["lats_ms"]) / (w_t1 - w_t0),
                "latencies_ms": res["lats_ms"],
                "percentiles": lat_stats,
                "cgroup_bytes": res["cgroup_bytes"],
                "cgroup_mib": res["cgroup_bytes"] / (1024 * 1024),
                "cpu_stat": res.get("cpu_stat", {})
            }
    t_end_all = time.perf_counter()
    t_common = t_end_all - t_start_all
    total_samples = 4 * 500
    aggregate_rps = total_samples / t_common
    print(f"  * Concurrent Completed: 2,000 predictions across 4 pods in {t_common:.3f}s -> Aggregate RPS = {aggregate_rps:.1f}")

    # Phase 4: Cluster Safety & Baseline Verification
    print("[Phase 4] Cluster Baseline & Routing Safety Audit...")
    ssh = get_ssh_client()
    stdin, stdout, stderr = ssh.exec_command("kubectl get virtualservices -n default -o json")
    vs_data = json.loads(stdout.read().decode('utf-8'))
    for vs in vs_data.get("items", []):
        vs_name = vs["metadata"]["name"]
        if vs_name in ["productpage", "details", "reviews", "ratings"]:
            route_dest = vs["spec"]["http"][0]["route"][0]
            subset = route_dest.get("destination", {}).get("subset")
            weight = route_dest.get("weight", 100)
            assert subset == "v1", f"VirtualService {vs_name} route subset {subset} != v1!"
            assert weight == 100, f"VirtualService {vs_name} route weight {weight} != 100!"

    stdin, stdout, stderr = ssh.exec_command("kubectl get leases -n default -o json")
    lease_data = json.loads(stdout.read().decode('utf-8'))
    leases = lease_data.get("items", [])
    assert len(leases) == 10, f"Expected 10 leases, found {len(leases)}"
    for l in leases:
        holder = l.get("spec", {}).get("holderIdentity")
        assert not holder, f"Lease {l['metadata']['name']} held by {holder}!"
    ssh.close()
    print("  * Safety Verified: All 4 VirtualServices at v1=100%, all 10 Leases unheld.")

    trial_end_ts = datetime.now(timezone.utc).isoformat()

    trial_payload = {
        "trial_id": trial_num,
        "trial_start_ts": trial_start_ts,
        "trial_end_ts": trial_end_ts,
        "specialized_single_service": specialized_results,
        "global_baselines": global_results,
        "concurrent_four_service": {
            "total_requests": total_samples,
            "t_common_duration_sec": t_common,
            "aggregate_throughput_rps": aggregate_rps,
            "per_service": worker_times
        },
        "audit": {
            "routing_safe": True,
            "leases_unheld": 10
        }
    }

    out_file = os.path.join(RAW_OUT_DIR, f"trial_{trial_num}.json")
    with open(out_file, "w") as jf:
        json.dump(trial_payload, jf, indent=2)
    print(f"Saved: {out_file}")

def main():
    print("================================================================================")
    print("SCENARIO 4: FULL 10-TRIAL BENCHMARK EXECUTION")
    print("Benchmarking Deployed Specialized Models vs Global Baselines & 4-Pod Concurrency")
    print("================================================================================")
    for trial_idx in range(1, 11):
        run_trial(trial_idx)
    print("\nALL 10 TRIALS COMPLETED SUCCESSFULLY.")

if __name__ == '__main__':
    main()
