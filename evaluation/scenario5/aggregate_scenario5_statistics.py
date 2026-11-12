import json, os, glob
import numpy as np

raw_dir = "PAPER/Backup/SCENARIO_5_BENCHMARK_RESULTS/raw"
rep_trials = [f"concurrent_rep_{i}" for i in range(1, 6)]

data = []
for t in rep_trials:
    p = os.path.join(raw_dir, f"trial_{t}_concurrent_autonomous.json")
    if os.path.exists(p):
        data.append(json.load(open(p)))

print(f"=== SCENARIO 5 REPETITION BENCHMARK AGGREGATION ({len(data)} Repetitions) ===")

services = ["productpage", "details", "reviews", "ratings"]
metrics = {s: {"occ_mit_lat": [], "poll_mit_lat": [], "occ_td_lat": [], "poll_td_lat": [], "benign_sent": 0, "benign_succ": 0} for s in services}

total_occ_updates = 0
total_occ_conflicts = 0
total_lease_acquisitions = 0
total_attack_attempted = 0
total_attack_successful = 0

for d in data:
    for s in services:
        s_data = d["services"][s]
        # Latencies
        if s_data.get("quarantine_latency_occ_s") is not None:
            metrics[s]["occ_mit_lat"].append(s_data["quarantine_latency_occ_s"])
        if s_data.get("quarantine_latency_poll_s") is not None:
            metrics[s]["poll_mit_lat"].append(s_data["quarantine_latency_poll_s"])
        if s_data.get("teardown_latency_occ_s") is not None:
            metrics[s]["occ_td_lat"].append(s_data["teardown_latency_occ_s"])
        if s_data.get("teardown_latency_poll_s") is not None:
            metrics[s]["poll_td_lat"].append(s_data["teardown_latency_poll_s"])
        
        # Benign
        bs = s_data.get("benign_summary", {})
        metrics[s]["benign_sent"] += bs.get("total_sent", 0)
        metrics[s]["benign_succ"] += bs.get("success_200", 0)
        
        # OCC & Lease
        total_occ_updates += len(s_data.get("occ_atomic_update_events", []))
        total_occ_conflicts += s_data.get("occ_conflicts_count", 0)
        total_lease_acquisitions += len(s_data.get("lease_acquisition_events", []))
        
        # Attack
        pa = s_data.get("phase_A_attacker_summary", {})
        total_attack_attempted += pa.get("total_requests", 0)
        total_attack_successful += pa.get("successful_deliveries", 0)

print("\n--- PER-SERVICE MITIGATION & TEARDOWN LATENCIES ---")
print(f"{'Service':<12} | {'OCC Mit Mean±Std (s)':<22} | {'Poll Mit Mean±Std (s)':<22} | {'OCC TD Mean±Std (s)':<22} | {'Poll TD Mean±Std (s)':<22}")
print("-" * 110)

stats_table = {}
for s in services:
    occ_m = np.array(metrics[s]["occ_mit_lat"])
    poll_m = np.array(metrics[s]["poll_mit_lat"])
    occ_td = np.array(metrics[s]["occ_td_lat"])
    poll_td = np.array(metrics[s]["poll_td_lat"])
    
    stats_table[s] = {
        "occ_mit": {"mean": float(np.mean(occ_m)), "std": float(np.std(occ_m)), "min": float(np.min(occ_m)), "max": float(np.max(occ_m))},
        "poll_m": {"mean": float(np.mean(poll_m)), "std": float(np.std(poll_m)), "min": float(np.min(poll_m)), "max": float(np.max(poll_m))},
        "occ_td": {"mean": float(np.mean(occ_td)), "std": float(np.std(occ_td)), "min": float(np.min(occ_td)), "max": float(np.max(occ_td))},
        "poll_td": {"mean": float(np.mean(poll_td)), "std": float(np.std(poll_td)), "min": float(np.min(poll_td)), "max": float(np.max(poll_td))},
        "benign_sent": metrics[s]["benign_sent"],
        "benign_succ": metrics[s]["benign_succ"],
        "benign_avail_pct": float(metrics[s]["benign_succ"] / metrics[s]["benign_sent"] * 100) if metrics[s]["benign_sent"] > 0 else 0.0
    }
    
    print(f"{s:<12} | {np.mean(occ_m):.2f} ± {np.std(occ_m):.2f} ({np.min(occ_m):.2f}-{np.max(occ_m):.2f})   | "
          f"{np.mean(poll_m):.2f} ± {np.std(poll_m):.2f} ({np.min(poll_m):.2f}-{np.max(poll_m):.2f})   | "
          f"{np.mean(occ_td):.2f} ± {np.std(occ_td):.2f} ({np.min(occ_td):.2f}-{np.max(occ_td):.2f})   | "
          f"{np.mean(poll_td):.2f} ± {np.std(poll_td):.2f} ({np.min(poll_td):.2f}-{np.max(poll_td):.2f})")

print("\n--- BENIGN TRAFFIC CONTINUITY SUMMARY ---")
mesh_benign_sent = sum(metrics[s]["benign_sent"] for s in services)
mesh_benign_succ = sum(metrics[s]["benign_succ"] for s in services)
for s in services:
    sent = metrics[s]["benign_sent"]
    succ = metrics[s]["benign_succ"]
    pct = (succ / sent * 100) if sent > 0 else 0.0
    print(f"{s:<12}: {succ} / {sent} HTTP 200 ({pct:.3f}%)")
print(f"Total Mesh  : {mesh_benign_succ} / {mesh_benign_sent} HTTP 200 ({mesh_benign_succ/mesh_benign_sent*100:.4f}%)")

print("\n--- OCC CONCURRENCY & LEASE TOTALS ---")
print(f"Total OCC Atomic Updates Committed: {total_occ_updates}")
print(f"Total Unresolved OCC Conflicts    : {total_occ_conflicts}")
print(f"Total Lease Acquisitions / Locks  : {total_lease_acquisitions}")
print(f"Total Attack Requests Attempted   : {total_attack_attempted}")
print(f"Total Attack Requests Successful  : {total_attack_successful} ({total_attack_successful/total_attack_attempted*100:.2f}%)")

# Save aggregated stats JSON
agg_path = os.path.join(raw_dir, "scenario5_concurrent_repetitions_aggregated_stats.json")
with open(agg_path, "w", encoding="utf-8") as f:
    json.dump({
        "repetitions_count": len(data),
        "trial_ids": rep_trials,
        "mesh_benign_sent": mesh_benign_sent,
        "mesh_benign_succ": mesh_benign_succ,
        "mesh_benign_avail_pct": mesh_benign_succ / mesh_benign_sent * 100,
        "total_occ_updates": total_occ_updates,
        "total_occ_conflicts": total_occ_conflicts,
        "total_lease_acquisitions": total_lease_acquisitions,
        "per_service_stats": stats_table
    }, f, indent=2)
print(f"\nSaved aggregated statistics to: {agg_path}")
