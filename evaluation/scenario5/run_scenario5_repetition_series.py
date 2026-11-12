#!/usr/bin/env python3
"""
Scenario 5 — Four-Service Concurrent Benchmark Repetition Series Runner
=======================================================================
Sequentially executes synchronized four-service concurrent DDoS mitigation trials
with strict pre-trial and post-trial cluster verification, dual timestamp recording,
per-request benign and attack logging, and cumulative metric aggregation.
"""

import argparse
import datetime
import json
import os
import sys
import time

if not os.getenv("SSH_PASS") and not os.getenv("SSH_KEY"):
    raise SystemExit("Set SSH_PASS or SSH_KEY environment variable. No credential fallbacks are provided.")

import run_scenario5_concurrent_harness as harness

RAW_DIR = "PAPER/Backup/SCENARIO_5_BENCHMARK_RESULTS/raw"
INTER_TRIAL_SOAK_S = 15.0

def run_pre_trial_baseline_audit(rep_num, trial_id):
    print(f"\n================================================================================")
    print(f"[REPETITION {rep_num}] Pre-Trial Baseline Audit for '{trial_id}'...")
    print(f"================================================================================")
    pre = harness.run_global_preflight()
    held = [k for k, v in pre["leases"].items() if v]
    if held:
        raise RuntimeError(f"Pre-trial baseline failure: Leases currently held in 'default': {held}")
    
    for dep, status in pre["defenders"].items():
        if not status["ready"]:
            raise RuntimeError(f"Pre-trial baseline failure: Defender {dep} is not Ready")
        if status["restarts"] > 0:
            raise RuntimeError(f"Pre-trial baseline failure: Defender {dep} has {status['restarts']} restarts")
    
    vs = harness.poll_all_virtual_services()
    for svc, profile in harness.SERVICES.items():
        vs_name = profile["vs_name"]
        info = vs[vs_name]
        if info["rules_count"] != 1 or info["quarantine_present"] or info["production_routes"] != [("v1", 100)]:
            raise RuntimeError(f"Pre-trial baseline failure: {vs_name} not at clean baseline: {info}")
    
    print(f"[REPETITION {rep_num}] Pre-trial baseline certified clean. Ready for trial execution.\n")
    return pre

def run_post_trial_verification(rep_num, trial_id):
    print(f"\n[REPETITION {rep_num}] Post-Trial Baseline Verification for '{trial_id}'...")
    post = harness.run_global_preflight()
    held = [k for k, v in post["leases"].items() if v]
    if held:
        raise RuntimeError(f"Post-trial baseline failure: Leases remaining held after recovery: {held}")
    
    for dep, status in post["defenders"].items():
        if status["restarts"] > 0:
            raise RuntimeError(f"Post-trial baseline failure: Defender {dep} recorded {status['restarts']} restarts")
    
    vs = harness.poll_all_virtual_services()
    for svc, profile in harness.SERVICES.items():
        vs_name = profile["vs_name"]
        info = vs[vs_name]
        if info["rules_count"] != 1 or info["quarantine_present"] or info["production_routes"] != [("v1", 100)]:
            raise RuntimeError(f"Post-trial baseline failure: {vs_name} not restored to clean baseline: {info}")
    
    print(f"[REPETITION {rep_num}] Post-trial baseline certified clean: 10/10 unheld Leases, 0 restarts, all 4 VS at baseline.")
    return True

def execute_repetition(rep_num, trial_id, raw_dir):
    t_start = time.time()
    # 1. Pre-trial baseline check
    run_pre_trial_baseline_audit(rep_num, trial_id)
    
    # 2. Execute concurrent trial
    harness.execute_concurrent_trial(trial_id, raw_dir)
    
    # 3. Post-trial verification
    run_post_trial_verification(rep_num, trial_id)
    
    # 4. Read result summary
    trial_file = os.path.join(raw_dir, f"trial_{trial_id}_concurrent_autonomous.json")
    with open(trial_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    passed_cnt = sum(1 for v in data["assertions"].values() if v)
    total_cnt = len(data["assertions"])
    elapsed = time.time() - t_start
    print(f"\n[REPETITION {rep_num} COMPLETE] Trial '{trial_id}': {passed_cnt}/{total_cnt} assertions passed in {elapsed:.1f}s.")
    return data

def main():
    parser = argparse.ArgumentParser(description="Scenario 5 Benchmark Repetition Series")
    parser.add_argument("--start-rep", type=int, default=1, help="Starting repetition number")
    parser.add_argument("--num-reps", type=int, default=1, help="Number of repetitions to run")
    parser.add_argument("--prefix", default="concurrent_rep", help="Trial ID prefix")
    parser.add_argument("--raw-dir", default=RAW_DIR, help="Raw evidence directory")
    args = parser.parse_args()

    os.makedirs(args.raw_dir, exist_ok=True)
    results_summary = []

    for r in range(args.start_rep, args.start_rep + args.num_reps):
        trial_id = f"{args.prefix}_{r}"
        print(f"\n================================================================================")
        print(f"STARTING SCENARIO 5 REPETITION {r} of {args.start_rep + args.num_reps - 1}: {trial_id}")
        print(f"================================================================================")
        
        trial_data = execute_repetition(r, trial_id, args.raw_dir)
        results_summary.append({
            "repetition": r,
            "trial_id": trial_id,
            "status": trial_data.get("status"),
            "assertions_passed": sum(1 for v in trial_data["assertions"].values() if v),
            "assertions_total": len(trial_data["assertions"]),
            "services": {
                svc: {
                    "attribution": s.get("observed_attribution"),
                    "mitigation_class": s.get("observed_mitigation_class"),
                    "occ_latency_s": s.get("quarantine_latency_occ_s"),
                    "poll_latency_s": s.get("quarantine_latency_poll_s"),
                    "teardown_occ_s": s.get("teardown_latency_occ_s"),
                    "benign_success": s.get("benign_summary", {}).get("success_rate"),
                    "benign_total": s.get("benign_summary", {}).get("total_sent"),
                    "benign_200": s.get("benign_summary", {}).get("success_200")
                }
                for svc, s in trial_data.get("services", {}).items()
            }
        })

        if r < args.start_rep + args.num_reps - 1:
            print(f"\n[INTER-TRIAL COOLDOWN] Soaking for {INTER_TRIAL_SOAK_S}s before next repetition...")
            time.sleep(INTER_TRIAL_SOAK_S)

    summary_file = os.path.join(args.raw_dir, f"scenario5_repetition_series_summary_{args.prefix}_{args.start_rep}_to_{args.start_rep + args.num_reps - 1}.json")
    with open(summary_file, "w", encoding="utf-8") as sf:
        json.dump(results_summary, sf, indent=2)
    print(f"\n================================================================================")
    print(f"REPETITION SERIES COMPLETE. Summary saved to: {summary_file}")
    print(f"================================================================================")

if __name__ == "__main__":
    main()
