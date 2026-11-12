import json, sys

path = sys.argv[1] if len(sys.argv) > 1 else 'PAPER/Backup/SCENARIO_5_BENCHMARK_RESULTS/raw/trial_concurrent_pilot_r2_concurrent_autonomous.json'
d = json.load(open(path))
print("=== CONCURRENT TRIAL ANALYSIS ===")
print("Trial ID:", d.get("trial_id"))
print("Timing Barrier:", d.get("timing_barrier_vm"))
print("Status:", d.get("status"))

t_bar = d.get("timing_barrier_vm")
for svc, s in d["services"].items():
    print(f"\n--- {svc.upper()} ---")
    print("Recovery Path:", s.get("recovery_path"))
    print("Mitigation Class:", s.get("observed_mitigation_class"))
    print("Attribution:", s.get("observed_attribution"))
    print("Quarantine Latency (Polled):", s.get("quarantine_latency_poll_s"), "s")
    print("Quarantine Latency (OCC Internal):", s.get("quarantine_latency_occ_s"), "s")
    print("Initial Mitigation RV:", s.get("initial_mitigation_rv"))
    print("Teardown Latency (Polled):", s.get("teardown_latency_poll_s"), "s")
    print("Teardown Latency (OCC Internal):", s.get("teardown_latency_occ_s"), "s")
    print("Fencing Tokens: Q =", s.get("fencing_token_quarantine"), ", S2 =", s.get("fencing_token_teardown"))
    print("Lease Acquisitions:", len(s.get("lease_acquisition_events", [])))
    print("OCC Updates:", len(s.get("occ_atomic_update_events", [])))
    print("OCC Conflicts:", s.get("occ_conflicts_count"))
    
    pa = s.get("phase_A_attacker_summary", {})
    print(f"Phase A Traffic: {pa.get('successful_deliveries')}/{pa.get('total_requests')} ({pa.get('attempted_rps')} att RPS, {pa.get('successful_rps')} succ RPS, dur={pa.get('duration_s')}s)")
    
    dm = s.get("decoy_measurement", {})
    print(f"Decoy Interception: {dm.get('delta_attacker')} reqs ({dm.get('measured_rps')} RPS), benign leakage = {dm.get('delta_benign')}")
    
    bs = s.get("benign_summary", {})
    print(f"Benign Availability: {bs.get('success_200')}/{bs.get('total_sent')} ({bs.get('success_rate')*100:.2f}%), served by decoy = {bs.get('served_by_decoy')}, non-200 = {bs.get('non_200_count')}")

print("\n=== OVERALL ASSERTIONS ===")
passed = sum(1 for v in d["assertions"].values() if v)
total = len(d["assertions"])
print(f"Total: {passed}/{total} PASS")
failed = [k for k, v in d["assertions"].items() if not v]
print("Failed Assertions:", failed)
