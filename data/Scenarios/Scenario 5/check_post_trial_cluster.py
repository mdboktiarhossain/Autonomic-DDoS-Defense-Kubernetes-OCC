import os, sys

if not os.getenv("SSH_PASS") and not os.getenv("SSH_KEY"):
    raise SystemExit("Set SSH_PASS or SSH_KEY environment variable. No credential fallbacks are provided.")
import run_scenario5_concurrent_harness as h

print("=== POST-PILOT CLUSTER VERIFICATION ===")
pre = h.run_global_preflight()
print("Held Leases:", [k for k, v in pre["leases"].items() if v])
print("Defenders:", {k: f"restarts={v['restarts']}" for k, v in pre["defenders"].items()})
vs = h.poll_all_virtual_services()
for k, v in vs.items():
    print(f"VS {k:<10}: rules={v['rules_count']}, quarantine={v['quarantine_present']}, routes={v['production_routes']}")
