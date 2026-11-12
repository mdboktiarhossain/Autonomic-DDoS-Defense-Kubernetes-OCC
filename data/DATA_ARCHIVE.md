# Full Raw Experimental Data Archive (~22 GB)

## Overview

During the experimental evaluation of the decentralized service-mesh DDoS defense framework (including over 50 multi-cycle test runs across Scenarios 1–5, kernel `strace` syscall profiling, and multi-day CIC-IDS2017/DistriNet flow evaluations), approximately **22 GB of raw telemetry, container logs, and dataset splits** were generated.

Because GitHub enforces a 100 MB per-file limit and recommends keeping code repositories lightweight, we provide:
1. **In This GitHub Repository (`data/sample_evidence/` and `models/`):**
   * All frozen 7-feature model bundles (`.joblib`), `StandardScaler` parameters, and JSON model registries (`models/`).
   * Reconciled trial-by-trial summary JSONs, manifest files, markdown audit reports, and compact raw evidence `.zip` bundles for **Scenarios 1–5** (`data/sample_evidence/Scenario_1/` through `Scenario_5/`).
2. **In the Cloud Storage Archive (OneDrive):**
   * The complete ~22 GB raw data archive, organized in the hierarchy below.

---

## Cloud Archive Access (Available Upon Request)

* **Cloud Archive Link (OneDrive):** `[Insert Your OneDrive Shared Folder Link Here — Click to Request Access]`
* *Note for Reviewers and Researchers:* Click the OneDrive link above to request read access, or contact the authors to receive a direct download token.

---

## Cloud Archive Folder Hierarchy

```text
DDoS_ServiceMesh_Raw_Experimental_Archive/
├── 01_Datasets_CIC_IDS2017_DistriNet/
│   ├── wednesday.csv                  # Raw Wednesday HTTP capture (496,641 rows; 43,166 curated flows)
│   ├── monday_benign.csv              # Unseen Monday benign HTTP flows
│   ├── friday_benign.csv              # Unseen Friday benign HTTP flows
│   └── friday_loic_ddos.csv           # Unseen Friday LOIC HTTP flood flows (20,000 flows)
│
├── 02_Scenario_1_Single_Service_Quarantine/
│   ├── decentralized_10_trials/       # Per-trial defender logs, VirtualService YAML snapshots, client latencies
│   └── centralized_10_trials/         # Per-trial centralized controller logs and client traces
│
├── 03_Scenario_2_Concurrency_and_Kernel_Futex_Profiling/
│   ├── approach1_60rps_90rps_logs/    # Per-request inference latency and throughput traces (10 repetitions)
│   ├── approach2_live_cluster_cycles/ # Concurrent 4-service L7 cycle logs & T_con micro-benchmarks
│   └── kernel_strace_futex_dumps/     # Raw Linux strace -f -c -T and getrusage thread-wait profiles
│
├── 04_Scenario_3_Fault_Blast_Radius_Containment/
│   ├── decentralized_crash_trials/    # 10 trials with induced productpage defender outage (30/30 surviving quarantines)
│   └── centralized_crash_trials/      # 10 trials with central controller outage (100% protection loss)
│
├── 05_Scenario_4_Model_Generalization_and_Scaling/
│   ├── strict_out_of_fold_cv/         # GroupShuffleSplit Flow-ID disjoint folds & duplicate-removed sensitivity
│   ├── cross_day_loic_and_benign/     # Full confusion matrices, ROC-AUC, PR-AUC, and threshold sweep logs
│   └── live_pod_scaling_1_to_4_pods/  # In-container RF & HGB scoring latency distributions
│
└── 06_Scenario_5_End_to_End_Concurrent_Mitigation_and_Recovery/
    ├── repetition_1_to_5_raw_logs/    # Full 4-service synchronized 160 RPS attack & 2-stage recovery traces
    ├── lease_occ_audit_trails/        # 56/56 first-attempt OCC VirtualService patch & fencing token logs
    └── stage3b_gateway_provenance/    # 95 live windows + anti-framing & East-West spoofing rejection logs
```
