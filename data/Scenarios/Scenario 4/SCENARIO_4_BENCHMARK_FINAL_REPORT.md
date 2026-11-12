# Scenario 4 Benchmark Final Report: Service-Specific Heterogeneous Model Performance and Latency Trade-Offs

**Document ID:** `SCENARIO_4_BENCHMARK_FINAL_REPORT.md`  
**Date:** November 5, 2026  
**Environment:** Active Enforcement Mode (`cic-v5.3`) on Istio Service Mesh (Minikube `192.168.160.129`)  
**Scope:** 10 Measured Benchmark Trials across 4 Independent Defender Pods, Single-Service Workloads, Global Model Baselines, and Multi-Pod Concurrency  
**Primary Artifacts:** 
- Summary: [`PAPER/Backup/SCENARIO_4_BENCHMARK_SUMMARY.json`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/Backup/SCENARIO_4_BENCHMARK_SUMMARY.json) (`SHA-256: d3449cbd3c6b75abe2aefbac7e71b0b619b0d7b2deb0d9114e4eb49bf226b4d9`)
- Raw Archive: [`PAPER/Backup/SCENARIO_4_BENCHMARK_RAW_EVIDENCE.zip`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/Backup/SCENARIO_4_BENCHMARK_RAW_EVIDENCE.zip) (`SHA-256: e18f51f986cb17e6aad88f2d5e9ece9fe3b362669f8542b34d0403db46e8efd1`)
- Manifest: [`PAPER/Backup/SCENARIO_4_EVIDENCE_MANIFEST.json`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/Backup/SCENARIO_4_EVIDENCE_MANIFEST.json) (`SHA-256: c3998d448c59500949d0f247d535bdcaf1a5daad70cbc47b7190bc00c4e66f8d`)
- Reconciler: [`PAPER/Backup/reconcile_scenario4_statistics.py`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/Backup/reconcile_scenario4_statistics.py) (`SHA-256: 2f08d15ca6efb0e8fcd87f8bd726b03743f96009543353d053700f2471da7427`)
- Execution Script: [`PAPER/Backup/run_scenario4_full_benchmark.py`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/Backup/run_scenario4_full_benchmark.py) (`SHA-256: 1199caf931d9d4b1a8a20e3304bee313a6059f1f0e092da05cabb93ba5ae9215`)
- LaTeX Section: [`PAPER/Backup/SCENARIO_4_RESULTS_SECTION.tex`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/Backup/SCENARIO_4_RESULTS_SECTION.tex)

---

## 1. Executive Summary

Scenario 4 investigates the core machine learning research question:
> *Can service-specific machine learning models provide accurate DDoS detection with low inference overhead, negligible false-positive rates, and efficient resource utilization across heterogeneous microservices?*

Across **10 independent benchmark trials ($N=10$)** executed inside **four live Kubernetes defender pods** and evaluated against **7-feature and 14-feature global baselines**, our findings demonstrate that:
1. **Restored Certified Classification Fidelity:**
   - **Cross-Day Attack Recall ($N = 20,000$ Friday LOIC):** Deployed models achieved **$99.70\%$** on `productpage`, **$99.76\%$** on `details`, **$99.89\%$** on `reviews`, and **$99.97\%$** on `ratings` without retraining.
   - **Large-Scale Benign Safety ($N = 67,886$ Monday \& Friday HTTP):** False-positive rates remained strictly bounded below $0.20\%$ ($0.14\%$ on `productpage`, $0.15\%$ on `details`, $0.19\%$ on `reviews`, $0.12\%$ on `ratings`).
   - **Live Benign Mesh Validation ($N = 400$ Requests):** Recorded **$0 / 400$ false positives ($0.00\%$ live FPR)** across 11 discrete scrape windows.
2. **In-Pod Latency Trade-Offs by Service & Architecture:**
   - Deployed Random Forest models on `productpage` and `ratings` averaged a trial-level mean latency of **$4.324 \pm 0.499\text{ ms}$**, compared to **$0.832 \pm 0.114\text{ ms}$** for HistGradientBoosting models on `details` and `reviews`.
   - A trial-level Welch's $t$-test indicates that this latency difference is statistically significant ($t = 21.584$, $p = 1.126 \times 10^{-9}$), reflecting the combined effect of decision tree structures and service-specific feature schemas.
3. **Decomposition of Multi-Pod Concurrency Overhead:**
   - Under 4-pod concurrent workload (2,000 predictions across 4 pods per trial), total worker wall-clock duration averaged $8.60 \pm 2.20\text{ s}$ ($246.39 \pm 61.75\text{ RPS}$).
   - **Measured Non-Inference Overhead:** Timing decomposition demonstrates that approximately $6\text{ s}$ per worker ($4.5\text{ s}$ to $5.3\text{ s}$ of residual duration beyond model evaluation) represents measured non-inference invocation overhead. Possible contributors in our testbed include Paramiko SSH transport negotiation, `kubectl exec` SPDY session establishment, containerd process creation, Python runtime initialization, scikit-learn model unpickling, and initial warmup passes, which were not separately instrumented in-situ. Pure in-container model prediction times averaged only $0.56\text{ s}$ for `details`, $0.62\text{ s}$ for `reviews`, $2.55\text{ s}$ for `productpage`, and $2.56\text{ s}$ for `ratings`.
   - **Latency Preservation:** In-container per-flow inference latency remained sub-millisecond on backend services ($0.997\text{ ms}$ on `details`, $1.139\text{ ms}$ on `reviews`), shifting by less than $0.3\text{ ms}$ from isolated baselines.
4. **Clarification on CPU Throttling:**
   - Telemetry from `/sys/fs/cgroup/cpu.stat` revealed that cumulative container throttling counters increased between the pre-test snapshot and the post-concurrency snapshot (mean delta of $+13$ to $+21$ throttled periods per container, or $\approx 5-7\%$ of accounting periods). Because available kernel counters span the entire interval between measurement snapshots rather than isolating only the active prediction burst, we note that modest throttling occurred during the test cycle and do not claim zero CPU throttling.
5. **Memory Accounting Distinguishes Container RSS from Model Serialization:**
   - Serialized model files require only $110.5\text{ KB}$--$740.8\text{ KB}$ on disk. Container resident memory (`VmRSS`) stabilized at $154.6\text{ MiB}$--$160.0\text{ MiB}$ and cgroup memory at $286.0\text{ MiB}$--$304.7\text{ MiB}$.

---

## 2. Real-Pod Verification Gate Audit

Prior to initiating the 10-trial benchmark, a strict pre-benchmark verification gate confirmed process isolation and container integrity across all four active defender pods:

| Service | Pod Name | Pod IP | Container UID | Bundle File | SHA-256 Checksum | Gate Status |
| :--- | :--- | :---: | :---: | :--- | :---: | :---: |
| `productpage` | `ddos-defender-product-5b5d95fc88-qmjp9` | `10.244.2.23` | `18fbce46...` | `productpage_bundle_7feat.joblib` | `93b55282b0d392f049ada29054749646c7ffbc9a6bfe4d6d81f45322f199be14` | **PASSED** |
| `details` | `ddos-defender-details-656c4f644d-nsxmr` | `10.244.2.22` | `06eb0cb8...` | `details_bundle_7feat.joblib` | `d65136992788cf68376b8821c0d8d598020a55ba84140c1a3bdb3ceb06e4977c` | **PASSED** |
| `reviews` | `ddos-defender-reviews-87c5895c8-whfs4` | `10.244.2.24` | `a76bac49...` | `reviews_bundle_7feat.joblib` | `63f4ee6f7d69d8e507955507d9d751ef850754ae52a9903bc323d9cf310ebdfc` | **PASSED** |
| `ratings` | `ddos-defender-ratings-5c5d5f94cb-2f6n6` | `10.244.2.25` | `cc34179e...` | `ratings_bundle_7feat.joblib` | `e7b14bf17f428dde7820dca07678601b95bde1dac1a3013cbb8916080cfb75d5` | **PASSED** |

- **Process Separation:** All 4 defender pods have strictly unique Pod UIDs, Container IDs, and Pod IPs.
- **Numerical Parity:** Sample flow vectors evaluated inside the containers matched local reference models with absolute maximum difference $\Delta = 0.00 \times 10^0$.
- **Cluster Preflight:** All 4 VirtualServices verified at `v1=100%`, and all 10 Kubernetes Lease locks confirmed unheld.

---

## 3. Restored Certified Classification Accuracy and False-Positive Profiles

We restore the previously certified offline and live benign evaluation metrics established in the active-enforcement deployment:

| Service | Model Architecture | Threshold ($T$) | Features | Held-Out Wed. Acc. ($N=8,484$) | Friday LOIC Recall ($N=20,000$) | Benign FPR ($N=67,886$) | Live Benign FP ($N=400$) |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `productpage` | `RandomForestClassifier` | 0.70 | 7 | 99.99% [99.93, 100] | 99.70% [99.61, 99.77] | 0.14% [0.12, 0.17] | **0 / 400 (0.00%)** |
| `details` | `HistGradientBoosting` | 0.80 | 7 | 99.99% [99.93, 100] | 99.76% [99.68, 99.82] | 0.15% [0.12, 0.18] | **0 / 400 (0.00%)** |
| `reviews` | `HistGradientBoosting` | 0.70 | 7 | 100.00% [99.95, 100] | 99.89% [99.84, 99.93] | 0.19% [0.16, 0.22] | **0 / 400 (0.00%)** |
| `ratings` | `RandomForestClassifier` | 0.70 | 7 | 100.00% [99.95, 100] | 99.97% [99.93, 99.98] | 0.12% [0.10, 0.15] | **0 / 400 (0.00%)** |

### Reconciliation of Dataset Denominators:
1. **Held-Out Wednesday Test Split ($N=8,484$):** $5,468$ attack flows, $3,016$ benign flows, partitioned strictly by `Flow ID` via `GroupShuffleSplit` (0 overlapping Flow IDs with training data).
2. **Friday LOIC Attack Corpus ($N=20,000$):** Unseen Low Orbit Ion Cannon flood attacks used to evaluate cross-day generalizability against different attack tooling without retraining.
3. **Multi-Day Benign Evaluation ($N=67,886$):** Comprises $36,111$ Monday HTTP flows and $31,775$ Friday HTTP flows, testing benign false-positive resistance across enterprise traffic.
4. **Live Mesh Telemetry ($N=400$):** $400$ completed user HTTP requests through Envoy proxies over 11 scrape windows; recorded $0$ spurious quarantines.

---

## 4. Single-Pod Inference Latency and Memory Trade-Offs

Each trial executed 500 timed single-flow inference operations per service inside the container environment. The table below presents the reconciled 10-trial statistics ($s$, $N-1=9$ sample standard deviation; percentiles computed using nearest-rank `inverted_cdf`):

| Service | Model | Mean Latency (ms) | 95% CI (ms) | p50 (ms) | p95 (ms) | p99 (ms) | Standalone Throughput (RPS) | VmRSS (MiB) | cgroup (MiB) | Bundle Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `productpage` | RF  | $4.44 \pm 0.62$ | [4.00, 4.88] | $3.89 \pm 0.36$ | $6.52 \pm 1.45$ | $12.23 \pm 9.82$ | $228.7 \pm 28.6$  | $160.03 \pm 0.18$ | $304.65 \pm 0.08$ | 740.8 KB |
| `details`     | HGB | $0.75 \pm 0.11$ | [0.67, 0.83] | $0.66 \pm 0.07$ | $1.03 \pm 0.21$ | $1.52 \pm 0.43$  | $1346.4 \pm 178.8$ | $154.58 \pm 0.13$ | $285.99 \pm 0.06$ | 110.5 KB |
| `reviews`     | HGB | $0.91 \pm 0.14$ | [0.81, 1.01] | $0.79 \pm 0.09$ | $1.24 \pm 0.29$ | $2.16 \pm 1.43$  | $1118.9 \pm 156.8$ | $154.69 \pm 0.16$ | $286.99 \pm 0.08$ | 134.6 KB |
| `ratings`     | RF  | $4.21 \pm 0.58$ | [3.79, 4.62] | $3.73 \pm 0.38$ | $6.05 \pm 1.65$ | $12.26 \pm 4.97$ | $241.3 \pm 30.4$  | $158.90 \pm 0.24$ | $288.51 \pm 0.12$ | 568.0 KB |

### Statistical Comparison:
- **Random Forest (Trial-Level Mean):** $4.324 \pm 0.499\text{ ms}$
- **HistGradientBoosting (Trial-Level Mean):** $0.832 \pm 0.114\text{ ms}$
- **Welch's $t$-test:** $t = 21.584$, $p = 1.126 \times 10^{-9}$ (statistically significant).

### Latency Distribution Visualization
![Inference Latency Distributions Across Services](C:/Users/mdbohos/.gemini/antigravity/brain/1243f7e2-4203-47f5-8fff-b5e3ec8d043a/fig_scenario4_inference_latencies.png)

---

## 5. Feature Budget Ablation: Specialized vs. Global Baselines

We benchmarked two global baselines on identical evaluation vectors:
- **7-Feature Global Baseline:** Strictly constrained to 7 features selected from training set mutual information only (`Packet Length Variance`, `Bwd Packet Length Mean`, `Packet Length Mean`, `Packet Length Std`, `Total Bwd packets`, `Flow Packets/s`, `Total Length of Bwd Packet`).
- **14-Feature Extended Baseline:** Ingests the full 14-feature union across all microservices.

| Baseline Model | Features | Mean Latency (ms) | p95 Latency (ms) | Throughput (RPS) | Test Errors ($N=8,484$) | Disk Size |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Global RF (7-Feature)** | 7 | $29.88 \pm 4.35$ | 38.40 | $34.1 \pm 5.3$ | 1 FP, 5 FN (Acc: 99.93%) | 1259.9 KB |
| **Global HGB (7-Feature)** | 7 | $1.65 \pm 0.25$ | 2.82 | $618.1 \pm 100.4$ | 3 FP, 2 FN (Acc: 99.94%) | 318.3 KB |
| **Global RF (14-Feature)** | 14 | $29.75 \pm 4.70$ | 38.34 | $34.4 \pm 5.9$ | 1 FP, 0 FN (Acc: 99.99%) | 1177.6 KB |
| **Global HGB (14-Feature)**| 14 | $1.87 \pm 0.47$ | 3.47 | $558.1 \pm 122.2$ | 4 FP, 1 FN (Acc: 99.94%) | 306.5 KB |
| **Specialized HGB (`details`)** | 7 | **$0.75 \pm 0.11$** | **1.03** | **$1346.4 \pm 178.8$** | 1 FP, 0 FN (Acc: 99.99%) | **110.5 KB** |
| **Specialized HGB (`reviews`)** | 7 | **$0.91 \pm 0.14$** | **1.24** | **$1118.9 \pm 156.8$** | 0 FP, 0 FN (Acc: 100.0%) | **134.6 KB** |

---

## 6. Multi-Pod Concurrency and Execution Overhead Decomposition

During the concurrent benchmark, four client threads issued simultaneous inference requests to all four running Kubernetes defender pods.

| Service | Worker Total Duration | Pure Model Eval Time | Orchestration Overhead | Worker In-Pod Latency | Standalone In-Pod Latency | CFS Throttling $\Delta$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `productpage` | $8.53 \pm 2.20\text{ s}$ | $2.36\text{ s}$ | $6.17\text{ s}$ | $4.71 \pm 0.37\text{ ms}$ | $4.44 \pm 0.62\text{ ms}$ | $+20$ periods |
| `details`     | $6.52 \pm 2.19\text{ s}$ | $0.50\text{ s}$ | $6.02\text{ s}$ | $1.00 \pm 0.23\text{ ms}$ | $0.75 \pm 0.11\text{ ms}$ | $+16$ periods |
| `reviews`     | $6.58 \pm 2.20\text{ s}$ | $0.57\text{ s}$ | $6.01\text{ s}$ | $1.14 \pm 0.19\text{ ms}$ | $0.91 \pm 0.14\text{ ms}$ | $+13$ periods |
| `ratings`     | $8.56 \pm 2.22\text{ s}$ | $2.38\text{ s}$ | $6.18\text{ s}$ | $4.76 \pm 0.44\text{ ms}$ | $4.21 \pm 0.58\text{ ms}$ | $+21$ periods |

### Concurrency Overhead Decomposition Visualization
![Per-Pod Latency Stability and Overhead Breakdown](C:/Users/mdbohos/.gemini/antigravity/brain/1243f7e2-4203-47f5-8fff-b5e3ec8d043a/fig_scenario4_throughput_scaling.png)

### Key Technical Findings:
1. **Measured Non-Inference Overhead:**
   - The ~6-second difference between total worker duration and model execution time represents non-inference invocation overhead.
   - Possible contributors in our environment include Paramiko SSH transport negotiation, `kubectl exec` API server stream negotiation, containerd exec shim process creation, Python runtime startup, module unpickling, and initial warmup passes, which were not separately instrumented in-situ.
2. **Per-Pod Latency Stability:**
   - In-container inference latency remained steady under concurrency: `details` increased from $0.75\text{ ms}$ to $1.00\text{ ms}$; `reviews` increased from $0.91\text{ ms}$ to $1.14\text{ ms}$; `productpage` shifted from $4.44\text{ ms}$ to $4.71\text{ ms}$; and `ratings` shifted from $4.21\text{ ms}$ to $4.76\text{ ms}$.
3. **Clarification on CPU Throttling:**
   - Containers recorded an average increase of 13 to 21 throttled CFS periods out of ~300 accounting periods between the pre-test snapshot and the post-concurrency snapshot. Because available kernel counters span the entire interval between measurement snapshots rather than isolating only the active prediction burst, we note that modest throttling occurred during the test cycle and do not claim zero CPU throttling.

---

## 7. Cluster Baseline & Post-Benchmark Safety Audit

Following completion of all 10 benchmark trials, the cluster was audited to ensure no lingering side-effects:
- **Istio VirtualServices:** All 4 VirtualServices (`productpage`, `details`, `reviews`, `ratings`) verified with route weight `v1=100%` and zero traffic routed to decoys or canary subsets.
- **Distributed Leases:** All 10 Kubernetes Lease objects audited; zero active locks held (`holderIdentity = ''`).
- **Container Health:** All 4 defender pods remained in continuous `1/1 Ready` state with 0 restarts throughout the entire benchmark.

---

## 8. Evidence Package and Verified Cryptographic Checksums

All raw experimental evidence, execution scripts, global models, and figures have been packed into `SCENARIO_4_BENCHMARK_RAW_EVIDENCE.zip` and cataloged in `SCENARIO_4_EVIDENCE_MANIFEST.json`:

- **Archive File:** `PAPER\Backup\SCENARIO_4_BENCHMARK_RAW_EVIDENCE.zip`
- **File Size:** $1,511.9\text{ KB}$ (1,548,223 bytes)
- **SHA-256 Checksum:** `e18f51f986cb17e6aad88f2d5e9ece9fe3b362669f8542b34d0403db46e8efd1`
- **Manifest Checksum:** `c3998d448c59500949d0f247d535bdcaf1a5daad70cbc47b7190bc00c4e66f8d`
- **Total Indexed Files:** 24 files (10 raw trial JSONs, 4 global model bundles, 1 evaluation dataset, 2 summary files, 4 figure files, 1 benchmark execution script, 1 verification script, 1 gate audit result).

### Verified File Checksums (Exact Match to Manifest and Disk):
- `SCENARIO_4_BENCHMARK_RESULTS/raw/trial_1.json`: `52ac9c2eddeb8ad33f3559b5cfa64725304f798b68c2a75b18f10af9b3724677`
- `SCENARIO_4_BENCHMARK_RESULTS/raw/trial_10.json`: `dd9f22d8802c148e61b6506ef5997568cf9469a48c526937e22b9ec1fd50b56d`
- `SCENARIO_4_BENCHMARK_SUMMARY.json`: `d3449cbd3c6b75abe2aefbac7e71b0b619b0d7b2deb0d9114e4eb49bf226b4d9`
- `run_scenario4_full_benchmark.py`: `1199caf931d9d4b1a8a20e3304bee313a6059f1f0e092da05cabb93ba5ae9215`
- `reconcile_scenario4_statistics.py`: `2f08d15ca6efb0e8fcd87f8bd726b03743f96009543353d053700f2471da7427`

---

## 9. Benchmark Execution and Reproduction Command

The benchmark was executed using the standalone script `run_scenario4_full_benchmark.py`:
```bash
# Command executed to run the full 10-trial benchmark:
python -u scratch/run_scenario4_full_benchmark.py
```

To reproduce and verify all Scenario 4 statistics directly from the raw trial records in read-only audit mode:
```bash
# Run the comprehensive read-only audit against raw trial data
python PAPER/Backup/reconcile_scenario4_statistics.py --verify-only
```

### Verified Output:
```text
VERIFY-ONLY AUDIT: Running Comprehensive Verification Across 10 Trials...
  [PASS] All 10 trials present with exact sample counts (500 per service, 500 per baseline, 2,000 concurrent).
  [PASS] Specialized model latencies, percentiles (p50, p95, p99), std devs, and throughput verified.
  [PASS] Global model baseline latencies, percentiles, and throughput verified.
  [PASS] Concurrent multi-pod execution metrics (T_common, Aggregate RPS, per-service latencies) verified.
  [PASS] Welch t-test statistics and p-values verified.
  [PASS] Cluster baseline safety audits verified (v1=100%, 10 Leases unheld across all 10 trials).
  [PASS] Manifest integrity verified (24 files checked).
==============================================================================
COMPREHENSIVE VERIFY-ONLY AUDIT: PASSED.
All raw trial data, sample counts, percentiles, confidence intervals,
throttling deltas, statistical tests, and manifest checksums match perfectly.
==============================================================================
```
