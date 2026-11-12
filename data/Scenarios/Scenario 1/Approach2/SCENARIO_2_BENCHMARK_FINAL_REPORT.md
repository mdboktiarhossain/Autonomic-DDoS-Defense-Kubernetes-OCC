# Scenario 2 Benchmark Final Report & Raw Evidence Reconciliation Audit

**Storage Location:** `C:\Users\mdbohos\Desktop\ddos_detector\PAPER\Backup\SCENARIO_2_BENCHMARK_FINAL_REPORT.md`  
**Evaluation Testbed:** Kubernetes (Minikube 4 vCPUs, 8192 MB RAM) / Istio 1.24.2 / Bookinfo (`productpage`, `details`, `reviews`, `ratings`)  
**Evidence Package:** `C:\Users\mdbohos\Desktop\ddos_detector\PAPER\Backup\SCENARIO_2_BENCHMARK_RAW_EVIDENCE.zip`  
**Archive SHA-256:** `bc838a0136b1400115a67a96a29cb9cf97ed1dec107399aadf61a8d18ad9fd50`  

---

## 1. Executive Summary: Core Scientific Findings

Following the raw evidence audit across all 91 archive files and 20 individual trials (10 Decentralized vs. 10 Centralized), the empirical findings demonstrate:

1. **Quarantine Reliability Advantage (Primary Finding):**
   - **Decentralized Architecture:** **10/10 trials (100%)** successfully established quarantine routing for all four targeted services (**40/40 service instances, 100%**).
   - **Centralized Architecture:** **7/10 trials (70%)** successfully established quarantine routing for all four targeted services (**37/40 service instances, 92.5%**).
   - **Centralized Misses Identified in Raw Logs:**
     - *Trial 1:* `details` never entered quarantine (`has_quarantine: False`, decoy attacker hits = 0).
     - *Trial 2:* `details` never entered quarantine (`has_quarantine: False`, decoy attacker hits = 0).
     - *Trial 3:* `ratings` never entered quarantine (`has_quarantine: False`, decoy attacker hits = 0).
     - In all three cases, the centralized controller executed fallback routing changes to $v_2/v_3$ via the `RPS_ONLY` attribution path, but failed to insert the dedicated `quarantine-malicious` decoy route, leaving the attacker unisolated.
   - **Statistical Significance:** Fisher's exact test yields $p = 0.211$ at the trial level and $p = 0.241$ at the service level. While neither reaches statistical significance at $\alpha = 0.05$ (with service observations clustered within 10 trials), the decentralized architecture demonstrated complete four-service quarantine reliability across all executed runs.

2. **Time to First Observed Routing Action ($n=10$ vs. $n=10$):**
   - **Decentralized:** Mean time to first routing action = **$6.940 \pm 1.513\text{ s}$** (all 40 actions established active quarantine).
   - **Centralized:** Mean time to first routing action = **$8.061 \pm 3.467\text{ s}$** (37 established quarantine, 3 established non-quarantine fallback routing).
   - **Statistical Tests:** Two-sided Welch's t-test: $t = -0.937$, $\mathbf{p = 0.3669}$; Mann-Whitney U test: $U = 49.0$, $\mathbf{p = 0.9698}$.
   - **Conclusion:** While decentralized routing response is descriptively 13.9% to 18.2% faster, high inter-trial variance under multi-service bursts establishes an operational trend rather than formal statistical significance at $\alpha = 0.05$. All claims of $p < 0.05$ have been removed.

3. **Legitimate Traffic QoS & Architectural Trade-offs:**
   - **Total Verified Legitimate Requests:** 7,200 per architecture (14,400 mesh total).
   - **Percentile Convention:** Calculated using the **nearest-observation method** on successful HTTP responses (`numpy.percentile(lats, ..., method="nearest")`).
   - **Trade-off:**
     - *Centralized:* Lower median latency ($\text{p50} = \mathbf{4.55\text{ ms}}$ vs. $6.77\text{ ms}$), lower mean latency ($22.87\text{ ms}$ vs. $26.13\text{ ms}$), lower p99 latency ($\mathbf{234.30\text{ ms}}$ vs. $263.25\text{ ms}$), and fewer HTTP errors ($2$ vs. $4$, out of 7,200).
     - *Decentralized:* Lower pooled 95th-percentile tail latency (**$\text{p95} = \mathbf{47.59\text{ ms}}$** vs. **$55.87\text{ ms}$**; a $-14.82\%$ tail reduction during active multi-service failover) alongside complete quarantine coverage.
     - *Trial-level p95 averages:* $60.89 \pm 36.57\text{ ms}$ decentralized vs. $51.14 \pm 40.98\text{ ms}$ centralized ($t = 0.562, p = 0.581$).

4. **Zero Benign Quarantine Contamination:**
   - Exactly **zero (0) benign requests were diverted to decoys** across all 14,400 background transactions (0.00% false quarantine rate).

---

## 2. Delineation of Evaluation Tiers

To ensure complete clarity between computational micro-benchmarking and live traffic mitigation, the manuscript separates the two evaluation tiers:

### Tier A: ML Engine Concurrency Micro-benchmark (Historical Reference)
*Evaluates the computational API overhead ($T_{\text{ML}}$) of the `/api/predict` FastAPI endpoint under synthetic concurrent load (Section VI-A / VI-C of prior manuscript).*

#### Table XI: Scenario 2 Decentralized Micro-benchmark Results
| Service | Avg Latency (ms) | p95 Latency (ms) | Throughput (rps) | Errors |
| :--- | :---: | :---: | :---: | :---: |
| productpage | 19.67 | 31.45 | 238.52 | 0 |
| details     | 20.53 | 32.32 | 235.45 | 0 |
| reviews     | 19.99 | 31.42 | 239.17 | 0 |
| ratings     | 19.64 | 31.66 | 237.09 | 0 |
| **TOTAL**   | **19.96** | **31.71** | **936.19** | **0** |

#### Table XII: Scenario 2 Centralized Micro-benchmark Results
| Service | Avg Latency (ms) | p95 Latency (ms) | Throughput (rps) | Errors |
| :--- | :---: | :---: | :---: | :---: |
| productpage | 27.65 | 33.51 | 177.53 | 0 |
| details     | 27.61 | 32.88 | 175.08 | 0 |
| reviews     | 27.66 | 32.45 | 175.54 | 0 |
| ratings     | 27.42 | 33.15 | 175.67 | 0 |
| **TOTAL**   | **27.59** | **33.00** | **698.94** | **0** |

#### Table XIII: Scenario 2 Micro-benchmark Comparison
| Metric | Decentralized | Centralized | Difference |
| :--- | :---: | :---: | :---: |
| Avg Latency | 19.96 ms | 27.59 ms | **$-$28%** (Decentralized wins) |
| p95 Latency | 31.71 ms | 33.00 ms | **$-$4%** (Decentralized wins) |
| Throughput  | 936.19 rps | 698.94 rps | **+34%** (Decentralized wins) |
| Errors      | 0 | 0 | Tie |

---

### Tier B: Live End-to-End Traffic Mitigation Benchmark (20 Measured Trials)
*Evaluates full-system live DDoS defense across 20 measured trials with calibrated 125 RPS attack load and 24 RPS legitimate traffic.*

#### Table XIV: Runtime Routing Actions and Coordination Dynamics Under Live Parallel Attack
| Architecture | 4-Service Quaran. | Service Quaran. | Time to 1st Routing Action | OCC Retries | Decoy Hits (Att./Ben.) | Mean Recovery |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Decentralized** | **10/10 (100%)** | **40/40 (100%)** | 6.940 $\pm$ 1.513 s | 0 (1.00 att.) | **31,522 / 0** | 108.91 $\pm$ 6.66 s |
| **Centralized**   | 7/10 (70%)        | 37/40 (92.5%)     | 8.061 $\pm$ 3.467 s | 0 (1.00 att.) | 27,699 / 0          | 108.82 $\pm$ 7.09 s |

---

## 3. Representative Service-Level Detection and Mitigation Timelines

To illustrate the exact operational sequence and clarify the centralized misses, Table XV summarizes representative trial timelines across all four services.

#### Table XV: Representative Detection and Mitigation Timelines (Decentralized T1 vs. Centralized T1, T2, T3)
| Trial | Service | Attribution Path | 1st Routing Action | Quarantine Est. | Production Recovery |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Dec. T1** | productpage | BOTH (L7+RPS) | T+5.45 s | T+5.45 s | T+41.14 s |
| **Dec. T1** | details     | BOTH (L7+RPS) | T+8.45 s | T+8.45 s | T+128.85 s |
| **Dec. T1** | reviews     | BOTH (L7+RPS) | T+9.26 s | T+9.26 s | T+129.18 s |
| **Dec. T1** | ratings     | BOTH (L7+RPS) | T+5.75 s | T+5.75 s | T+126.02 s |
| **Cen. T1** | productpage | BOTH (L7+RPS) | T+8.50 s | T+8.50 s | T+44.58 s |
| **Cen. T1** | details     | RPS\_ONLY     | T+15.68 s | **None** (Failover only) | T+75.85 s |
| **Cen. T1** | reviews     | BOTH (L7+RPS) | T+15.68 s | T+15.68 s | T+136.17 s |
| **Cen. T1** | ratings     | BOTH (L7+RPS) | T+15.68 s | T+15.68 s | T+136.17 s |
| **Cen. T2** | details     | RPS\_ONLY     | T+3.76 s | **None** (Failover only) | T+63.89 s |
| **Cen. T3** | ratings     | RPS\_ONLY     | T+11.85 s | **None** (Failover only) | T+71.89 s |

*Note: In Cen. T1, T2, and T3, the controller executed fallback routing changes to $v_2/v_3$ but failed to insert the `quarantine-malicious` route, leaving the target service unquarantined.*

---

## 4. Legitimate Traffic Verification Summary

*Calculated across all 14,394 successful background HTTP requests using the nearest-observation percentile method (`numpy.percentile(..., method="nearest")`):*

| Metric | Decentralized (10 Trials) | Centralized (10 Trials) | Verification Status |
| :--- | :---: | :---: | :---: |
| **Total Requests** | 7,200 | 7,200 | 100% Audited |
| **Successful (HTTP 200)** | 7,196 (99.94%) | 7,198 (99.97%) | Verified |
| **Errors** | 4 | 2 | Verified |
| **Mean Latency** | 26.13 ms | 22.87 ms | Verified |
| **Median Latency (p50)** | **6.77 ms** | **4.55 ms** | **Corrected & Verified** |
| **95th Percentile (p95)** | **47.59 ms** | **55.87 ms** | **Verified (-14.82% Tail Reduction for Dec.)** |
| **99th Percentile (p99)** | **263.25 ms** | **234.30 ms** | **Corrected & Verified** |
| **Decoy Benign Hits** | **0 (0.00%)** | **0 (0.00%)** | **100% Clean Isolation Verified** |

---

## 5. Decoy Telemetry & Limitations

1. **Telemetry Collected:** Cumulative integer counter deltas recorded 31,522 attack requests captured across all four decoys under decentralized control versus 27,699 under centralized control, with zero benign requests diverted.
2. **Empirical Limitations:** The deployed decoy sinkhole handler (`update_decoy_deployments_yaml.py`) recorded an in-memory counter delta and maintained only a 100-entry sliding FIFO log buffer. Full disk-persisted sub-second arrival logs were not retained.
3. **Unaccounted Dispatched Requests:** Dispatched attack requests unaccounted for by decoy counters (5,858 in decentralized vs. 9,655 in centralized) reflect requests arriving prior to route propagation and generator drainage, and should be reported as unaccounted-for requests rather than assumed production hits.

---

## 6. Raw Evidence Archive Verification

The complete 91-file evidence archive is available at:
`C:\Users\mdbohos\Desktop\ddos_detector\PAPER\Backup\SCENARIO_2_BENCHMARK_RAW_EVIDENCE.zip`
- **SHA-256:** `bc838a0136b1400115a67a96a29cb9cf97ed1dec107399aadf61a8d18ad9fd50`
- **File Contents:**
  - `scenario2_final_benchmark_summary.json`
  - `decentralized_trial_1.json` to `10.json`
  - `centralized_trial_1.json` to `10.json`
  - `raw/benign_decentralized_trial_1.json` to `10.json` (7,200 raw request records)
  - `raw/benign_centralized_trial_1.json` to `10.json` (7,200 raw request records)
  - `raw/defender_*.log` (48 container `--timestamps` logs showing OCC commits and fencing tokens)
