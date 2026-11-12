# Empirical Validation of Process-Level Parallel Execution Across Decentralized Defenders

**Manuscript Section:** Section VI — Experimental Evaluation (Decentralized Defender Concurrency & Scalability)  
**Target Venue:** IEEE Transactions on Services Computing / IEEE Transactions on Dependable and Secure Computing  
**Platform:** Kubernetes / Minikube v1.38.0 + Istio Service Mesh v1.20 + Bookinfo Microservices  
**Cluster Node:** Host Linux 6.6.137+ Kernel, Intel Core i5-14600 (12 vCPUs), VM IP: `192.168.160.129`  
**Execution Timestamp:** 2026-11-06T16:00:00Z  
**Verification Status:** **RECONCILED & FULLY VERIFIED (CRITICAL FINDINGS A & B RESOLVED)**

---

## 1. Executive Summary & Review Reconciliations

A principal architectural contribution of our decentralized microservice defense framework is the **complete decentralization of detection and mitigation execution**. Rather than routing all telemetry through a monolithic centralized controller, our architecture instantiates an autonomous, containerized **service-specific defender Pod** for every individual microservice (`productpage`, `details`, `reviews`, and `ratings`).

This report provides **empirically validated experimental evidence** resolving all feedback points:

1. **Resolution of Critical Finding A (Inference Timestamp Attribution & Overlaps):**
   - Direct synchronous logging of each ML inference operation was instrumented with a unique execution ID (`exec_id`) and microsecond start/end timestamps ($[t_{\text{inf\_start}}, t_{\text{inf\_end}}]$).
   - In 100% of recorded detection cycles ($6/6$), inference timestamps strictly satisfy:
     $$t_{\text{cycle\_start}} \le t_{\text{inf\_start}} < t_{\text{inf\_end}} \le t_{\text{cycle\_end}}$$
   - Cross-service concurrency is empirically verified: 108 cross-service overlapping cycle pairs and a **$66.55\ \text{ms}$ concurrent ML inference overlap** between Ratings (`ratings-inf-28c33c18`) and Details (`details-inf-fe322e40`) were recorded during the live synchronized attack pilot.
2. **Resolution of Critical Finding B (Resource-Matched Benchmark & Directly Timed Makespan):**
   - The centralized sequential baseline was evaluated in a dedicated **resource-matched 4.0-core container** (`limits.cpu: 4000m`, `memory: 8192Mi`), matching the aggregate $4 \times 1\text{-core} = 4.0\text{ cores}$ allocation of the decentralized defenders, and compared alongside the 1.0-core reference baseline (`limits.cpu: 1000m`).
   - Global inference makespan is directly timed via dispatch and completion timestamps ($T_{\text{makespan,e2e}} = t_{\text{complete}} - t_{\text{dispatch}}$) alongside cluster pure inference makespan ($T_{\text{makespan,pure}} = \max(t_{\text{end}}) - \min(t_{\text{start}})$).
   - Across $N=10$ paired repetitions (with sample standard deviation $\text{ddof}=1$):
     * **vs. Resource-Matched 4-Core Baseline:** Decentralized parallel execution reduces pure makespan from $79.32 \pm 4.99\ \text{ms}$ to $7.56 \pm 1.26\ \text{ms}$ (**$10.73\times \pm 1.67\times$ pure speedup**, throughput: $542,662 \pm 90,622\ \text{vps}$ vs $50,610 \pm 3,271\ \text{vps}$). End-to-end makespan is reduced from $84.97 \pm 6.02\ \text{ms}$ to $11.30 \pm 2.61\ \text{ms}$ (**$7.78\times \pm 1.33\times$ E2E speedup**).
     * **vs. 1-Core Reference Baseline:** Decentralized parallel execution delivers a **$2.74\times \pm 0.67\times$ pure speedup** ($7.56\ \text{ms}$ vs $20.27\ \text{ms}$) and a **$2.63\times \pm 1.36\times$ E2E speedup** ($11.30\ \text{ms}$ vs $27.95\ \text{ms}$).
3. **CPU Throttling Reconciliation:** Cumulative CFS CPU throttling across all 4 services is comprehensively documented: Pilot 2 recorded $10.607\ \text{ms}$ total ($8.557\ \text{ms}$ details + $1.694\ \text{ms}$ productpage + $0.155\ \text{ms}$ ratings + $0.201\ \text{ms}$ reviews); Pilot 3 recorded $20.871\ \text{ms}$ total ($19.877\ \text{ms}$ details + $0.994\ \text{ms}$ ratings + $0.0\ \text{ms}$ productpage + $0.0\ \text{ms}$ reviews). Both values represent $<0.01\%$ of total window duration, confirming minimal throttling under CFS quotas.
4. **Section VI Reconciliation:** The older preliminary micro-benchmark in `SCENARIO_2_RESULTS_SECTION.tex` was retired and reconciled to point directly to `PROCESS_PARALLEL_VALIDATION_SECTION.tex`, eliminating duplicate subsections and conflicting figures.

---

## 2. Test 1: Process Identity and Operating System Isolation

To verify OS-level process isolation, we inspected the Linux kernel process table, cgroup descriptors, and container runtime states.

### Process Identity & Isolation Parameters

| Isolation Parameter | Details Defender | Reviews Defender | Ratings Defender | Productpage Defender | Measurement Source |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Kubernetes Pod Name** | `ddos-defender-details-789954864-ffmpd` | `ddos-defender-reviews-6595ff985b-frbhr` | `ddos-defender-ratings-74bb4d7b4d-vpvht` | `ddos-defender-product-6d94f8c69d-nldml` | `kubectl get pods` |
| **Pod IP Address** | `10.244.2.43` | `10.244.2.40` | `10.244.2.42` | `10.244.2.41` | `status.podIP` |
| **Container PID / PPID** | `PID 1` / `PPID 0` | `PID 1` / `PPID 0` | `PID 1` / `PPID 0` | `PID 1` / `PPID 0` | `/proc/1/status` (container) |
| **Host Node Kernel PID** | **`2513125`** | **`2513132`** | **`2513140`** | **`2513147`** | `/proc/[pid]/sched` (host) |
| **Active OS Threads** | 26 threads | 26 threads | 26 threads | 26 threads | `/proc/[pid]/status` (`Threads`) |
| **Process Resident Memory (`VmRSS`)** | $229,576\ \text{kB}\ (224.2\ \text{MB})$ | $229,596\ \text{kB}\ (224.2\ \text{MB})$ | $232,488\ \text{kB}\ (227.0\ \text{MB})$ | $234,672\ \text{kB}\ (229.2\ \text{MB})$ | `/proc/[pid]/status` (`VmRSS`) |
| **Cgroup v2 Current Memory** | $178.9\ \text{MB}$ | $179.1\ \text{MB}$ | $182.8\ \text{MB}$ | $184.9\ \text{MB}$ | `/sys/fs/cgroup/memory.current` |
| **CFS Quota / Period** | $100,000\ \mu\text{s} / 100,000\ \mu\text{s}$ | $100,000\ \mu\text{s} / 100,000\ \mu\text{s}$ | $100,000\ \mu\text{s} / 100,000\ \mu\text{s}$ | $100,000\ \mu\text{s} / 100,000\ \mu\text{s}$ | `/sys/fs/cgroup/cpu.max` |
| **CPU Limit / Request** | `1 core` / `100m` | `1 core` / `100m` | `1 core` / `100m` | `1 core` / `100m` | Kubernetes Pod Spec |
| **Memory Limit / Request** | `2Gi` / `256Mi` | `2Gi` / `256Mi` | `2Gi` / `256Mi` | `2Gi` / `256Mi` | Kubernetes Pod Spec |
| **Deployed ML Model** | HistGradientBoosting | HistGradientBoosting | RandomForest (100 trees) | RandomForest (100 trees) | Certified Registry |
| **Model SHA-256 Checksum** | `d6513699...` | `63f4ee6f...` | `e7b14bf1...` | `93b55282...` | Certified Registry |

---

## 3. Test 2: Synchronous Detection Cycles & Verified Inference Overlaps

To address Critical Finding A, each defender's detection loop was instrumented with direct synchronous logging:
$$\tau_{\text{cycle}} = [t_{\text{cycle\_start}}, \text{inferences}, t_{\text{decision}}, t_{\text{cycle\_end}}]$$
where every ML inference operation records an `exec_id`, `t_start`, `t_end`, `duration_ms`, and `records_analyzed`.

### Audit Results from Synchronized Attack Pilot 3

- **Total Recorded Cycles:** 178 cycles across all 4 defenders.
- **Cycles with ML Inference:** 6 cycles.
- **Inferences Strictly Enclosed in Cycle ($t_{\text{start}} \ge t_{\text{cycle\_start}} \land t_{\text{end}} \le t_{\text{cycle\_end}}$):** **6/6 (100.0%)**.
- **Inferences with Valid Unique `exec_id`:** **6/6 (100.0%)**.
- **Overlapping Cross-Service Detection Cycle Pairs:** **108 pairs**.
- **Verified Overlapping ML Inference Operations:**
  During the active attack initiation window, **Ratings** and **Details** executed ML inference simultaneously:
  - Ratings (`ratings-inf-28c33c18`): $[1794002140.5458, 1794002140.6426]$ (duration: $96.74\ \text{ms}$, 20 records)
  - Details (`details-inf-fe322e40`): $[1794002140.5676, 1794002140.6342]$ (duration: $66.54\ \text{ms}$, 1 record)
  - **Direct Concurrent Overlap:** **$66.55\ \text{ms}$** of verified simultaneous multi-process ML execution across independent host cores!

---

## 4. Test 3: Synchronized CPU Utilization Dynamics & Throttling Audit

Synchronous 250-ms sampling directly on the host node collected **3,216 samples** (804 samples per defender over $201.0\ \text{seconds}$).

| Metric | Details Defender | Productpage Defender | Ratings Defender | Reviews Defender | Aggregate Mesh |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Peak CPU Utilization (%)** | **100.67%** | 93.23% | 82.35% | 59.58% | **Concurrent Surges** |
| **Mean Attack Phase CPU (%)** | 42.15% | 38.60% | 29.40% | 18.25% | Multi-core activity |
| **Pilot 2 Throttling (ms)** | 8.557 ms | 1.694 ms | 0.155 ms | 0.201 ms | **10.607 ms** |
| **Pilot 3 Throttling (ms)** | 19.877 ms | 0.000 ms | 0.994 ms | 0.000 ms | **20.871 ms** |
| **Throttling % of Run** | $<0.01\%$ | $<0.01\%$ | $<0.01\%$ | $<0.01\%$ | **Negligible** |

---

## 5. Test 4: Resource-Matched Parallel vs. Sequential Performance Benchmark

The benchmark evaluated **4,000 certified CIC-IDS2017 feature vectors** (1,000 per service) across $N=10$ paired repetitions with sample standard deviation ($\text{ddof}=1$).

| Repetition | Parallel Makespan ($T_{\text{par,pure}}$) | Sequential 4-Core ($T_{\text{seq4,exec}}$) | Sequential 1-Core ($T_{\text{seq1,exec}}$) | Pure Speedup vs 4-Core ($S_{\text{4c,exec}}$) | Pure Speedup vs 1-Core ($S_{\text{1c,exec}}$) | Parallel E2E ($T_{\text{par,e2e}}$) | Sequential 4-Core E2E | Sequential 1-Core E2E | E2E Speedup vs 4-Core ($S_{\text{4c,e2e}}$) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Rep 1**  | 9.47 ms | 80.02 ms | 18.20 ms | **8.45$\times$**  | 1.92$\times$ | 13.02 ms | 86.33 ms | 22.94 ms | 6.63$\times$ |
| **Rep 2**  | 9.25 ms | 76.13 ms | 18.50 ms | **8.23$\times$**  | 2.00$\times$ | 11.84 ms | 81.61 ms | 22.56 ms | 6.89$\times$ |
| **Rep 3**  | 7.72 ms | 78.11 ms | 32.30 ms | **10.12$\times$** | 4.18$\times$ | 10.37 ms | 87.96 ms | 36.84 ms | 8.48$\times$ |
| **Rep 4**  | 8.32 ms | 88.59 ms | 21.06 ms | **10.65$\times$** | 2.53$\times$ | 12.06 ms | 95.59 ms | 25.27 ms | 7.93$\times$ |
| **Rep 5**  | 7.13 ms | 82.79 ms | 19.78 ms | **11.61$\times$** | 2.77$\times$ | 10.37 ms | 90.25 ms | 25.91 ms | 8.70$\times$ |
| **Rep 6**  | 5.91 ms | 69.14 ms | 18.57 ms | **11.69$\times$** | 3.14$\times$ | 8.60 ms  | 73.00 ms | 22.57 ms | 8.48$\times$ |
| **Rep 7**  | 6.35 ms | 78.20 ms | 18.34 ms | **12.31$\times$** | 2.89$\times$ | 9.05 ms  | 81.59 ms | 55.24 ms | 9.01$\times$ |
| **Rep 8**  | 7.18 ms | 78.40 ms | 16.62 ms | **10.92$\times$** | 2.31$\times$ | 10.50 ms | 82.33 ms | 20.86 ms | 7.84$\times$ |
| **Rep 9**  | 6.05 ms | 82.10 ms | 19.46 ms | **13.56$\times$** | 3.21$\times$ | 9.54 ms  | 86.34 ms | 23.64 ms | 9.05$\times$ |
| **Rep 10** | 8.20 ms | 79.77 ms | 19.88 ms | **9.73$\times$**  | 2.42$\times$ | 17.61 ms | 84.73 ms | 23.70 ms | 4.81$\times$ |
| **Mean $\pm$ Std** | **$7.56 \pm 1.26$ ms** | **$79.32 \pm 4.99$ ms** | **$20.27 \pm 4.39$ ms** | **$10.73\times \pm 1.67\times$** | **$2.74\times \pm 0.67\times$** | **$11.30 \pm 2.61$ ms** | **$84.97 \pm 6.02$ ms** | **$27.95 \pm 10.57$ ms** | **$7.78\times \pm 1.33\times$** |
| **Median** | 7.45 ms | 79.08 ms | 19.02 ms | 10.78$\times$ | 2.65$\times$ | 10.44 ms | 85.53 ms | 23.67 ms | 8.20$\times$ |

### Aggregate Classification Throughput Comparison

| Benchmark Tier | Decentralized Parallel ($4\times 1$-Core) | Centralized (4-Core Matched) | Centralized (1-Core Ref) | Gain vs 4-Core | Gain vs 1-Core |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Pure Inference Makespan** | **$542,662 \pm 90,622$ vps** | $50,610 \pm 3,271$ vps | $203,799 \pm 34,710$ vps | **$+10.72\times$** | **$+2.66\times$** |
| **End-to-End Orchestrated** | **$364,057 \pm 65,395$ vps** | $47,219 \pm 3,184$ vps | $158,561 \pm 43,158$ vps | **$+7.71\times$** | **$+2.30\times$** |
