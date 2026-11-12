# Scenario 5 — Synchronized Four-Service Concurrent DDoS Mitigation Pilot Report (Reconciled)

---

## 1. Executive Summary & Experimental Classification

This report provides the reconciled experimental evaluation of the **Scenario 5 Synchronized Four-Service Concurrent DDoS Mitigation Pilot** (`concurrent_pilot`), conducted across the complete Istio service mesh on 2026-11-06T02:10:30Z to 02:13:30Z.

### Experimental Assessment: PARTIAL PASS (76 / 77 Formal Assertions Passed)

The pilot provides strong empirical proof of decentralized mitigation across all four Bookinfo microservices (`productpage`, `details`, `reviews`, `ratings`) under concurrent multi-workload DDoS attacks at **160.190 aggregate attempted RPS** (159.652 successful-response RPS). All four decentralized controllers independently acquired leases, executed Optimistic Concurrency Control (OCC) commits without a single conflict, isolated attackers via decoy diversion, and autonomously recovered.

The trial status is recorded strictly as **PARTIAL PASS (76 / 77)** because assertion `productpage_benign_100_percent_success` did not achieve 100% (598 / 599 legitimate requests returned HTTP 200, achieving **99.833%** availability).

### Key Experimental Findings Matrix

| Scientific Dimension | Section G Target | Observed Experimental Value | Formal Assertion Result |
| :--- | :---: | :---: | :---: |
| **Simultaneous Attack Inception** | Shared $t_{\text{barrier}}$ | Max inter-service delta: **$+0.0002\text{ s}$** (0.2 ms) | **PASS** |
| **Offered Aggregate Attack Rate** | 160.000 RPS | **160.190 RPS** (2,230 / 2,230 attempted) | **PASS** |
| **Successful Response Attack Rate** | Baseline continuity | **159.652 RPS** (2,223 / 2,230 succeeded: 6 timeouts, 1 HTTP 503) | **PASS** |
| **Four Independent Mitigations** | 4 / 4 committed | **4 / 4 committed** (Internal OCC latency $\le 6.197\text{ s}$) | **PASS** |
| **Targeted Quarantine Isolation** | Attacker diverted to decoys | **100% targeted** (0 benign requests diverted to decoys) | **PASS** |
| **OCC Atomic Updates & Conflicts** | $\ge 1$ update, 0 unresolved | **10 atomic OCC updates OK, 0 OCC conflicts** | **PASS** |
| **Independent Fencing Tokens** | Monotonic tokens | Tokens **27, 46, 7, 26** ($Q$); **28, 48, 9, 27** ($S2$) | **PASS** |
| **Legitimate Traffic Continuity** | 100% across all services | **2,408 / 2,409 HTTP 200 (99.958%)** across all 4 services | **PARTIAL** (76/77) |
| **Two-Stage Autonomous Recovery** | Stage 1 + Stage 2 | All 4 services autonomously restored to $v_1=100\%$ | **PASS** |
| **Final Mesh Baseline** | Clean cluster baseline | **10 / 10 unheld Leases, 0 defender restarts, 4 VS at baseline** | **PASS** |

---

## 2. Multi-Workload Inception & Phase A Traffic Delivery

The four attack streams were synchronized to the shared VM timing barrier at $t_{\text{barrier}} = 1793931065.9749$.

### Phase A Workload Measurements

| Service | Target Route | Target RPS | Attempted RPS | Successful RPS | Planned Req | Attempted Req | Successful Req | Barrier Delta | Workload Duration |
| :--- | :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `productpage` | Gateway static route (`/static/img/izzy.png`) | 85.0 | **85.033** | **84.495** | 1,105 | 1,105 | 1,098 (6 timeout, 1 503) | $+0.0001\text{ s}$ | 12.995 s |
| `details` | East-West service (`details.default:9080`) | 25.0 | **25.049** | **25.049** | 375 | 375 | 375 (0 failed) | $+0.0001\text{ s}$ | 14.971 s |
| `reviews` | East-West service (`reviews.default:9080`) | 25.0 | **25.056** | **25.056** | 375 | 375 | 375 (0 failed) | $+0.0002\text{ s}$ | 14.967 s |
| `ratings` | East-West service (`ratings.default:9080`) | 25.0 | **25.052** | **25.052** | 375 | 375 | 375 (0 failed) | $+0.0002\text{ s}$ | 14.969 s |
| **Mesh Total** | — | **160.0** | **160.190** | **159.652** | **2,230** | **2,230** | **2,223** | **$\le 0.2\text{ ms}$** | — |

> [!NOTE]
> ML inference for all four services was driven by HMAC-SHA256 signed replay headers bearing representative CIC-DDoS2017 feature vectors, evaluated inside the defender containers against trained 7-feature Random Forest models. This mechanism guarantees deterministic, reproducible benchmark evaluation, distinguishing controlled dataset evaluation from passive real-time flow feature extraction.

---

## 3. Decentralized Detection, Mitigation Latencies & Resource Versions

The experiment validated complete decentralization: each defender independently detected the attack, acquired its service-specific mitigation lease, and committed its OCC update.

### Dual Latency & Resource Version Reconciliation

Both the controller-internal timestamps (from `[OCC-ATOMIC]` log records) and the coordinator's external polling timestamps are presented below:

| Service | Observed Attribution | Initial OCC Commit Latency (Internal) | Quarantine Commit Latency (Polled) | Initial Mitigation Resource Version | Fencing Token ($Q$) | Production Route During Phase A | Stage 2 Teardown Latency (Internal) | Stage 2 Teardown Latency (Polled) | Final Teardown Resource Version | Fencing Token ($S2$) |
| :--- | :---: | :-: | :-: | :-: | :-: | :--- | :-: | :-: | :-: | :-: |
| `productpage` | `ML_ONLY` | **2.502 s** | 2.393 s | **3075922** | 27 | `[('v1', 100)]` (preserved) | **11.804 s** | 12.106 s | 3085810 | 28 |
| `details` | `BOTH` | **2.534 s** | 2.393 s | **3071343** | 46 | `[('v2', 50), ('v3', 50)]` | **49.259 s** | 49.164 s | 3085901 | 48 |
| `reviews` | `BOTH` | **6.197 s** | 6.446 s | **3079688** | 7 | `[('v2', 50), ('v3', 50)]` | **52.734 s** | 53.047 s | 3085911 | 9 |
| `ratings` | `ML_ONLY` | **2.596 s** | 2.393 s | **3081889** | 26 | `[('v1', 100)]` (preserved) | **15.877 s** | 16.137 s | 3085811 | 27 |

### OCC Concurrency & Leader Election Audit
- **Total Lease Takeovers / Acquisitions:** 10
- **Total OCC Atomic Updates:** 10 (all succeeded on `attempt=1`)
- **OCC Conflicts Count:** **0**
- **Lock Contention / Deadlocks:** 0.

---

## 4. Phase B Active Decoy Interception

During Phase B, low-rate attacker probing (5.0 RPS target) was sustained to verify active decoy interception. All four decoy pods confirmed interception with zero legitimate leakage:

| Service | Decoy Target Pod | Initial Decoy Count | Final Decoy Count | Intercepted Attacker Req ($\Delta \ge 15$) | Measured Decoy RPS | Benign Leakage ($\Delta = 0$) | Attacker IP Verified (`10.244.0.131`) | Request IDs Verified |
| :--- | :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| `productpage` | `productpage-decoy` (8080) | 65,043 | 65,082 | **39** | 7.8 | **0** | **YES** | **YES** |
| `details` | `details-decoy` (8080) | 19,318 | 19,353 | **35** | 7.0 | **0** | **YES** | **YES** |
| `reviews` | `reviews-decoy` (9080) | 12,114 | 12,148 | **34** | 6.8 | **0** | **YES** | **YES** |
| `ratings` | `ratings-decoy` (9080) | 16,976 | 17,008 | **32** | 6.4 | **0** | **YES** | **YES** |

---

## 5. Legitimate Traffic Continuity & Benign Assertion Analysis

Continuous legitimate background traffic was generated across all four workloads throughout the entire ~3.5 minute experiment lifecycle:

| Service | Target Route | Total Sent | HTTP 200 Success | Success Rate | Served by Decoy | Formal Assertion Status |
| :--- | :--- | :-: | :-: | :-: | :-: | :---: |
| `details` | `details.default:9080` | 597 | 597 | **100.00%** | **0** | **PASS** |
| `reviews` | `reviews.default:9080` | 597 | 597 | **100.00%** | **0** | **PASS** |
| `ratings` | `ratings.default:9080` | 616 | 616 | **100.00%** | **0** | **PASS** |
| `productpage` | Gateway static route (`/static/img/izzy.png`) | 599 | 598 | **99.833%** | **0** | **FAIL** (Expected 100%) |
| **Mesh Aggregate** | — | **2,409** | **2,408** | **99.958%** | **0** | **76 / 77 PASS** |

### Rigorous Analysis of the Single Benign Drop
- **Recorded Evidence:** 598 out of 599 legitimate requests to `productpage` returned HTTP 200 with 0 decoy leakage. Exactly 1 request did not return HTTP 200.
- **Evidence Limitation:** In the `concurrent_pilot` package, benign traffic was captured as summary statistics (`total_sent`, `success_200`, `served_by_decoy`); the individual per-request timestamps, status codes, and network error messages were not persisted to disk. Consequently, assigning an unverified cause (such as pre-quarantine congestion) is scientifically ungrounded.
- **Harness Enhancement:** The runner coordinator has been upgraded to permanently archive the full per-request JSONL logs (`trial_{trial_id}_benign_{svc}.jsonl`) and structure any non-200 records directly within the evidence JSON for all future trials.

---

## 6. Post-Trial Cluster Baseline Audit

Immediately following trial completion, an independent audit verified full cluster restoration:

| Audit Check | Expected Value | Observed Post-Trial Value | Result |
| :--- | :---: | :---: | :---: |
| **Lease Namespace Baseline** | Exactly 10 unheld Leases | 10 Leases present in `default`, 0 held | **PASS** |
| **Defender Pod Restarts** | 0 restarts across all pods | `details`: 0, `product`: 0, `reviews`: 0, `ratings`: 0 | **PASS** |
| **VirtualService Rules Count** | Exactly 1 rule per VS | `bookinfo`: 1, `details`: 1, `reviews`: 1, `ratings`: 1 | **PASS** |
| **VirtualService Quarantine** | `quarantine_present == False` | All 4 services have 0 quarantine rules | **PASS** |
| **VirtualService Production Route** | $v_1=100\%$ | All 4 services routed to `[('v1', 100)]` | **PASS** |
| **Orphan Client Processes** | 0 processes on attacker/benign pods | 0 `s5c_` processes running | **PASS** |

---

## 7. Artifact Manifest & Exact Checksums

The raw evidence package is archived in [`SCENARIO_5_CONCURRENT_PILOT_PACKAGE.zip`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/Backup/SCENARIO_5_CONCURRENT_PILOT_PACKAGE.zip):

| Filename | Size (Bytes) | SHA-256 Checksum |
| :--- | :-: | :--- |
| `trial_concurrent_pilot_concurrent_autonomous.json` | 857,019 | `6aed1e7966a51313681f00753d8af582bec79d105d240a281da1dae0ffba0586` |
| `controller_trace_trial_concurrent_pilot_productpage.log` | 18,309 | `f8d5e1592f7f1b81c9dc0678640a4c92548c04a847680ad0da68b39e6aaee3c3` |
| `controller_trace_trial_concurrent_pilot_details.log` | 22,068 | `838f6f1a975c4f71d803c22acc01379a5dcc4fdc20ae09a6008269af743b47d9` |
| `controller_trace_trial_concurrent_pilot_reviews.log` | 21,367 | `a5822f593a557c94ca0a412cbd0848e6f80bea552e0f8163649ee131c1ac6b9a` |
| `controller_trace_trial_concurrent_pilot_ratings.log` | 36,264 | `e80a4c7a802a15c0282f03015003494f921e10647076d38fb4c194abb3569843` |
| **ZIP Archive (`SCENARIO_5_CONCURRENT_PILOT_PACKAGE.zip`)** | **109,128** | **`269db8d969ecae973edd120228167c03a31e716b99c76ab15f72a7213812418e`** |
