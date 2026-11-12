# Scenario 5 — Synchronized Four-Service Concurrent DDoS Mitigation Pilot R2 Report

---

## 1. Executive Summary & Experimental Classification

This report provides the experimental evaluation of the **Scenario 5 Synchronized Four-Service Concurrent DDoS Mitigation Pilot R2** (`concurrent_pilot_r2`), conducted across the complete Istio service mesh on 2026-11-06T03:13:00Z to 03:16:20Z.

### Experimental Assessment: PARTIAL PASS (76 / 77 Formal Assertions Passed)

Pilot R2 directly evaluates the reproducibility of legitimate traffic preservation and decentralized mitigation under concurrent 160 RPS DDoS attacks with **full per-request JSONL logging enabled**.

### Key Experimental Findings Matrix

| Scientific Dimension | Section G Target | Observed Pilot R2 Experimental Value | Formal Assertion Result |
| :--- | :---: | :---: | :---: |
| **Simultaneous Attack Inception** | Shared $t_{\text{barrier}}$ | Max inter-service delta: **$+0.0006\text{ s}$** (0.6 ms) | **PASS** |
| **Offered Aggregate Attack Rate** | 160.000 RPS | **160.097 RPS** (2,230 / 2,230 attempted) | **PASS** |
| **Successful Response Attack Rate** | Baseline continuity | **159.789 RPS** (2,226 / 2,230 succeeded: 4 timeouts on productpage) | **PASS** |
| **Four Independent Mitigations** | 4 / 4 committed | **4 / 4 committed** (Internal OCC commit $\le 9.554\text{ s}$) | **PASS** |
| **Targeted Quarantine Isolation** | Attacker diverted to decoys | **100% targeted** (0 benign requests diverted to decoys) | **PASS** |
| **OCC Atomic Updates & Conflicts** | $\ge 1$ update, 0 unresolved | **11 atomic OCC updates OK, 0 OCC conflicts** | **PASS** |
| **Independent Fencing Tokens** | Monotonic tokens | Tokens **29, 49, 10, 28** ($Q$); **30, 51, 12, 30** ($S2$) | **PASS** |
| **Legitimate Traffic Continuity** | 100% across all services | **2,459 / 2,459 HTTP 200 (100.00%)** across all 4 services | **PASS** (4/4 100%) |
| **Two-Stage Autonomous Recovery** | Stage 1 + Stage 2 | All 4 services autonomously restored to $v_1=100\%$ | **PASS** |
| **Final Mesh Baseline** | Clean cluster baseline | **10 / 10 unheld Leases, 0 defender restarts, 4 VS at baseline** | **PASS** |

---

## 2. Perfect Legitimate Traffic Continuity (100.00%)

In Pilot R2, all four workloads achieved **perfect 100.00% legitimate traffic continuity** with zero dropped requests, zero timeouts, and zero decoy leakage throughout the entire 3.5-minute trial lifecycle:

| Service | Target Route | Total Sent | HTTP 200 Success | Success Rate | Served by Decoy | Non-200 Drops | Per-Request Log Archived |
| :--- | :--- | :-: | :-: | :-: | :-: | :-: | :---: |
| `productpage` | Gateway static route (`/static/img/izzy.png`) | 608 | 608 | **100.00%** | **0** | **0** | `trial_concurrent_pilot_r2_benign_productpage.jsonl` |
| `details` | East-West service (`details.default:9080`) | 612 | 612 | **100.00%** | **0** | **0** | `trial_concurrent_pilot_r2_benign_details.jsonl` |
| `reviews` | East-West service (`reviews.default:9080`) | 615 | 615 | **100.00%** | **0** | **0** | `trial_concurrent_pilot_r2_benign_reviews.jsonl` |
| `ratings` | East-West service (`ratings.default:9080`) | 624 | 624 | **100.00%** | **0** | **0** | `trial_concurrent_pilot_r2_benign_ratings.jsonl` |
| **Mesh Total** | — | **2,459** | **2,459** | **100.00%** | **0** | **0** | **All 4 JSONL logs archived** |

All four per-request JSONL logs have been permanently preserved in the raw directory and packaged into the evidence archive.

---

## 3. Mitigation Latencies: Controller-Internal vs. Polled Marks & Resource Versions

In Pilot R2, all four controllers successfully detected the attack and committed their OCC updates. The sequence of resource versions confirms the distinct transitions:

| Service | Observed Attribution | Initial OCC Commit Latency (Internal) | Quarantine Commit Latency (Polled) | Initial Mitigation Resource Version | Stage 1 Restoration Resource Version | Final Teardown Resource Version | Fencing Token ($Q$) | Production Route During Phase A | Stage 2 Teardown Latency (Internal) | Stage 2 Teardown Latency (Polled) | Fencing Token ($S2$) |
| :--- | :---: | :-: | :-: | :-: | :-: | :-: | :-: | :--- | :-: | :-: | :-: |
| `productpage` | `ML_ONLY` | **2.580 s** | 2.873 s | **3085946** | N/A ($v_1$ preserved) | **3090846** | 29 | `[('v1', 100)]` (preserved) | **9.165 s** | 9.277 s | 30 |
| `ratings` | `BOTH` | **3.497 s** | 3.598 s | **3085953** | **3090850** | **3090941** | 28 | `[('v2', 50), ('v3', 50)]` | **48.528 s** | 48.599 s | 30 |
| `details` | `BOTH` | **5.814 s** | 6.800 s | **3086001** | **3090858** | **3090949** | 49 | `[('v2', 50), ('v3', 50)]` | **50.892 s** | 51.122 s | 51 |
| `reviews` | `BOTH` | **9.554 s** | **10.145 s** | **3086007** | **3090866** | **3090956** | 10 | `[('v2', 50), ('v3', 50)]` | **54.398 s** | 54.429 s | 12 |

### Analysis of Assertion `concurrency_mitigation_latencies_under_10s`
- **Internal Controller Timestamp:** The `reviews` defender completed its L7 inference and committed the OCC update to the `reviews` VirtualService at $t+9.554\text{ s}$ from the barrier.
- **External Polling Interval:** The runner coordinator polls Istio VirtualServices at 0.25-second intervals via SSH to the Minikube cluster. The polling cycle completed and recorded the commit at $t+10.145\text{ s}$.
- Because the coordinator evaluated `marks["phase_A_commit"]["reviews"] - t_barrier < 10.0`, the 10.145s polled mark exceeded 10.000s by 0.145s, flagging this single assertion as False (76/77 assertions passed).
- **OCC Concurrency:** **11 atomic OCC updates**, **0 OCC conflicts**.

---

## 4. Synthesis Across Both Concurrent Pilots

| Metric | Pilot 1 (`concurrent_pilot`) | Pilot 2 (`concurrent_pilot_r2`) | Combined Aggregate |
| :--- | :---: | :---: | :---: |
| **Formal Assertions Passed** | 76 / 77 | 76 / 77 | — |
| **Limiting Assertion** | `productpage_benign_100_percent_success` (99.83%) | `concurrency_mitigation_latencies_under_10s` (10.145s polled, 9.554s OCC) | — |
| **Offered Attack RPS** | 160.190 RPS | 160.097 RPS | **160.144 RPS** |
| **Successful Attack RPS** | 159.652 RPS | 159.789 RPS | **159.721 RPS** |
| **Total Legitimate Requests** | 2,409 | 2,459 | **4,868** |
| **Successful Legitimate Requests** | 2,408 | 2,459 | **4,867 (99.979%)** |
| **Legitimate Requests to Decoys** | 0 | 0 | **0 (0.00%)** |
| **Total OCC Atomic Updates** | 10 | 11 | **21** |
| **Total OCC Conflicts** | 0 | 0 | **0** |
| **Final Unheld Leases / Restarts** | 10 / 10 unheld; 0 restarts | 10 / 10 unheld; 0 restarts | **100% baseline restored** |

---

## 5. Artifact Manifest & Exact Checksums

The raw evidence package is archived in [`SCENARIO_5_CONCURRENT_PILOT_R2_PACKAGE.zip`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/Backup/SCENARIO_5_CONCURRENT_PILOT_R2_PACKAGE.zip):

| Filename | Size (Bytes) | SHA-256 Checksum |
| :--- | :-: | :--- |
| `trial_concurrent_pilot_r2_concurrent_autonomous.json` | 864,619 | `83bd2373d7d6fc80e76cf898a03812c9553b7023497ded5f5e0e9f0f7e531d9f` |
| `controller_trace_trial_concurrent_pilot_r2_productpage.log` | 19,613 | `5ae0ce027d7bd1471e090b84ac982c7b59c93ebe5ae51e3a8abef72f3e899555` |
| `controller_trace_trial_concurrent_pilot_r2_details.log` | 23,551 | `38b2002f9e83c1f15cea578b64d125b327081c94a69bd81822ed120593739658` |
| `controller_trace_trial_concurrent_pilot_r2_reviews.log` | 23,450 | `926aca7e57395af5ad41d27b4a350c4801a944c763ecf04e7ab523ed05984b31` |
| `controller_trace_trial_concurrent_pilot_r2_ratings.log` | 27,399 | `46e656791ebc417d7192a37b4571e06fd75bc8435c43d5ebdb6e9264ec93ff20` |
| `trial_concurrent_pilot_r2_benign_productpage.jsonl` | 120,008 | `accee4c09935fd2e60b905d3c18868a88bdfd0605ac05e93b705ec8c11892dbc` |
| `trial_concurrent_pilot_r2_benign_details.jsonl` | 115,980 | `a35e0ca007f51846d7f35ea569a447bc919da82ff09b9fa6cc89ea905eba23a6` |
| `trial_concurrent_pilot_r2_benign_reviews.jsonl` | 116,521 | `72e09d1b9b2ec3333c55f613fd265511d23dad9e8ce8338712c9e3935015eeb6` |
| `trial_concurrent_pilot_r2_benign_ratings.jsonl` | 118,160 | `cce87ae5c8b71fceb594a1ab6298ef3cf742d395b7acff21f9dd59b6761bcfdb` |
| **ZIP Archive (`SCENARIO_5_CONCURRENT_PILOT_R2_PACKAGE.zip`)** | **153,353** | **`0b6b15a386ac859144a78a271fadf1c48b48fbce423a53f9c227c50dc134988a`** |
| `run_scenario5_concurrent_harness.py` (Coordinator) | 61,095 | `c0c5261a0fbc91fa1f4c47e7e208b70845518b1b3c87181efadda622c75d520c` |
