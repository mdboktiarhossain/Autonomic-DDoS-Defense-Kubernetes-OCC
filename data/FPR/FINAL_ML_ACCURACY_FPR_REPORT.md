# Comprehensive Verification Report: ML Detection Accuracy & False-Positive Analysis

**Document ID:** `FINAL_ML_ACCURACY_FPR_REPORT.md`  
**Location:** `PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/FINAL_ML_ACCURACY_FPR_REPORT.md`  
**Companion LaTeX Source:** [`FINAL_ML_ACCURACY_FPR_MANUSCRIPT.tex`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/FINAL_ML_ACCURACY_FPR_MANUSCRIPT.tex)  
**Date:** November 3, 2026  
**Status:** Certified Active Enforcement Baseline (`cic-v5.3`, `shadow_mode=false`)  

---

## 1. Executive Summary

This verification package provides the complete, publication-grade empirical evidence supporting the **Machine Learning Detection Accuracy and False-Positive Analysis** section of our research manuscript. 

Every reported metric in this document is backed by raw prediction files, dataset manifests, container cryptographic checksums, and live Kubernetes snapshots preserved in [`PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/).

### Summary of Certified Empirical Findings:
1. **Dataset Integrity & Zero Leakage:** The $43,166$-flow Wednesday calibration corpus (*DistriNet CNS 2022 Corrected Edition of CIC-IDS2017*) was partitioned strictly by `Flow ID` via `GroupShuffleSplit` (80% train / 20% test). An exhaustive audit verified **$0$ overlapping Flow IDs** between the training partition ($34,682$ flows) and the held-out test partition ($8,484$ flows). `StandardScaler` was fitted strictly on training data.
2. **In-Distribution Accuracy ($N = 8,484$):** Evaluated on the held-out Wednesday test partition ($5,468$ attack flows, $3,016$ benign flows), the four service-specialized models achieved:
   - `productpage` (`RandomForestClassifier`, $T=0.70$): **$99.99\%$** Accuracy, **$0.00\%$** FPR ($[0.00\%, 0.13\%]$).
   - `details` (`HistGradientBoostingClassifier`, $T=0.80$): **$99.99\%$** Accuracy, **$0.03\%$** FPR ($[0.01\%, 0.19\%]$).
   - `reviews` (`HistGradientBoostingClassifier`, $T=0.70$): **$100.00\%$** Accuracy, **$0.00\%$** FPR ($[0.00\%, 0.13\%]$).
   - `ratings` (`RandomForestClassifier`, $T=0.70$): **$100.00\%$** Accuracy, **$0.00\%$** FPR ($[0.00\%, 0.13\%]$).
3. **Out-of-Distribution Generalization ($N = 87,886$):** Evaluated against independent multi-day traffic from Monday and Friday:
   - Unseen LOIC DDoS attacks ($N = 20,000$): Detection recall exceeds **$99.70\%$** across all four services ($99.70\%$ to $99.97\%$).
   - Large-scale benign background ($N = 67,886$ across Monday and Friday): Combined empirical FPR is strictly $\le \mathbf{0.19\%}$ ($0.12\%$ to $0.19\%$).
   - **Cross-Day Flow-ID Audit:** 792 5-tuple identifier strings recur between Wednesday and Friday LOIC due to testbed ephemeral port reuse (attacker IP `172.16.0.1` targeting server IP `192.168.10.50:80`). A cryptographic audit confirmed **$0$ overlapping feature hashes** ($0.00\%$ overlap) and a 48-hour timestamp separation, confirming zero feature leakage.
4. **Live Kubernetes Benign Safety ($N = 400$):**
   - **Workload Confirmation:** All $400$ requests ($100$ per microservice) completed with HTTP $200$ OK and were recorded in Envoy access logs.
   - **Live Daemon Scrape-Window Inferences:** In-pod daemons logged $11$ discrete window-level ML inference evaluations ($6$ on `productpage`, $2$ on `details`, $2$ on `reviews`, $1$ on `ratings`). All $11$ evaluated as **NORMAL**. Zero attack alerts were triggered, zero Kubernetes Leases were acquired, and zero VirtualServices were modified.
   - **Request-ID-Level Matching:** Matching all $400$ unique Request IDs from Envoy logs against the frozen model pipelines confirmed **$0 / 400$ false positives ($0.00\%$ live FPR)** with a mean anomaly probability of $0.0049$ and maximum probability of $0.6200$ (well below operating tripwires of $0.70$ and $0.80$).
5. **Historical Log Residue Resolved:** Forensic timestamp analysis proved that the 6 apparent alerts in earlier diagnostics were residual lines from an adversarial test executed 60 seconds prior within the same container session ($23:42:50\text{ UTC}$ vs $23:44:10\text{ UTC}$).
6. **Authentication Token Redaction:** All benchmark authentication tokens in logs and traces have been sanitized to `<REDACTED_BENCH_AUTH_TOKEN>`.

---

## 2. Task 1: Verified Dataset & Deployed Model Configuration

### 2.1 Dataset Provenance & Calibration Corpus
- **Dataset Source:** DistriNet CNS 2022 Corrected Edition of CIC-IDS2017 (`CICIDS2017_improved.zip`, SHA-256: `97fdb91d339e2d8cf5627f981b831e5e7e400b981c58181c451a38fd03c48883`).
- **Data Filtering:** Cleaned by discarding unattempted records (`Attempted Category == -1`) and zero-duration records (`Flow Duration > 0`).
- **Wednesday Calibration Corpus ($N = 43,166$):**
  - DoS Hulk: $15,000$ flows
  - DoS GoldenEye: $7,567$ flows
  - DoS Slowloris: $3,859$ flows
  - DoS Slowhttptest: $1,740$ flows
  - Port 80 Benign: $15,000$ flows
  - Total Attacks: $28,166$ flows ($65.25\%$) | Total Benign: $15,000$ flows ($34.75\%$)
  - Total Unique Flow IDs: $27,141$

### 2.2 Leakage-Free Partitioning & Underlying Hash Audit
Partitioned via `GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)` grouped by `Flow ID`:
- **Training Partition:** $34,682$ flows ($21,712$ unique Flow IDs)
- **Held-Out Test Partition:** $8,484$ flows ($5,429$ unique Flow IDs; $5,468$ attack, $3,016$ benign)
- **Flow ID Overlap Audit:** $\text{Shared Flow IDs} = \mathbf{0}$.
- **Feature Hash Audit:** The training partition has $34,271$ unique feature hashes; the test partition has $8,433$ unique feature hashes. Exactly $84$ feature hashes recur across different Flow IDs due to the repetitive keep-alive mechanics of Slowloris (e.g., 2 forward packets, 0 backward packets, ACK count = 2) initiated from different client sockets.
- **Scaling Preprocessing:** `StandardScaler` was fitted strictly on the training partition ($34,682$ flows). Test features were transformed using the frozen training parameters (`mean_`, `scale_`).
- **Manifests:** Serialized in [`dataset_calibration_split_manifest.json`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/dataset_calibration_split_manifest.json) and [`dataset_leakage_and_hash_audit.json`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/dataset_leakage_and_hash_audit.json).

### 2.3 Deployed Model Manifest & Checksums
All models are serialized within self-contained `.joblib` bundles inside container image `boktiar/ddos-defender:cic-v5.3`:

| Microservice | Architecture | Threshold ($T$) | Hyperparameters | Input Features (7) | Bundle SHA-256 Checksum |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **`productpage`** | `RandomForestClassifier` | $0.70$ | `n_estimators=100`, `max_depth=15`, `random_state=42` | Flow Packets/s, Total Fwd Packet, Total Length of Fwd Packet, Fwd Packet Length Mean, ACK Flag Count, PSH Flag Count, Packet Length Variance | `93b55282b0d392f049ada29054749646c7ffbc9a6bfe4d6d81f45322f199be14` |
| **`details`** | `HistGradientBoostingClassifier` | $0.80$ | `max_iter=100`, `random_state=42` | Total Fwd Packet, Total Bwd packets, Total Length of Fwd Packet, Total Length of Bwd Packet, Fwd Packet Length Mean, Bwd Packet Length Mean, Down/Up Ratio | `d65136992788cf68376b8821c0d8d598020a55ba84140c1a3bdb3ceb06e4977c` |
| **`reviews`** | `HistGradientBoostingClassifier` | $0.70$ | `max_iter=100`, `random_state=42` | Total Length of Bwd Packet, Bwd Packet Length Mean, Packet Length Variance, Packet Length Std, Total Bwd packets, Down/Up Ratio, Flow IAT Mean | `63f4ee6f7d69d8e507955507d9d751ef850754ae52a9903bc323d9cf310ebdfc` |
| **`ratings`** | `RandomForestClassifier` | $0.70$ | `n_estimators=100`, `max_depth=15`, `random_state=42` | Total Fwd Packet, Total Bwd packets, Packet Length Mean, Packet Length Std, Packet Length Variance, PSH Flag Count, ACK Flag Count | `e7b14bf17f428dde7820dca07678601b95bde1dac1a3013cbb8916080cfb75d5` |

Full configuration manifest serialized in [`deployed_models_manifest.json`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/deployed_models_manifest.json).

---

## 3. Task 2: Offline ML Performance (Held-Out Test Split, $N = 8,484$)

Each model was evaluated against the independent $8,484$-flow test split ($5,468$ attack flows, $3,016$ benign flows). Raw predictions containing Flow IDs, ground-truth labels, continuous probabilities, and binary predictions are serialized in [`in_distribution_test_predictions.csv`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/in_distribution_test_predictions.csv).

### Table 1: In-Distribution Performance & Confusion Matrices ($N = 8,484$)

| Microservice | Architecture | $T$ | TP | TN | FP | FN | Accuracy [95% CI] | Precision | Recall (TPR) [95% CI] | F1-Score | FPR [95% CI] |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`productpage`** | Random Forest | $0.70$ | $5,467$ | $3,016$ | $0$ | $1$ | **$99.99\%$**<br>$[99.93\%, 100.0\%]$ | $1.0000$ | **$99.98\%$**<br>$[99.90\%, 100.0\%]$ | **$0.9999$** | **$0.00\%$**<br>$[0.00\%, 0.13\%]$ |
| **`details`** | HistGradientBoost | $0.80$ | $5,468$ | $3,015$ | $1$ | $0$ | **$99.99\%$**<br>$[99.93\%, 100.0\%]$ | $0.9998$ | **$100.00\%$**<br>$[99.93\%, 100.0\%]$ | **$0.9999$** | **$0.03\%$**<br>$[0.01\%, 0.19\%]$ |
| **`reviews`** | HistGradientBoost | $0.70$ | $5,468$ | $3,016$ | $0$ | $0$ | **$100.00\%$**<br>$[99.95\%, 100.0\%]$ | $1.0000$ | **$100.00\%$**<br>$[99.93\%, 100.0\%]$ | **$1.0000$** | **$0.00\%$**<br>$[0.00\%, 0.13\%]$ |
| **`ratings`** | Random Forest | $0.70$ | $5,468$ | $3,016$ | $0$ | $0$ | **$100.00\%$**<br>$[99.95\%, 100.0\%]$ | $1.0000$ | **$100.00\%$**<br>$[99.93\%, 100.0\%]$ | **$1.0000$** | **$0.00\%$**<br>$[0.00\%, 0.13\%]$ |

All metrics match the serialized baseline in [`in_distribution_metrics.json`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/in_distribution_metrics.json).

---

## 4. Task 3: Cross-Day Generalization & Flow-ID Independence Analysis ($N = 87,886$)

To test external generalization, the frozen models were evaluated on $87,886$ independent unseen flows captured on different calendar days:
- **Monday Port 80 Benign Baseline ($N = 36,111$):** Pure enterprise normal HTTP traffic.
- **Friday Port 80 Benign Baseline ($N = 31,775$):** Normal background HTTP traffic around attack campaigns.
- **Friday LOIC DDoS Attacks ($N = 20,000$):** High Orbit / Low Orbit Ion Cannon flood attacks.

Raw prediction files are saved in:
- [`out_of_distribution_loic_predictions.csv`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/out_of_distribution_loic_predictions.csv) ($20,000$ rows)
- [`out_of_distribution_monday_benign_predictions.csv`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/out_of_distribution_monday_benign_predictions.csv) ($36,111$ rows)
- [`out_of_distribution_friday_benign_predictions.csv`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/out_of_distribution_friday_benign_predictions.csv) ($31,775$ rows)

### Table 2: Multi-Day Generalization & Large-Scale Benign Evaluation ($N = 87,886$)

| Microservice | LOIC Attack Recall ($N = 20,000$) [95% CI] | Monday HTTP FPR ($N = 36,111$) [95% CI] | Friday HTTP FPR ($N = 31,775$) [95% CI] | Combined Large-Scale Benign FPR ($N = 67,886$) |
| :--- | :---: | :---: | :---: | :---: |
| **`productpage`** | **$99.70\%$** ($19,940/20,000$)<br>$[99.61\%, 99.77\%]$ | **$0.17\%$** ($61/36,111$)<br>$[0.13\%, 0.22\%]$ | **$0.12\%$** ($37/31,775$)<br>$[0.08\%, 0.16\%]$ | **$0.14\%$** ($98/67,886$) |
| **`details`** | **$99.76\%$** ($19,952/20,000$)<br>$[99.68\%, 99.82\%]$ | **$0.15\%$** ($55/36,111$)<br>$[0.12\%, 0.20\%]$ | **$0.15\%$** ($49/31,775$)<br>$[0.12\%, 0.20\%]$ | **$0.15\%$** ($104/67,886$) |
| **`reviews`** | **$99.89\%$** ($19,979/20,000$)<br>$[99.84\%, 99.93\%]$ | **$0.25\%$** ($92/36,111$)<br>$[0.21\%, 0.31\%]$ | **$0.11\%$** ($36/31,775$)<br>$[0.08\%, 0.16\%]$ | **$0.19\%$** ($128/67,886$) |
| **`ratings`** | **$99.97\%$** ($19,993/20,000$)<br>$[99.93\%, 99.98\%]$ | **$0.13\%$** ($47/36,111$)<br>$[0.10\%, 0.17\%]$ | **$0.11\%$** ($36/31,775$)<br>$[0.08\%, 0.16\%]$ | **$0.12\%$** ($83/67,886$) |

### 4.1 Reconciliation of the 792 Overlapping Flow IDs
In the CIC-IDS2017 dataset, `Flow ID` is a text concatenation of the 5-tuple: `Src IP-Dst IP-Src Port-Dst Port-Protocol`. 

An audit of the $792$ Flow IDs appearing in both Wednesday Test and Friday LOIC revealed:
1. **Testbed Fixed Addressing:** Attacker machine IP (`172.16.0.1`) and web server IP (`192.168.10.50:80`) were fixed throughout the week. Standard OS client ephemeral port ranges ($49152\sim 65535$) were recycled by automated scripts on Wednesday and Friday.
2. **Temporal Separation:** Wednesday flows occurred on **July 5, 2017**, whereas Friday LOIC flows occurred on **July 7, 2017** (48 hours later).
3. **Zero Feature Hash Overlap:** Evaluating all $792$ flows across Wednesday and Friday proved that **$\mathbf{0}$ feature hashes overlap ($\mathbf{0.00\%}$ collision rate)**. LOIC packet size distributions, burst volumes, and inter-arrival timing patterns are completely distinct from Wednesday Hulk/Slowloris attacks.

Full details documented in [`dataset_leakage_and_hash_audit.json`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/dataset_leakage_and_hash_audit.json).

---

## 5. Task 4: Live Kubernetes False-Positive Evaluation ($N = 400$)

### 5.1 Reconciling Online Scrape Decisions vs. Request-ID-Level Matching
To resolve the live telemetry discrepancy:
- **Workload Delivery:** $400$ requests ($100$ per service) were transmitted from `client-benign` (`10.244.0.130`). Envoy access logs intercepted and recorded all $400$ requests ($100\%$ HTTP $200$ OK).
- **Online Scrape-Window Evaluations ($N = 11$):** Because requests were sent at $0.08\text{ s}$ intervals ($8\text{ s}$ burst per service), the controller's periodic 2-second log-scraping loop accumulated requests in batches and evaluated the latest vector in each window (`latest_replay = replay_records[-1]`). This resulted in **$11$ live online ML inference evaluations** across the four pods ($6$ on `productpage`, $2$ on `details`, $2$ on `reviews`, $1$ on `ratings`). All $11$ evaluated as **NORMAL**. Zero attack alerts were triggered, zero Kubernetes Leases were acquired, and zero VirtualServices were modified.
- **Request-ID-Level Trace Matching ($N = 400$):** To verify all $400$ individual requests, each tagged Request ID was parsed from Envoy access logs and evaluated directly against the frozen model pipeline. All $400$ requests produced probabilities far below operating tripwires:
  - `productpage` ($T=0.70$): Maximum probability was $0.2200$ (mean: $0.0042$).
  - `details` ($T=0.80$): Maximum probability was $0.4446$ (mean: $0.0046$).
  - `reviews` ($T=0.70$): Maximum probability was $0.0754$ (mean: $0.0012$).
  - `ratings` ($T=0.70$): Maximum probability was $0.6200$ (mean: $0.0095$).
  - **Empirical FPR:** **$0 / 400$ ($0.00\%$)**.

### Table 3: Live Kubernetes False-Positive Test Results ($N = 400$)

| Microservice | Requests Sent | HTTP 200 OK | Online ML Scrape Decisions | Request-ID Matching Evals | False Positive Alerts | Leases Acquired | VirtualService Mutations | Empirical Live FPR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **`productpage`** | $100$ | $100$ ($100\%$) | $6$ | $100$ | $0$ | $0$ | $0$ | **$0.00\%$** ($0/100$) |
| **`details`** | $100$ | $100$ ($100\%$) | $2$ | $100$ | $0$ | $0$ | $0$ | **$0.00\%$** ($0/100$) |
| **`reviews`** | $100$ | $100$ ($100\%$) | $2$ | $100$ | $0$ | $0$ | $0$ | **$0.00\%$** ($0/100$) |
| **`ratings`** | $100$ | $100$ ($100\%$) | $1$ | $100$ | $0$ | $0$ | $0$ | **$0.00\%$** ($0/100$) |
| **OVERALL** | **$400$** | **$400$** ($100\%$) | **$11$** | **$400$** | **$0$** | **$0$** | **$0$** | **$0.00\%$** ($0/400$) |

### 5.2 State Immutability Verification
- **VirtualServices:** Pre-test vs. post-test `resourceVersion` comparison confirmed **$0$ modifications** across all services. Pre-test and post-test snapshot JSON files have **identical SHA-256: `5d2cd0dbc24a9238...`**.
- **Kubernetes Leases:** Pre-test vs. post-test lease inspection confirmed **$0$ active lease holders**. Pre-test and post-test snapshot JSON files have **identical SHA-256: `6b860dc91cf066a1...`**.
- **Request-ID CSV:** Full row-level matching table saved to [`live_benign_400_request_id_evaluations.csv`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/live_benign_400_request_id_evaluations.csv).
- **Sanitized Logs:** All bearer authentication tokens redacted in [`live_benign_envoy_logs.txt`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/live_benign_envoy_logs.txt) and [`live_benign_defender_logs.txt`](file:///c:/Users/mdbohos/Desktop/ddos_detector/PAPER/FINAL_MANUSCRIPT_EVIDENCE/ML_ACCURACY_FPR/live_benign_defender_logs.txt).

---

## 6. Task 5: Methodology Clarification & Scientific Limitations

### 6.1 Evaluation Harness vs. Production Telemetry
To maintain absolute scientific transparency:
- **Production Mode:** In enterprise deployments, network and transport features are aggregated by in-kernel eBPF probes, sidecar proxies, or network flow collectors.
- **Benchmark Evaluation Mode:** To test the distributed control plane (ML inference, Kubernetes Lease consensus, and Istio VirtualService OCC updates) with bit-exact reproducibility, authentic benchmark flow features from CIC-IDS2017 are transmitted within authenticated HTTP headers (`x-request-id`) by authorized client pods. When requests traverse Envoy, the controller extracts the 7 feature values and passes them to the local model pipeline. Thus, live inference evaluates authentic benchmark flow features carried via HTTP metadata, isolating control-plane coordination from raw packet-reassembly timing variance.

### 6.2 Access Control Policy
The evaluation harness enforces access control via a **Pre-Shared Bearer Key (PSK) with Network Peer IP Allowlisting**. Replay requests authorize mitigation if and only if: (1) the payload includes an authorized token (`#auth=<REDACTED_BENCH_AUTH_TOKEN>`); (2) the Envoy TCP downstream remote peer matches sanctioned client IPs (`10.244.0.130`, `10.244.0.131`); and (3) the Request-ID is fresh ($< 8.0\text{ s}$) and deduplicated. Any unauthorized injection is rejected with `[SECURITY-BLOCKED]`.

### 6.3 Limitations
While offline evaluation encompasses $8,484$ in-distribution flows and $87,886$ multi-day generalization flows, live Kubernetes false-positive testing was conducted on a sample of $400$ requests ($100$ per service) due to live cluster pacing and log-scraping cycle times. In larger enterprise deployments, continuous background traffic evaluation across multiple days is recommended to observe long-term diurnal shifts.
