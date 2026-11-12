# Experimental Data & Cloud Archive Guide

## 1. Data Included Directly in This GitHub Repository (`data/`)

All primary benchmark evidence packages, reconciled summary JSONs, SHA-256 integrity manifests, and markdown audit reports required to verify the manuscript's tables and figures are included directly in this repository under [`data/`](./):

* **[`data/Concurrency/`](Concurrency/):**
  * `PROCESS_LEVEL_PARALLEL_EVIDENCE_PACKAGE.zip` & `PROCESS_LEVEL_PARALLEL_MANIFEST.sha256`
  * `EMPIRICAL_VALIDATION_PARALLEL_EXECUTION_REPORT.md`
  * Multi-process execution overlap, Linux `strace` kernel `futex` contention, and GIL ablation evidence.
* **[`data/FPR/`](FPR/):**
  * `FINAL_ML_EVIDENCE_MANIFEST.json` & `FINAL_ML_ACCURACY_FPR_REPORT.md`
  * Strict out-of-fold accuracy, duplicate-removed sensitivity, and unseen Monday/Friday benign false-positive rate (FPR) validation.
* **[`data/Scenarios/`](Scenarios/):**
  * **`Scenario 1/`:** Single-service targeted quarantine (`10/10 PASS` decentralized vs. `10/10 PASS` centralized), `SCENARIO_1_BENCHMARK_RESULTS_RAW.zip`, `scenario1_final_benchmark_summary.json`, and `Approach2/` parity & cgroup throttling audits.
  * **`Scenario 2/`:** Two-dimensional concurrency, $60\text{ RPS}$ / $90\text{ RPS}$ throughput & latency benchmarks, and `SCENARIO_2_MEASUREMENT_AUDIT_EVIDENCE_PACKAGE.zip`.
  * **`Scenario 3/`:** Controller crash fault-blast-radius containment (`25%` decentralized blast radius vs. `100%` centralized loss), `SCENARIO_3_BENCHMARK_RAW_EVIDENCE.zip`, and `SCENARIO_3_BENCHMARK_SUMMARY.json`.
  * **`Scenario 4/`:** Heterogeneous 7-feature classifier evaluation, unseen Friday LOIC recall, container scaling benchmarks, `SCENARIO_4_BENCHMARK_RAW_EVIDENCE.zip`, and `SCENARIO_4_BENCHMARK_SUMMARY.json`.
  * **`Scenario 5/`:** End-to-end synchronized 4-service $160\text{ RPS}$ attack mitigation, Lease/fencing/OCC audit (`56/56` first-attempt commits), two-stage recovery, and `SCENARIO_5_REPETITIONS_PACKAGE.zip`.

---

## 2. Full Raw Experimental Archive & Upstream Dataset (Hosted on OneDrive)

Because GitHub enforces a 100 MB per-file limit, the following two large archives are hosted on Cloud Storage (**OneDrive**):

1. **`CICIDS2017_improved.zip` (`~335.5 MB`):**
   * The upstream DistriNet CNS 2022 corrected edition of the CIC-IDS2017 dataset (`wednesday.csv`, `monday.csv`, `friday.csv`) used by [`src/training/train_approved_four_models.py`](../src/training/train_approved_four_models.py) to train and evaluate the four 7-feature service models.
2. **`Backup raw experimental data for journal/` (`~1.73 GB`):**
   * The complete, uncondensed multi-cycle experimental archive containing all intermediate pilot runs, per-request client trace logs, raw Envoy sidecar access logs, Kubernetes `VirtualService`/`Lease` YAML snapshots, and historical rollout logs across Scenarios 1–5.

### Cloud Archive Access Link
* **OneDrive Shared Folder (Available Upon Request):** [Request Access to `Other Data` (`CICIDS2017_improved.zip` & `Backup raw experimental data for journal`) on OneDrive](https://ostatemailokstate-my.sharepoint.com/my?id=%2Fpersonal%2Fmd%5Fboktiar%5Fhossain%5Fokstate%5Fedu%2FDocuments%2FOther%20Data)
