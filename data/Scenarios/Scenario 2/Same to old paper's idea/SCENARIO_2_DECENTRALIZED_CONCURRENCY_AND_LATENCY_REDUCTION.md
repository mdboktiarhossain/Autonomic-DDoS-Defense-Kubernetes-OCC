# C. Scenario 2: Decentralized Concurrency and Latency Reduction

To address the contention identified in Scenario 1, the proposed architecture distributes the four service workloads across independent defender processes, enabling concurrent cross-service execution. Within each defender, a six-worker `ThreadPoolExecutor` concurrently evaluates the available service-version feature vectors. The total cycle time is therefore bounded by the slowest inference:

$$T_{\text{con}} = \max(t_1, t_2, \dots, t_N) + t_{\text{overhead}} \quad (5)$$

where $t_{\text{overhead}}$ accounts for thread scheduling and synchronization costs. Since each pod operates as a separate OS process, cross-service GIL contention is substantially reduced. Under simultaneous parallel attack across all four services, this decentralized approach achieved a **37% throughput gain (60.1 rps vs. 44.0 rps centralized at 60 RPS offered load, scaling to a 170% gain of 90.0 rps vs. 34.9 rps at 90 RPS)** and a **98.8% latency reduction (13.2 ms vs. 1,103.4 ms centralized at 60 RPS)**, with direct live cluster cycle time reduced by **77.0% (44.6 ms vs. 193.7 ms centralized, a 4.34x speedup)**. Under unsaturated baseline conditions, median latency remains strictly bounded at 7.5 ms vs. 29.3 ms centralized (a 65.9% reduction, matching the 19.9 ms vs. 27.6 ms closed-loop baseline), demonstrating that parallel per-pod inference substantially improves scalability under concurrent-attack conditions.

---

### Table II: Scenario 2: Decentralized Parallel Attack Results
*(10 Paired Repetitions, 60 RPS Offered Load, 64 Client Workers, 4 Cores Aggregate)*

| Service | Avg Latency (ms) | p95 Latency (ms) | Throughput (rps) | Errors |
| :--- | :---: | :---: | :---: | :---: |
| **productpage** | 13.56 $\pm$ 2.45 | 43.63 $\pm$ 16.81 | 15.02 $\pm$ 0.01 | 0 |
| **details** | 10.97 $\pm$ 1.89 | 39.32 $\pm$ 14.20 | 15.01 $\pm$ 0.01 | 0 |
| **reviews** | 11.23 $\pm$ 2.12 | 36.24 $\pm$ 13.95 | 15.02 $\pm$ 0.01 | 0 |
| **ratings** | 17.08 $\pm$ 3.82 | 55.33 $\pm$ 18.42 | 15.01 $\pm$ 0.01 | 0 |
| **TOTAL** | **13.21 $\pm$ 3.02** | **43.63 $\pm$ 16.81** | **60.06 $\pm$ 0.03** | **0** |

---

### Table III: Scenario 2: Centralized Parallel Attack Results
*(10 Paired Repetitions, 60 RPS Offered Load, 64 Client Workers, 4 Cores, No Global Mutex Lock)*

| Service | Avg Latency (ms) | p95 Latency (ms) | Throughput (rps) | Errors |
| :--- | :---: | :---: | :---: | :---: |
| **productpage** | 1,098.42 $\pm$ 135.20 | 1,652.14 $\pm$ 245.10 | 11.02 $\pm$ 0.82 | 0 |
| **details** | 1,105.18 $\pm$ 124.60 | 1,658.30 $\pm$ 238.40 | 10.99 $\pm$ 0.74 | 0 |
| **reviews** | 1,102.75 $\pm$ 129.80 | 1,654.80 $\pm$ 242.10 | 11.01 $\pm$ 0.76 | 0 |
| **ratings** | 1,107.12 $\pm$ 126.50 | 1,657.12 $\pm$ 239.50 | 10.97 $\pm$ 0.71 | 0 |
| **TOTAL** | **1,103.37 $\pm$ 128.55** | **1,655.59 $\pm$ 240.93** | **43.99 $\pm$ 3.01** | **0** |

---

### Table IV: Scenario 2: Parallel Attack Comparison

| Metric | Decentralized | Centralized | Difference |
| :--- | :---: | :---: | :---: |
| **Throughput (60 RPS Offered)** | 60.06 $\pm$ 0.03 rps | 43.99 $\pm$ 3.01 rps | **+37.2%** (Decentralized wins) |
| **Throughput (90 RPS Offered)** | 89.96 $\pm$ 0.26 rps | 34.86 $\pm$ 8.00 rps | **+169.8%** (Decentralized wins) |
| **Avg Latency (60 RPS Offered)** | 13.21 $\pm$ 3.02 ms | 1,103.37 $\pm$ 128.55 ms | **$-$98.8%** (Decentralized wins) |
| **p95 Latency (60 RPS Offered)** | 43.63 $\pm$ 16.81 ms | 1,655.59 $\pm$ 240.93 ms | **$-$97.4%** (Decentralized wins) |
| **Live Cluster Cycle ($T_{\text{cluster}}$)** | 44.64 $\pm$ 27.30 ms | 193.66 $\pm$ 41.69 ms | **$-$77.0%** ($4.34\times$ speedup) |
| **Max Saturation Capacity** | 252.68 $\pm$ 15.45 rps/pod | 46.36 $\pm$ 2.35 rps (total) | **+446.5%** (Decentralized wins) |
| **Prediction Agreement** | 100.0% (0 mismatches) | 100.0% (0 mismatches) | Exact Parity |
| **Errors** | 0 | 0 | Tie |

---

The performance gap in parallel scenarios arises directly from a fundamental architectural difference in concurrency management. The evaluated metric here is the **ML Inference Latency** defined earlier, which isolates the computational API overhead from the broader detection cycle. In the centralized baseline, a simultaneous attack across all four services causes concurrent inference requests across all services to compete for a single Python process. Consequently, FastAPI request routing, JSON parsing, feature vector scaling, and response serialization remain heavily contended and partially serialized, creating a queuing effect that more than doubles latency and inflates model execution time from 7.0 ms to 134.1 ms. In the decentralized architecture, each of the four pods is a separate OS process with its own Python interpreter, so the evaluated deployment can dispatch up to three service-version inference tasks concurrently within each pod using the six-worker `ThreadPoolExecutor`. Because the pods are separate processes, there is no inter-service GIL contention. This process-level isolation contributes to the observed latency advantage under simultaneous multi-service attacks.

To confirm that the performance divergence is caused specifically by interpreter serialization rather than hardware constraints, we conducted an empirical audit of the Linux Completely Fair Scheduler (CFS) and Python thread execution states:

1. **Cgroup CPU Quota Audit:** Across all ten benchmark repetitions, reading `/sys/fs/cgroup/cpu.stat` confirmed that both architectures experienced strictly zero throttling ($\Delta \text{nr\_throttled} = 0$, $\Delta \text{throttled\_usec} = 0$). CPU quota starvation is therefore ruled out as a confounding factor.
2. **Thread CPU vs. Wall-Clock Execution Time:** Comparing active thread CPU execution time ($C = \text{time.thread\_time()}$) against elapsed wall-clock duration ($W = \text{time.perf\_counter()}$) isolates the exact lock contention overhead:
   $$T_{\text{gil\_wait}} = W - C, \quad \Gamma = \frac{W}{C}$$
   Under decentralized execution (four OS processes, four independent GILs), each worker thread achieves near-ideal multi-core scaling: $\Gamma = 1.06\times$, with GIL wait delay $T_{\text{gil\_wait}} = 0.88\text{ ms}$. Under centralized concurrent execution (one OS process, single GIL), active thread execution requires only $C = 6.69\text{ ms}$, but wall-clock duration swells to $W = 78.67\text{ ms}$ ($\Gamma = 11.75\times$). Worker threads spend $91.5\%$ of their wall-clock lifetime ($71.97\text{ ms}$) suspended in kernel `futex` states awaiting GIL acquisition, confirming that the single-process interpreter lock is the primary scalability bottleneck.
3. **Mathematical Verification of Equation (5):** Micro-level profiling across 100 consecutive multi-version evaluation cycles verified Equation (5) down to sub-millisecond precision. For *productpage*, $\max(t_i) = 67.26 \pm 1.66\text{ ms}$ and $t_{\text{overhead}} = 1.08 \pm 0.21\text{ ms}$ yielded a measured cycle time $T_{\text{con}} = 68.34 \pm 1.69\text{ ms}$ ($67.26 + 1.08 = 68.34\text{ ms}$); for *details*, $14.79 + 1.18 = 15.97\text{ ms}$; for *reviews*, $16.71 + 2.27 = 18.97\text{ ms}$; and for *ratings*, $69.87 + 1.00 = 70.86\text{ ms}$. Thread synchronization overhead ($t_{\text{overhead}}$) remained between $1.00\text{ ms}$ and $2.27\text{ ms}$ across all services.

These latency reductions have direct implications for real-time mitigation: the concurrent execution model ensures rapid identification of attack onset. The Traffic Rerouting Engine then applies the corresponding Kubernetes API update, after which Istio propagates the updated routing configuration to the relevant Envoy proxies.
