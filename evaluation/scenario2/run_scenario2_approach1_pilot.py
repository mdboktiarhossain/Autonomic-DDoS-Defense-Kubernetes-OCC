import paramiko, os, time, json

ssh_pass = os.getenv('VM_SSH_PASSWORD') or os.getenv('SSH_PASS')
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('192.168.160.129', username='osu', password=ssh_pass, timeout=15)

def run(cmd):
    stdin, stdout, stderr = c.exec_command(cmd)
    return stdout.read().decode('utf-8', errors='replace').strip()

token = "s5-bench-f053dcc794d2ded12515542502dd2a49736e6c21294343d6"

print("[1] Configuring defender deployments...")
for dep in ["ddos-defender-product", "ddos-defender-details", "ddos-defender-reviews", "ddos-defender-ratings"]:
    run(f"kubectl set env deployment/{dep} ENABLE_SCENARIO2_EVAL_API=true SCENARIO2_EVAL_API_TOKEN={token}")

for dep in ["ddos-defender-product", "ddos-defender-details", "ddos-defender-reviews", "ddos-defender-ratings"]:
    run(f"kubectl rollout status deployment/{dep} --timeout=60s")

print("[2] Deploying scenario2-central-b (Approach 1: Concurrent, 4 cores, NO global lock)...")
manifest = f"""apiVersion: v1
kind: Pod
metadata:
  name: scenario2-central-b
  namespace: default
  labels:
    app: scenario2-central-b
  annotations:
    sidecar.istio.io/inject: "false"
spec:
  serviceAccountName: ddos-defender-sa
  containers:
  - name: central-evaluator
    image: boktiar/ddos-defender:cic-v5.5-scenario2
    imagePullPolicy: Never
    command: ["uvicorn", "defender:app", "--host", "0.0.0.0", "--port", "8080"]
    env:
    - name: DETECTION_MODE
      value: "central"
    - name: SERVICE_NAME
      value: ""
    - name: ENABLE_PARALLEL_L7_INFERENCE
      value: "false"
    - name: ENABLE_SCENARIO2_EVAL_API
      value: "true"
    - name: SCENARIO2_SEQUENTIAL_API
      value: "false"
    - name: SCENARIO2_EVAL_API_TOKEN
      value: "{token}"
    - name: READ_ONLY_MODE
      value: "true"
    - name: ENABLE_ML_MITIGATION
      value: "false"
    - name: ENABLE_RPS_ENFORCEMENT
      value: "false"
    - name: ENABLE_STAGE3B_ATTRIBUTION
      value: "false"
    - name: ENABLE_STAGE3B_ENFORCEMENT
      value: "false"
    ports:
    - containerPort: 8080
      name: http
    resources:
      requests:
        cpu: "4"
        memory: 2Gi
      limits:
        cpu: "4"
        memory: 8Gi
"""

sftp = c.open_sftp()
with sftp.file('/tmp/scenario2_central_b_app1.yaml', 'w') as f:
    f.write(manifest)
sftp.close()

run("kubectl delete pod scenario2-central-b --force --grace-period=0 2>/dev/null || true")
time.sleep(2)
run("kubectl apply -f /tmp/scenario2_central_b_app1.yaml")
run("kubectl wait --for=condition=ready pod/scenario2-central-b --timeout=45s")
time.sleep(3)

p_ip = run("kubectl get pod -l app=ddos-defender-product -o jsonpath='{.items[0].status.podIP}'")
d_ip = run("kubectl get pod -l app=ddos-defender-details -o jsonpath='{.items[0].status.podIP}'")
r_ip = run("kubectl get pod -l app=ddos-defender-reviews -o jsonpath='{.items[0].status.podIP}'")
t_ip = run("kubectl get pod -l app=ddos-defender-ratings -o jsonpath='{.items[0].status.podIP}'")
b_ip = run("kubectl get pod scenario2-central-b -o jsonpath='{.status.podIP}'")

p_pod = run("kubectl get pod -l app=ddos-defender-product -o jsonpath='{.items[0].metadata.name}'")
d_pod = run("kubectl get pod -l app=ddos-defender-details -o jsonpath='{.items[0].metadata.name}'")
r_pod = run("kubectl get pod -l app=ddos-defender-reviews -o jsonpath='{.items[0].metadata.name}'")
t_pod = run("kubectl get pod -l app=ddos-defender-ratings -o jsonpath='{.items[0].metadata.name}'")
b_pod = "scenario2-central-b"

print(f"Verified IPs:\nProduct: {p_ip}\nDetails: {d_ip}\nReviews: {r_ip}\nRatings: {t_ip}\nCentral B: {b_ip}")

# Create runner script on VM for Scenario 2 Approach 1 Pilot
vm_runner = f"""
import subprocess, threading, time, json, os, urllib.request

token = "{token}"
os.environ["SCENARIO2_EVAL_API_TOKEN"] = token

p_ip = "{p_ip}"
d_ip = "{d_ip}"
r_ip = "{r_ip}"
t_ip = "{t_ip}"
b_ip = "{b_ip}"

p_pod = "{p_pod}"
d_pod = "{d_pod}"
r_pod = "{r_pod}"
t_pod = "{t_pod}"
b_pod = "{b_pod}"

base_dir = "/home/osu/scenario2_parallel_l7/scenario2_approach1/pilot"
os.makedirs(base_dir, exist_ok=True)

def get_cgroup_stats():
    stats = {{}}
    pods = [("product", p_pod), ("details", d_pod), ("reviews", r_pod), ("ratings", t_pod), ("central_b", b_pod)]
    for label, pod in pods:
        try:
            res = subprocess.run(["kubectl", "exec", pod, "--", "cat", "/sys/fs/cgroup/cpu.stat"], capture_output=True, text=True, timeout=5)
            kv = {{}}
            for line in res.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) == 2:
                    kv[parts[0]] = int(parts[1])
            stats[label] = kv
        except Exception as e:
            stats[label] = {{"error": str(e)}}
    return stats

attack_script = '''
import os, sys, time, threading, urllib.request, json

stop_flag = sys.argv[1]
log_path = sys.argv[2]

targets = [
    ("productpage", "http://productpage:9080/productpage"),
    ("details", "http://details:9080/details/0"),
    ("reviews", "http://reviews:9080/reviews/0"),
    ("ratings", "http://ratings:9080/ratings/0"),
]

stats = {{name: {{"sent": 0, "success": 0, "errors": 0}} for name, _ in targets}}
lock = threading.Lock()
start_ts = time.time()

def worker(name, url):
    while not os.path.exists(stop_flag):
        try:
            req = urllib.request.Request(url, headers={{"User-Agent": "synchronized-bookinfo-attacker/1.0"}})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                code = resp.getcode()
                with lock:
                    stats[name]["sent"] += 1
                    if code == 200:
                        stats[name]["success"] += 1
                    else:
                        stats[name]["errors"] += 1
        except Exception:
            with lock:
                stats[name]["sent"] += 1
                stats[name]["errors"] += 1
        time.sleep(0.04)

threads = []
for name, url in targets:
    for _ in range(2):
        t = threading.Thread(target=worker, args=(name, url), daemon=True)
        t.start()
        threads.append(t)

while not os.path.exists(stop_flag):
    time.sleep(0.5)

end_ts = time.time()
dur = end_ts - start_ts
total_sent = sum(s["sent"] for s in stats.values())
achieved_rps = total_sent / dur if dur > 0 else 0.0

res = {{
    "start_time_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_ts)),
    "end_time_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(end_ts)),
    "start_timestamp": start_ts,
    "end_timestamp": end_ts,
    "duration_seconds": round(dur, 2),
    "total_requests": total_sent,
    "total_success": sum(s["success"] for s in stats.values()),
    "total_errors": sum(s["errors"] for s in stats.values()),
    "achieved_attack_rps": round(achieved_rps, 2),
    "per_service": stats
}}
with open(log_path, "w") as f:
    json.dump(res, f, indent=2)
'''

subprocess.run(["kubectl", "exec", "-i", "client-attacker", "-c", "client-attacker", "--", "sh", "-c", "cat > /tmp/atk_app1_pilot.py"], input=attack_script, text=True)

for rps in [60.0, 90.0]:
    rps_str = str(int(rps))
    print(f"\\n==================================================================")
    print(f"SCENARIO 2 APPROACH 1 PILOT @ {{rps_str}} RPS (1 PAIRED REP, 64 WORKERS)")
    print(f"==================================================================")
    out_dir = os.path.join(base_dir, f"rps_{{rps_str}}")
    os.makedirs(out_dir, exist_ok=True)
    
    stop_flag = f"/tmp/stop_app1_pilot_{{rps_str}}.flag"
    log_path = f"/tmp/atk_log_app1_pilot_{{rps_str}}.json"
    subprocess.run(["kubectl", "exec", "client-attacker", "-c", "client-attacker", "--", "rm", "-f", stop_flag, log_path])
    
    atk_proc = subprocess.Popen(["kubectl", "exec", "client-attacker", "-c", "client-attacker", "--", "python3", "-u", "/tmp/atk_app1_pilot.py", stop_flag, log_path])
    print("[+] Background attack generator started on client-attacker.")
    time.sleep(5.0)
    
    cpu_before = get_cgroup_stats()
    bench_start_ts = time.time()
    bench_start_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(bench_start_ts))
    print(f"Benchmark started at UTC: {{bench_start_iso}}")
    
    cmd = [
        "python3", "scenario2_ab_live_api_benchmark.py",
        "--workload", "test4_workload_1000.json",
        "--a-productpage", f"http://{{p_ip}}:8080",
        "--a-details", f"http://{{d_ip}}:8080",
        "--a-reviews", f"http://{{r_ip}}:8080",
        "--a-ratings", f"http://{{t_ip}}:8080",
        "--b-central", f"http://{{b_ip}}:8080",
        "--per-service", "100",
        "--repetitions", "1",
        "--offered-rps", str(rps),
        "--client-workers", "64",
        "--output-dir", out_dir
    ]
    
    bench_res = subprocess.run(cmd, cwd="/home/osu/scenario2_parallel_l7", capture_output=True, text=True)
    bench_end_ts = time.time()
    bench_end_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(bench_end_ts))
    cpu_after = get_cgroup_stats()
    
    print(bench_res.stdout)
    if bench_res.stderr:
        print("BENCH STDERR:", bench_res.stderr[-400:])
        
    print(f"Benchmark completed at UTC: {{bench_end_iso}} (Elapsed: {{bench_end_ts - bench_start_ts:.2f}}s)")
    
    time.sleep(3.0)
    subprocess.run(["kubectl", "exec", "client-attacker", "-c", "client-attacker", "--", "touch", stop_flag])
    try:
        atk_proc.wait(timeout=10.0)
    except Exception:
        atk_proc.kill()
        
    print("[+] Background attack generator stopped.")
    
    atk_log_res = subprocess.run(["kubectl", "exec", "client-attacker", "-c", "client-attacker", "--", "cat", log_path], capture_output=True, text=True)
    try:
        attack_data = json.loads(atk_log_res.stdout)
    except Exception:
        attack_data = {{"raw": atk_log_res.stdout}}
        
    with open(os.path.join(out_dir, "synchronized_attack_generator_log.json"), "w") as f:
        json.dump(attack_data, f, indent=2)
        
    cpu_deltas = {{}}
    for k in cpu_before:
        if "usage_usec" in cpu_before[k] and "usage_usec" in cpu_after[k]:
            cpu_deltas[k] = {{
                "delta_usage_usec": cpu_after[k]["usage_usec"] - cpu_before[k]["usage_usec"],
                "delta_nr_throttled": cpu_after[k].get("nr_throttled", 0) - cpu_before[k].get("nr_throttled", 0),
                "delta_throttled_usec": cpu_after[k].get("throttled_usec", 0) - cpu_before[k].get("throttled_usec", 0)
            }}
    with open(os.path.join(out_dir, "cgroup_cpu_deltas.json"), "w") as f:
        json.dump(cpu_deltas, f, indent=2)
        
    containment = {{
        "attack_start_iso": attack_data.get("start_time_iso"),
        "benchmark_start_iso": bench_start_iso,
        "benchmark_end_iso": bench_end_iso,
        "attack_end_iso": attack_data.get("end_time_iso"),
        "strict_containment_verified": (
            (attack_data.get("start_timestamp") or 0) < bench_start_ts and
            (attack_data.get("end_timestamp") or float('inf')) > bench_end_ts
        )
    }}
    with open(os.path.join(out_dir, "temporal_containment_verification.json"), "w") as f:
        json.dump(containment, f, indent=2)
        
    time.sleep(4.0)

print("\\n[+] Approach 1 Pilot completed successfully!")
"""

sftp = c.open_sftp()
with sftp.file('/home/osu/scenario2_parallel_l7/execute_approach1_pilot.py', 'w') as f:
    f.write(vm_runner)
sftp.close()

c.close()
print("Scenario 2 Approach 1 pilot environment deployed successfully!")
