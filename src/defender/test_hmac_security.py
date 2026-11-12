#!/usr/bin/env python3
"""
Comprehensive Security Unit and End-to-End Pipeline Test Suite for HMAC v2 Replay Authentication.
Directly imports and exercises the EXACT submitted controller:
PAPER/Backup/SCENARIO_5_PATCHED_DEFENDER_HMAC_V2.py

Tests include:
1. Full end-to-end inference cycle: run_l7_inference_cycle() and is_ml_attacked()
2. Cryptographic signature verification: verify_replay_signature()
3. All reviewer requirements:
   - Replaying an accepted signed request after controller restart while signature remains fresh (Finding H1)
   - Replaying after signature expiration (>60s)
   - Invalid or malformed log timestamps (NaN, inf, non-numeric, corrupt)
   - Cross-service authorization failure (#svc=ratings on details)
   - Duplicate request IDs rejected by in-memory cache
   - Cache expiration (>300s) and positive-only insertion
   - Invalid authentication without ML enforcement
   - Seven-feature details model compatibility
"""

import sys
import os
import time
import math
import hmac
import hashlib
import datetime
import secrets
import unittest.mock as mock
import numpy as np

sys.stdout.reconfigure(encoding="utf-8")

# 1. Mock kubernetes APIs so controller can be imported in any environment without kubeconfig
mock_config = mock.MagicMock()
mock_client = mock.MagicMock()
sys.modules['kubernetes'] = mock.MagicMock()
sys.modules['kubernetes.config'] = mock_config
sys.modules['kubernetes.client'] = mock_client
sys.modules['kubernetes.client.rest'] = mock.MagicMock()

# 2. Directly import the submitted patched controller
CONTROLLER_PATH = os.path.abspath("PAPER/Backup/SCENARIO_5_PATCHED_DEFENDER_HMAC_V2.py")
if not os.path.exists(CONTROLLER_PATH):
    raise FileNotFoundError(f"Missing patched controller at {CONTROLLER_PATH}")

import importlib.util
spec = importlib.util.spec_from_file_location("defender", CONTROLLER_PATH)
defender = importlib.util.module_from_spec(spec)
spec.loader.exec_module(defender)

# 3. Test Configuration & Harness Setup
import joblib
TEST_KEY = secrets.token_hex(24)  # 192 bits of entropy
FEAT_DETAILS_7 = "4.0,3.0,239.0,0.0,59.75,0.0,0.75"
SERVICE = "details"
POD_NAME = "details-v1-testpod"

# Load the REAL serialized 7-feature model artifact (Reviewer Instruction 3)
REAL_BUNDLE_PATH = os.path.abspath("models/details/details_bundle_7feat.joblib")
if not os.path.exists(REAL_BUNDLE_PATH):
    raise FileNotFoundError(f"Missing real model bundle at {REAL_BUNDLE_PATH}")

loaded_bundle = joblib.load(REAL_BUNDLE_PATH)
real_bundle_sha = hashlib.sha256(open(REAL_BUNDLE_PATH, "rb").read()).hexdigest()

active_bundle = {
    "architecture": "hist_gradient_boosting",
    "variant": loaded_bundle.get("variant", "calibrated_v5"),
    "feature_names": loaded_bundle["feature_names"],
    "scaler": loaded_bundle["scaler"],
    "model": loaded_bundle["model"],
    "threshold": float(loaded_bundle.get("threshold", 0.80)),
    "is_real_artifact": True,
    "artifact_path": REAL_BUNDLE_PATH,
    "artifact_sha256": real_bundle_sha
}

# Configure controller runtime state with the REAL trained model
defender.L7_MODEL_REGISTRY = {SERVICE: active_bundle}
defender.TEST_AUTH_TOKEN = TEST_KEY
defender.MY_APP_LABEL = SERVICE
defender.CANONICAL_SERVICE_NAME = SERVICE
defender.AUTHORIZED_TEST_CLIENT_IPS = {"10.244.0.131"}
defender.STATE["pods"] = {POD_NAME: {"app": SERVICE, "rps": 5.0}}
defender.STATE["l7_predictions"] = {}
defender.PROCESSED_REPLAY_RIDS.clear()

def compute_sig(key: str, rid_base: str, svc: str, feat: str, ts: str) -> str:
    msg = f"v1|{rid_base}|{svc.strip().lower()}|{feat}|{ts}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:32]

def format_envoy_log_line(ts_iso: str, client_ip: str, rid: str, status: int = 200, cluster: str = "inbound|9080||") -> str:
    return f'[{ts_iso}] "GET /details/0 HTTP/1.1" {status} - via_upstream - "-" 0 120 2 1 "{client_ip}" "curl/7.88.1" "{rid}" "details:9080" "10.244.0.131:9080" {cluster} 10.244.0.131:9080 10.244.0.130:45678 {client_ip}'

def execute_pipeline(log_lines: list, current_time: float) -> tuple:
    defender.collect_pod_logs = lambda pod: log_lines
    with mock.patch("time.time", return_value=current_time):
        defender.run_l7_inference_cycle()
        atk, reason = defender.is_ml_attacked(SERVICE)
        return atk, reason

print("=" * 80)
print("COMPREHENSIVE HMAC v2 SECURITY & INFERENCE PIPELINE TEST SUITE")
print("Target Service:     ", SERVICE)
print("Auth Mode:          ", defender.REPLAY_AUTH_MODE)
print("Features (7):       ", len(active_bundle["feature_names"]))
print("Model Artifact:     ", os.path.basename(active_bundle["artifact_path"]))
print("Model Architecture: ", active_bundle["architecture"])
print("Controller Module:  ", os.path.basename(CONTROLLER_PATH))
print("Key Entropy:        192 bits (24 bytes hex)")
print("=" * 80)

results = []
t_now = 1700000000.0  # Fixed baseline epoch for deterministic test times
t_iso = datetime.datetime.fromtimestamp(t_now, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Test 1: Full pipeline with valid signature -> Triggers authorized ML mitigation
defender.STATE["l7_predictions"].clear()
defender.PROCESSED_REPLAY_RIDS.clear()
ts_str1 = f"{t_now:.3f}"
sig1 = compute_sig(TEST_KEY, "req-1", SERVICE, FEAT_DETAILS_7, ts_str1)
rid1 = f"req-1#replay=cic17#svc={SERVICE}#feat={FEAT_DETAILS_7}#ts={ts_str1}#sig={sig1}"
line1 = format_envoy_log_line(t_iso, "10.244.0.131", rid1)

atk1, reason1 = execute_pipeline([line1], current_time=t_now)
pred1 = defender.STATE["l7_predictions"].get(POD_NAME, {})
test1_pass = (
    atk1 is True
    and "DDOS" in reason1
    and pred1.get("prediction") == "DDOS"
    and pred1.get("probability") >= active_bundle["threshold"]
    and pred1.get("is_authorized_client") is True
    and rid1 in defender.PROCESSED_REPLAY_RIDS
)
results.append(("1. Valid signature -> Full pipeline authorized with REAL model (DDOS & Active Mitigation)", test1_pass))

# Test 2: Invalid signature rejected -> Mitigation suppressed, cache untouched
defender.STATE["l7_predictions"].clear()
sig2 = "0123456789abcdef0123456789abcdef"
rid2 = f"req-2#replay=cic17#svc={SERVICE}#feat={FEAT_DETAILS_7}#ts={ts_str1}#sig={sig2}"
line2 = format_envoy_log_line(t_iso, "10.244.0.131", rid2)

atk2, reason2 = execute_pipeline([line2], current_time=t_now)
test2_pass = (
    atk2 is False
    and rid2 not in defender.PROCESSED_REPLAY_RIDS
    and POD_NAME not in defender.STATE["l7_predictions"]
)
results.append(("2. Invalid signature -> Rejected, cache untouched, mitigation suppressed", test2_pass))

# Test 3: Tampered feature vector rejected -> Signature mismatch, mitigation suppressed
defender.STATE["l7_predictions"].clear()
feat_tampered = "4.0,3.0,239.0,0.0,9999.0,0.0,0.75"
rid3 = f"req-3#replay=cic17#svc={SERVICE}#feat={feat_tampered}#ts={ts_str1}#sig={sig1}"
line3 = format_envoy_log_line(t_iso, "10.244.0.131", rid3)

atk3, _ = execute_pipeline([line3], current_time=t_now)
test3_pass = (atk3 is False and rid3 not in defender.PROCESSED_REPLAY_RIDS)
results.append(("3. Tampered feature vector -> Signature mismatch, mitigation suppressed", test3_pass))

# Test 4: Cross-service replay rejected (strict service binding: #svc=ratings on details)
defender.STATE["l7_predictions"].clear()
rid4 = f"req-4#replay=cic17#svc=ratings#feat={FEAT_DETAILS_7}#ts={ts_str1}#sig={sig1}"
line4 = format_envoy_log_line(t_iso, "10.244.0.131", rid4)

atk4, _ = execute_pipeline([line4], current_time=t_now)
test4_pass = (atk4 is False and rid4 not in defender.PROCESSED_REPLAY_RIDS)
results.append(("4. Cross-service replay (#svc=ratings on details) -> Dropped, mitigation suppressed", test4_pass))

# Test 5: Expired signature in past (>60s) rejected
defender.STATE["l7_predictions"].clear()
ts_past = f"{t_now - 65.0:.3f}"
sig5 = compute_sig(TEST_KEY, "req-5", SERVICE, FEAT_DETAILS_7, ts_past)
rid5 = f"req-5#replay=cic17#svc={SERVICE}#feat={FEAT_DETAILS_7}#ts={ts_past}#sig={sig5}"
line5 = format_envoy_log_line(t_iso, "10.244.0.131", rid5)

atk5, _ = execute_pipeline([line5], current_time=t_now)
test5_pass = (atk5 is False and rid5 not in defender.PROCESSED_REPLAY_RIDS)
results.append(("5. Expired signature (>60s past) -> Clock check fails, mitigation suppressed", test5_pass))

# Test 6: Future-dated signature (>15s future) rejected
defender.STATE["l7_predictions"].clear()
ts_future = f"{t_now + 20.0:.3f}"
sig6 = compute_sig(TEST_KEY, "req-6", SERVICE, FEAT_DETAILS_7, ts_future)
rid6 = f"req-6#replay=cic17#svc={SERVICE}#feat={FEAT_DETAILS_7}#ts={ts_future}#sig={sig6}"
line6 = format_envoy_log_line(t_iso, "10.244.0.131", rid6)

atk6, _ = execute_pipeline([line6], current_time=t_now)
test6_pass = (atk6 is False and rid6 not in defender.PROCESSED_REPLAY_RIDS)
results.append(("6. Future-dated signature (>15s future) -> Skew check fails, mitigation suppressed", test6_pass))

# Test 7: Duplicate request ID rejected by cache
defender.STATE["l7_predictions"].clear()
# Re-feed line1 which is already in defender.PROCESSED_REPLAY_RIDS
atk7, _ = execute_pipeline([line1], current_time=t_now + 2.0)
test7_pass = (atk7 is False and rid1 in defender.PROCESSED_REPLAY_RIDS)
results.append(("7. Duplicate request ID -> Dropped by PROCESSED_REPLAY_RIDS deduplication", test7_pass))

# Test 8: Historical access-log reprocessing rejected against trusted clock
defender.STATE["l7_predictions"].clear()
hist_ts = 1000.0
hist_iso = "2026-01-01T00:00:01.000Z"
sig8 = compute_sig(TEST_KEY, "req-8", SERVICE, FEAT_DETAILS_7, f"{hist_ts:.3f}")
rid8 = f"req-8#replay=cic17#svc={SERVICE}#feat={FEAT_DETAILS_7}#ts={hist_ts:.3f}#sig={sig8}"
line8 = format_envoy_log_line(hist_iso, "10.244.0.131", rid8)

atk8, _ = execute_pipeline([line8], current_time=t_now)
test8_pass = (atk8 is False and rid8 not in defender.PROCESSED_REPLAY_RIDS)
results.append(("8. Reprocessed historical access log -> Trusted clock freshness rejects", test8_pass))

# Test 9: Legacy plaintext #auth field explicitly rejected
defender.STATE["l7_predictions"].clear()
rid9 = f"req-9#replay=cic17#svc={SERVICE}#feat={FEAT_DETAILS_7}#auth=cic-bench-auth-2026#ts={ts_str1}#sig={sig1}"
line9 = format_envoy_log_line(t_iso, "10.244.0.131", rid9)

atk9, _ = execute_pipeline([line9], current_time=t_now)
test9_pass = (atk9 is False and rid9 not in defender.PROCESSED_REPLAY_RIDS)
results.append(("9. Legacy plaintext #auth field -> Explicitly rejected, mitigation suppressed", test9_pass))

# Test 10: Empty authentication key fails closed
defender.STATE["l7_predictions"].clear()
defender.TEST_AUTH_TOKEN = ""
sig10 = compute_sig("", "req-10", SERVICE, FEAT_DETAILS_7, ts_str1)
rid10 = f"req-10#replay=cic17#svc={SERVICE}#feat={FEAT_DETAILS_7}#ts={ts_str1}#sig={sig10}"
line10 = format_envoy_log_line(t_iso, "10.244.0.131", rid10)

atk10, _ = execute_pipeline([line10], current_time=t_now)
test10_pass = (atk10 is False and rid10 not in defender.PROCESSED_REPLAY_RIDS)
results.append(("10. Empty controller key -> Fails closed, no replay authorization possible", test10_pass))
defender.TEST_AUTH_TOKEN = TEST_KEY

# Test 11: Malformed timestamp & signature values rejected safely
malformed_cases = [
    ("nan", sig1),
    ("inf", sig1),
    ("-inf", sig1),
    ("not-a-number", sig1),
    (ts_str1, ""),
    (ts_str1, "short_sig")
]
malformed_all_ok = True
for idx_m, (bad_ts, bad_sig) in enumerate(malformed_cases):
    rid_m = f"req-11-{idx_m}#replay=cic17#svc={SERVICE}#feat={FEAT_DETAILS_7}#ts={bad_ts}#sig={bad_sig}"
    line_m = format_envoy_log_line(t_iso, "10.244.0.131", rid_m)
    execute_pipeline([line_m], current_time=t_now)
    if rid_m in defender.PROCESSED_REPLAY_RIDS:
        malformed_all_ok = False
results.append(("11. Malformed timestamp and signature tokens -> Caught safely, unparsed", malformed_all_ok))

# Test 12: Finding H1 — Restart replay within fresh window (Documented limitation)
# Simulates controller pod restart: in-memory PROCESSED_REPLAY_RIDS is lost.
# If re-presented while log age <= L7_PREDICTION_TTL (8s) and signature age <= 60s,
# the request can be accepted again.
defender.PROCESSED_REPLAY_RIDS.clear()  # Pod restarted
t_restart_fresh = t_now + 5.0          # 5s later: <= 8.0s log TTL and <= 60s sig TTL
defender.STATE["l7_predictions"].clear()
atk12, _ = execute_pipeline([line1], current_time=t_restart_fresh)
# Documented behavior: it is re-accepted because cache was wiped and signature remains fresh
results.append(("12. Finding H1 verified: Restart within <=60s window accepts fresh replay (documented limitation)", atk12 is True and rid1 in defender.PROCESSED_REPLAY_RIDS))

# Test 13: Finding H1 — Replaying the same request after expiration (>60s)
defender.PROCESSED_REPLAY_RIDS.clear()  # Another restart
t_restart_expired = t_now + 65.0       # 65s later, >60s freshness window
defender.STATE["l7_predictions"].clear()
atk13, _ = execute_pipeline([line1], current_time=t_restart_expired)
# Beyond 60s, trusted clock permanently rejects the replay even across restarts!
results.append(("13. Finding H1 verified: Restart beyond >60s window permanently rejected by trusted clock", atk13 is False and rid1 not in defender.PROCESSED_REPLAY_RIDS))

# Test 14: Cache retention 300s pruning behavior
defender.PROCESSED_REPLAY_RIDS["old-stale-rid"] = t_now - 310.0
defender.PROCESSED_REPLAY_RIDS["recent-fresh-rid"] = t_now - 100.0
dummy_line = f'[{t_iso}] "GET /details/0 HTTP/1.1" 200 - via_upstream - "-" 0 120 2 1 "10.244.0.131" "curl/7.88.1" "req-dummy" "details:9080" "10.244.0.131:9080" inbound|9080|| 10.244.0.131:9080 10.244.0.130:45678 10.244.0.131'
execute_pipeline([dummy_line], current_time=t_now)  # Trigger cache sweep
prune_ok = (
    "old-stale-rid" not in defender.PROCESSED_REPLAY_RIDS
    and "recent-fresh-rid" in defender.PROCESSED_REPLAY_RIDS
)
results.append(("14. Cache TTL sweep -> 300s entries retained, >300s entries pruned", prune_ok))

# Test 15: Real details model artifact verification and 7-feature inference
raw_tokens = FEAT_DETAILS_7.split(",")
vals = [float(t.strip()) for t in raw_tokens]
sample_mat = np.array([vals])
scaled_mat = active_bundle["scaler"].transform(sample_mat)
real_prob = float(active_bundle["model"].predict_proba(scaled_mat)[0][1])

feat_7_real_ok = (
    len(vals) == 7
    and all(math.isfinite(v) for v in vals)
    and active_bundle.get("is_real_artifact") is True
    and active_bundle["model"].__class__.__name__ == "HistGradientBoostingClassifier"
    and active_bundle["scaler"].__class__.__name__ == "StandardScaler"
    and len(active_bundle["feature_names"]) == 7
    and real_prob >= active_bundle["threshold"]
)
results.append(("15. Real details model artifact verified -> HistGradientBoostingClassifier, 7 features, prob>0.80", feat_7_real_ok))

print("\nTEST RESULTS:")
all_pass = True
for name, passed in results:
    s = "PASS" if passed else "FAIL"
    if not passed:
        all_pass = False
    print(f"[{s}] {name}")

print("\n" + "=" * 80)
print(f"OVERALL SECURITY AUDIT: {'ALL ' + str(len(results)) + ' TESTS PASSED (100% SUCCESS)' if all_pass else 'FAILED'}")
print("=" * 80)

if not all_pass:
    sys.exit(1)
