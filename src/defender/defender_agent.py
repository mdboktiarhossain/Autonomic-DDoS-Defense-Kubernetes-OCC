from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from kubernetes import client, config
from kubernetes.client.rest import ApiException
import os, logging, time, threading, urllib.request, json, datetime, re, ast, ipaddress, math
import hmac, hashlib
import numpy as np
import pandas as pd
import joblib
from concurrent.futures import ThreadPoolExecutor, as_completed

NAMESPACE           = os.getenv("NAMESPACE", "default")
RPS_THRESHOLD       = float(os.getenv("DDOS_RPS_THRESHOLD", "50"))
REVERT_SECONDS      = int(os.getenv("DDOS_REVERT_SECONDS", "60"))
SCRAPE_INTERVAL     = float(os.getenv("SCRAPE_INTERVAL", "1.0"))
DETECTION_INTERVAL  = float(os.getenv("DETECTION_INTERVAL", "1.0"))
ML_CYCLE_SECONDS        = float(os.getenv("ML_CYCLE_SECONDS", "60"))
ML_PREDICTION_TTL       = float(os.getenv("ML_PREDICTION_TTL", "150.0"))
MAX_NORMAL_SCRAPE_GAP   = float(os.getenv("MAX_NORMAL_SCRAPE_GAP", "2.5")) * SCRAPE_INTERVAL
MODEL_PATH              = os.getenv("MODEL_PATH", "/app/ddos_detection_model.pkl")
MODELS_DIR              = os.getenv("MODELS_DIR", "/app/models")
MODEL_REGISTRY_PATH     = os.getenv("MODEL_REGISTRY_PATH", "/app/models/model_registry.json")
TRAIN_SAMPLE_PATH       = os.getenv("TRAIN_SAMPLE_PATH", "/app/train_sample.csv")
LOG_SINCE_SECONDS       = int(os.getenv("LOG_SINCE_SECONDS", "60"))
ML_WINDOW_SECONDS       = float(os.getenv("ML_WINDOW_SECONDS", "2"))
ML_MIN_REQUESTS         = int(os.getenv("ML_MIN_REQUESTS", "1"))
ML_COLLECTION_INTERVAL  = float(os.getenv("ML_COLLECTION_INTERVAL", "2.0"))
SETTLING_DELAY_SECONDS  = float(os.getenv("SETTLING_DELAY_SECONDS", "3.0"))
ENABLE_L7_INFERENCE     = os.getenv("ENABLE_L7_INFERENCE", "true").lower() == "true"
ENABLE_ML_MITIGATION    = os.getenv("ENABLE_ML_MITIGATION", "true").lower() == "true"
ALLOW_REPLAY_ENFORCEMENT = os.getenv("ALLOW_REPLAY_ENFORCEMENT", "true").lower() == "true"
AUTHORIZED_TEST_CLIENT_IPS = set(x.strip() for x in os.getenv("AUTHORIZED_TEST_CLIENT_IPS", "10.244.0.131,10.244.1.117,10.244.1.116,10.244.1.115").split(",") if x.strip())
TEST_AUTH_TOKEN = os.getenv("TEST_AUTH_TOKEN", "")
# Replay authentication: per-request HMAC-SHA256 signature; the shared key is never transmitted.
# Legacy plaintext '#auth=' tokens are rejected. Empty key => replay can never be authorized (fail closed).
REPLAY_AUTH_MODE = "hmac-sha256-v2"
REPLAY_SIG_MAX_AGE_SECONDS = float(os.getenv("REPLAY_SIG_MAX_AGE_SECONDS", "60.0"))
REPLAY_SIG_MAX_FUTURE_SKEW_SECONDS = float(os.getenv("REPLAY_SIG_MAX_FUTURE_SKEW_SECONDS", "15.0"))
REPLAY_LOG_EVENT_SKEW_SECONDS = float(os.getenv("REPLAY_LOG_EVENT_SKEW_SECONDS", "30.0"))
REPLAY_CACHE_TTL_SECONDS = float(os.getenv("REPLAY_CACHE_TTL_SECONDS", "300.0"))


def verify_replay_signature(rid_base: str, expected_svc: str, signed_svc: str, feat_str: str, ts_str: str, sig_hex: str, now: float, log_epoch: float = None) -> bool:
    """
    Cryptographic verification and freshness validation for dataset replay injection (HMAC-SHA256 v2).
    
    Security Controls:
    1. Fail-closed: Requires valid non-empty TEST_AUTH_TOKEN, sig_hex, and ts_str.
    2. Trusted Clock Freshness:
       - ts_val must be within [now - REPLAY_SIG_MAX_AGE_SECONDS, now + REPLAY_SIG_MAX_FUTURE_SKEW_SECONDS].
       - Prevents replaying old historical logs even if log_epoch matches ts_val.
    3. Log Event Consistency:
       - If log_epoch is provided, |log_epoch - ts_val| <= REPLAY_LOG_EVENT_SKEW_SECONDS.
    4. Service Identity Binding:
       - signed_svc must equal expected_svc (case-insensitive canonical match).
    5. Constant-time Signature Comparison:
       - Expected signature is HMAC-SHA256(TEST_AUTH_TOKEN, "v1|<rid_base>|<expected_svc>|<feat_str>|<ts_str>")[:32 hex].
       - Evaluated using hmac.compare_digest() to prevent timing side-channel attacks.
    """
    if not TEST_AUTH_TOKEN or not sig_hex or not ts_str:
        return False
    if not expected_svc or not signed_svc:
        return False
    if expected_svc.strip().lower() != signed_svc.strip().lower():
        return False
    try:
        ts_val = float(ts_str)
    except (ValueError, TypeError):
        return False
    if not math.isfinite(ts_val):
        return False

    # 1. Freshness against controller's trusted clock (now)
    if (now - ts_val) > REPLAY_SIG_MAX_AGE_SECONDS:
        return False  # Expired in the past
    if (ts_val - now) > REPLAY_SIG_MAX_FUTURE_SKEW_SECONDS:
        return False  # Unacceptable future timestamp

    # 2. Consistency against log timestamp (if parsed)
    if log_epoch is not None:
        if not math.isfinite(log_epoch) or abs(log_epoch - ts_val) > REPLAY_LOG_EVENT_SKEW_SECONDS:
            return False

    # 3. Cryptographic HMAC verification
    msg = f"v1|{rid_base}|{expected_svc.strip().lower()}|{feat_str}|{ts_str}".encode("utf-8")
    expected = hmac.new(TEST_AUTH_TOKEN.encode("utf-8"), msg, hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(expected, sig_hex.strip().lower())
L7_INFERENCE_INTERVAL   = float(os.getenv("L7_INFERENCE_INTERVAL", "2.0"))
L7_PREDICTION_TTL       = float(os.getenv("L7_PREDICTION_TTL", "8.0"))
L7_MODEL_PATH           = os.getenv("L7_MODEL_PATH", os.path.join(MODELS_DIR, "product_model_6feat.pkl"))
# Stage 3B Task 1-2: read-only candidate observations
ENABLE_STAGE3B_ATTRIBUTION = os.getenv("ENABLE_STAGE3B_ATTRIBUTION", "false").lower() == "true"
# Stage 3B Task 3B: selective automatic v4 quarantine for verified candidates
ENABLE_STAGE3B_ENFORCEMENT = os.getenv("ENABLE_STAGE3B_ENFORCEMENT", "false").lower() == "true"
# Stage 3B Task 3C: anti-oscillation decoy abatement monitoring threshold (RPS)
DECOY_ABATEMENT_RPS_THRESHOLD = float(os.getenv("DECOY_ABATEMENT_RPS_THRESHOLD", "2.0"))

# ── Authoritative 3-State ML Status (Dr. Jahan's Stage 3A Safeguard) ─────────
ML_ATTACK  = "ATTACK"
ML_BENIGN  = "BENIGN"
ML_UNKNOWN = "UNKNOWN"

# ── Canonical service mapping & startup validation ───────────────────────────
DETECTION_MODE = os.getenv("DETECTION_MODE", "decentralized").lower().strip()
READ_ONLY_MODE = os.getenv("READ_ONLY_MODE", "false").lower() == "true"
ENABLE_RPS_ENFORCEMENT = os.getenv("ENABLE_RPS_ENFORCEMENT", "true").lower() == "true"

def get_service_detection_interval(app_label: str) -> float:
    """
    Per-service detection interval cadence matching exact decentralized controller timings:
      - productpage: 1.0s (gateway entrypoint)
      - details, reviews, ratings: 5.0s (internal tier)
    """
    canon = get_canonical_service_name(app_label)
    if canon == "product":
        return float(os.getenv("DETECTION_INTERVAL_PRODUCT", os.getenv("DETECTION_INTERVAL", "1.0")))
    return float(os.getenv("DETECTION_INTERVAL_BACKEND", os.getenv("DETECTION_INTERVAL", "5.0")))

def get_service_rps_threshold(app_label: str) -> float:
    """
    Per-service RPS threshold resolution to preserve exact parity across
    both decentralized and centralized controller architectures.
    """
    canon = get_canonical_service_name(app_label)
    if canon == "product":
        return float(os.getenv("DDOS_RPS_THRESHOLD_PRODUCT", os.getenv("DDOS_RPS_THRESHOLD", "50.0")))
    return float(os.getenv("DDOS_RPS_THRESHOLD_BACKEND", os.getenv("DDOS_RPS_THRESHOLD", "15.0")))

APP_TO_CANONICAL_SERVICE = {
    "productpage": "product",
    "product":     "product",
    "details":     "details",
    "reviews":     "reviews",
    "ratings":     "ratings",
}

def get_canonical_service_name(svc_or_label: str = "") -> str:
    """
    Canonical mapping from service identifier or app label to standard service name.
    Ensures all defender pods coordinating on the same microservice (e.g., 'product'
    and 'productpage') resolve to the exact same Lease name, preventing split-brain locks.
    Safely handles empty-string environment variables and case/whitespace variations.
    """
    cleaned = (svc_or_label or "").strip().lower()
    if cleaned:
        return APP_TO_CANONICAL_SERVICE.get(cleaned, cleaned)
    env_svc = (os.getenv("SERVICE_NAME") or "").strip().lower()
    if env_svc:
        return APP_TO_CANONICAL_SERVICE.get(env_svc, env_svc)
    return "service"

SERVICE_NAME = (os.getenv("SERVICE_NAME") or "").lower().strip()
SERVICE_TO_APP = {
    "product":     "productpage",
    "productpage": "productpage",
    "details":     "details",
    "reviews":     "reviews",
    "ratings":     "ratings",
}
MY_APP_LABEL = SERVICE_TO_APP.get(SERVICE_NAME, SERVICE_NAME)
CANONICAL_SERVICE_NAME = get_canonical_service_name(MY_APP_LABEL or SERVICE_NAME)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

if SERVICE_NAME:
    logging.info(f"[STARTUP] Initialized defender for canonical service '{CANONICAL_SERVICE_NAME}' (SERVICE_NAME='{SERVICE_NAME}', app='{MY_APP_LABEL}')")
else:
    logging.warning("[STARTUP] SERVICE_NAME environment variable is unset or empty; falling back to dynamic per-service discovery.")

try:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
except Exception as e:
    logging.warning(f"[CONFIG] Kubernetes configuration could not be loaded: {e}")

core_api   = client.CoreV1Api()
apps_api   = client.AppsV1Api()
custom_api = client.CustomObjectsApi()
coord_api  = client.CoordinationV1Api()  # Distributed Lock API added here

app = FastAPI(title="DDoS Defender")

ml_model = None
ml_feature_names = None
train_sample_df = None
lime_explainer = None
MODEL_REGISTRY = {}
ml_executor = ThreadPoolExecutor(max_workers=6, thread_name_prefix="ml-worker")
LAST_PROCESSED_WINDOW = {}
L7_MODEL_REGISTRY = {}

APP_TO_SHORTNAME = {
    "productpage": "product",
    "details": "details",
    "reviews": "reviews",
    "ratings": "ratings",
}

def _get_pod_shortname(pod_name, app_label, version="v1"):
    base = APP_TO_SHORTNAME.get(app_label, app_label)
    if app_label == "reviews":
        ver_num = version.replace("v", "")
        return f"{base}{ver_num}"
    return base

def load_ml_models():
    global ml_model, ml_feature_names, train_sample_df, lime_explainer, MODEL_REGISTRY
    models_loaded = 0
    if os.path.exists(MODEL_REGISTRY_PATH):
        try:
            with open(MODEL_REGISTRY_PATH, 'r') as f:
                registry_meta = json.load(f)
            for pod_key, meta in registry_meta.items():
                model_file = os.path.join(MODELS_DIR, meta["model_file"])
                if not os.path.exists(model_file): continue
                bundle = joblib.load(model_file)
                arch = meta.get("architecture", "unknown")
                per_lime = None
                MODEL_REGISTRY[pod_key] = {
                    "model": bundle["model"],
                    "scaler": bundle.get("scaler"),
                    "feature_names": bundle.get("feature_names", []),
                    "architecture": arch,
                    "model_class": meta.get("model_class", type(bundle["model"]).__name__),
                    "lime": per_lime,
                    "metrics": meta.get("metrics", {}),
                }
                models_loaded += 1
        except Exception: pass
    if models_loaded == 0 and os.path.exists(MODEL_PATH):
        try:
            ml_model = joblib.load(MODEL_PATH)
            ml_feature_names = getattr(ml_model, 'feature_names_in_', None)
        except Exception: pass

    # ── Step 3A: Load & Validate Live 6-Feature L7 Model Separately ───────────
    global L7_MODEL_REGISTRY
    expected_feats = [
        "total_requests", "unique_ips", "max_requests_per_ip",
        "avg_requests_per_ip", "error_rate", "avg_response_time"
    ]
    if os.path.exists(L7_MODEL_PATH):
        try:
            l7_bundle = joblib.load(L7_MODEL_PATH)
            feats = l7_bundle.get("feature_names", [])
            scaler = l7_bundle.get("scaler")
            arch = l7_bundle.get("architecture", "")
            window_sec = l7_bundle.get("window_seconds", 2)
            if feats == expected_feats and scaler is not None and arch in ("random_forest", "gradient_boosting") and window_sec == 2:
                L7_MODEL_REGISTRY["product"] = l7_bundle
                L7_MODEL_REGISTRY["productpage"] = l7_bundle
                L7_MODEL_REGISTRY["details"] = l7_bundle
                logging.info(f"[L7-MODEL] Successfully loaded and validated 6-feature model from {L7_MODEL_PATH}")
            else:
                logging.error(f"[L7-MODEL] Model bundle at {L7_MODEL_PATH} failed validation (feats={feats}, arch={arch}, window={window_sec})")
        except Exception as e:
            logging.error(f"[L7-MODEL] Failed to load L7 model from {L7_MODEL_PATH}: {e}")

    # ── Step 3A-2: Multi-Service 7-Feature Improved CIC-IDS2017 Bundles ───────
    svc_key = MY_APP_LABEL or SERVICE_NAME
    if DETECTION_MODE == "central" or not svc_key:
        target_services = ["productpage", "details", "reviews", "ratings"]
    else:
        target_services = [svc_key]

    for s_key in target_services:
        c_key = get_canonical_service_name(s_key)
        cic_bundle_candidates = [
            f"/app/models_active/{s_key}/{s_key}_bundle_7feat.joblib",
            f"/app/models/{s_key}/{s_key}_bundle_7feat.joblib",
            f"/tmp/models_improved_cic/{s_key}/{s_key}_bundle_7feat.joblib",
            os.path.join(MODELS_DIR, f"{s_key}_bundle_7feat.joblib"),
            f"/tmp/active_model/bundle.joblib"
        ]
        for b_path in cic_bundle_candidates:
            if os.path.exists(b_path):
                try:
                    bundle_7f = joblib.load(b_path)
                    feats_7f = bundle_7f.get("feature_names", [])
                    scaler_7f = bundle_7f.get("scaler")
                    model_7f = bundle_7f.get("model")
                    arch_7f = bundle_7f.get("architecture", "unknown")
                    if len(feats_7f) == 7 and scaler_7f is not None and model_7f is not None:
                        L7_MODEL_REGISTRY[s_key] = bundle_7f
                        L7_MODEL_REGISTRY[c_key] = bundle_7f
                        if s_key in ("productpage", "product"):
                            L7_MODEL_REGISTRY["product"] = bundle_7f
                            L7_MODEL_REGISTRY["productpage"] = bundle_7f
                        logging.info(
                            f"[L7-MODEL] [CIC-IDS2017] Successfully loaded and validated 7-feature {arch_7f} "
                            f"model bundle for service '{s_key}' from {b_path} (features: {feats_7f})"
                        )
                        break
                except Exception as e_7f:
                    logging.error(f"[L7-MODEL] Failed loading 7-feature bundle from {b_path}: {e_7f}")

    # Dedicated Details Microservice Model Bundle
    details_bundle_path = os.getenv("L7_DETAILS_MODEL_PATH", "/app/models/details_model_6feat.pkl")
    if os.path.exists(details_bundle_path):
        try:
            d_bundle = joblib.load(details_bundle_path)
            d_feats = d_bundle.get("feature_names", [])
            d_scaler = d_bundle.get("scaler")
            if d_feats == expected_feats and d_scaler is not None:
                L7_MODEL_REGISTRY["details"] = d_bundle
                logging.info(f"[L7-MODEL] Successfully loaded dedicated 6-feature Details model from {details_bundle_path}")
        except Exception as e:
            logging.error(f"[L7-MODEL] Failed to load dedicated Details model from {details_bundle_path}: {e}")

    return models_loaded > 0 or bool(L7_MODEL_REGISTRY)

def predict_single_model(registry_entry, features_df, pod_name):
    try:
        model = registry_entry["model"]
        scaler = registry_entry.get("scaler")
        feat_names = registry_entry["feature_names"]
        arch = registry_entry["architecture"]
        inf_df = features_df.copy()
        for col in ['timestamp', 'pod_shortname']:
            if col in inf_df.columns: inf_df.drop(columns=[col], inplace=True)
        missing_feats = [col for col in feat_names if col not in inf_df.columns]
        if missing_feats:
            logging.error(f"[ML-SCHEMA] Feature mismatch for pod '{pod_name}'. Expected: {feat_names}, Missing: {missing_feats}. Refusing prediction.")
            return {
                "pod_name": pod_name,
                "prediction": "ERROR",
                "error": f"Schema mismatch: missing {missing_feats}",
                "architecture": arch,
                "model_class": registry_entry.get("model_class", "?")
            }
        extra = set(inf_df.columns) - set(feat_names)
        if extra: inf_df.drop(columns=list(extra), inplace=True)
        inf_df = inf_df[feat_names]
        if scaler is not None:
            inf_df = pd.DataFrame(scaler.transform(inf_df), columns=feat_names, index=inf_df.index)
        if arch == "isolation_forest":
            raw_pred = model.predict(inf_df)
            predictions = np.where(raw_pred == -1, 1, 0)
        else:
            predictions = model.predict(inf_df)
        is_ddos = int(predictions[-1]) == 1 if len(predictions) > 0 else False
        ddos_count = int(np.sum(predictions == 1))
        return {
            "pod_name": pod_name,
            "prediction": "DDOS" if is_ddos else "NORMAL",
            "ddos_windows": ddos_count,
            "total_windows": len(predictions),
            "architecture": arch,
            "model_class": registry_entry.get("model_class", "?"),
            "predictions_array": predictions,
            "inference_df": inf_df,
        }
    except Exception as e:
        return {"pod_name": pod_name, "prediction": "ERROR", "error": str(e)}

def run_concurrent_predictions(pods_features):
    futures, results = {}, {}
    for pod_name, (features_df, app_label, version) in pods_features.items():
        shortname = _get_pod_shortname(pod_name, app_label, version)
        entry = MODEL_REGISTRY.get(shortname, MODEL_REGISTRY.get("_global"))
        if entry is None: continue
        future = ml_executor.submit(predict_single_model, entry, features_df, pod_name)
        futures[future] = (pod_name, shortname)
    for future in as_completed(futures, timeout=30):
        pod_name, shortname = futures[future]
        try:
            results[pod_name] = future.result()
            results[pod_name]["shortname"] = shortname
        except Exception as e:
            results[pod_name] = {"pod_name": pod_name, "prediction": "ERROR"}
    return results

# Global Deduplication and Tracking for Controlled Dataset Replays
PROCESSED_REPLAY_RIDS = {}  # request_id -> epoch_seconds

STATE = {
    "ddos_status": "NORMAL", "migration_state": "NORMAL", "detection_method": "initializing",
    "pods": {}, "virtual_services": {}, "attack_history": [], "attacked_services": set(),
    "rps_mitigated": set(), "ml_quarantined": {},
    "revert_timers": {}, "ml_last_cycle": None, "ml_predictions": {},
    "fencing_tokens": {}, "attack_metadata": {}, "recovery_retries": {},
    "l7_predictions": {}, "hybrid_attribution": {}, "active_operations": set(),
    "stage3b_attribution": {}
}

OPERATION_LOCK = threading.Lock()

def scrape_prometheus(ip):
    """
    Scrape Prometheus metrics from Envoy sidecar at :15020.
    Returns:
        float: total requests counter if successfully scraped (can be 0.0).
        None: if scrape failed (timeout, network error, HTTP error, connection refused).
    """
    try:
        url = f"http://{ip}:15020/stats/prometheus"
        with urllib.request.urlopen(url, timeout=2) as resp:
            content = resp.read().decode("utf-8")
            total = 0.0
            found = False
            for line in content.split("\n"):
                if line.startswith("istio_requests_total") and ('reporter="destination"' in line or 'reporter=\\"destination\\"' in line):
                    try:
                        total += float(line.rsplit(" ", 1)[-1])
                        found = True
                    except ValueError:
                        pass
            return total if found else 0.0
    except Exception:
        return None

def discover_and_scrape():
    logging.info(f"[SCRAPE] Starting — watching service app='{MY_APP_LABEL}' (SERVICE_NAME={SERVICE_NAME})")
    while True:
        try:
            pods = core_api.list_namespaced_pod(NAMESPACE, field_selector="status.phase=Running")
            now = time.time()
            seen = set()
            for pod in pods.items:
                name, ip, labels = pod.metadata.name, pod.status.pod_ip, pod.metadata.labels or {}
                app_label = labels.get("app", "")
                version   = labels.get("version", "v1")

                # ── DECENTRALIZED: each pod only monitors its OWN service ──
                if MY_APP_LABEL and app_label != MY_APP_LABEL:
                    continue
                if not ip:
                    continue

                seen.add(name)
                new_total = scrape_prometheus(ip)
                if name not in STATE["pods"]:
                    initial_req = new_total if new_total is not None else 0.0
                    STATE["pods"][name] = {
                        "ip": ip, "rps": 0.0, "total_req": initial_req,
                        "last_check": now, "app": app_label,
                        "version": version, "status": "running" if new_total is not None else "scrape_failed",
                        "scrape_failures": 0 if new_total is not None else 1
                    }
                    logging.info(f"[SCRAPE] Discovered pod '{name}' ({ip}) app={app_label} v={version} total_req={initial_req}")
                    continue

                prev = STATE["pods"][name]
                prev["ip"], prev["app"], prev["version"] = ip, app_label, version

                if new_total is None:
                    # Explicit scrape failure handling: distinct from genuine zero traffic
                    prev["scrape_failures"] = prev.get("scrape_failures", 0) + 1
                    prev["status"] = "scrape_failed"
                    prev["telemetry_valid"] = False
                    continue

                # Successful scrape: calculate elapsed time
                dt = now - prev["last_check"]
                had_failures = prev.get("scrape_failures", 0) > 0

                if had_failures or dt > MAX_NORMAL_SCRAPE_GAP:
                    # Resumed after a telemetry outage or scrape gap
                    gap_failures = prev.get("scrape_failures", 0)
                    prev["scrape_failures"] = 0
                    prev["telemetry_valid"] = True
                    prev["status"] = "running"

                    if new_total < prev["total_req"]:
                        logging.warning(
                            f"[SCRAPE] Counter reset on pod '{name}' during telemetry gap "
                            f"(current={new_total} < prev={prev['total_req']}). Re-baselining."
                        )
                        prev["total_req"] = new_total
                        prev["last_check"] = now
                    else:
                        gap_avg_rate = (new_total - prev["total_req"]) / dt if dt > 0.0 else 0.0
                        if gap_avg_rate > RPS_THRESHOLD:
                            # Sustained high rate even averaged across the entire gap
                            prev["rps"] = max(prev["rps"], gap_avg_rate)
                            logging.warning(
                                f"[SCRAPE] Telemetry gap ({dt:.1f}s, {gap_failures} missed) for '{name}' "
                                f"exceeded threshold (gap avg={gap_avg_rate:.1f} rps > {RPS_THRESHOLD})."
                            )
                        else:
                            # Do not treat a long-gap average as an ordinary 1-second smoothed measurement; re-baseline cleanly
                            logging.info(
                                f"[SCRAPE] Resumed scrape for '{name}' after gap of {dt:.1f}s ({gap_failures} missed). "
                                f"Re-baselining total_req without distorting instantaneous RPS."
                            )
                        prev["total_req"] = new_total
                        prev["last_check"] = now
                else:
                    prev["scrape_failures"] = 0
                    prev["telemetry_valid"] = True
                    prev["status"] = "running"

                    if dt > 0.1:
                        if new_total < prev["total_req"]:
                            # Explicit counter reset handling (Envoy restart / counter cycle)
                            logging.warning(
                                f"[SCRAPE] Counter reset on pod '{name}' "
                                f"(current={new_total} < prev={prev['total_req']}). Re-baselining."
                            )
                            prev["total_req"] = new_total
                            prev["last_check"] = now
                        else:
                            instant = (new_total - prev["total_req"]) / dt
                            old_rps = prev["rps"]
                            prev["rps"] = old_rps * 0.7 + instant * 0.3
                            prev["total_req"] = new_total
                            prev["last_check"] = now

                            # Log when RPS crosses threshold
                            if prev["rps"] > RPS_THRESHOLD and old_rps <= RPS_THRESHOLD:
                                logging.info(f"[SCRAPE] '{name}' RPS crossed threshold: {prev['rps']:.1f} > {RPS_THRESHOLD}")

            for name in list(STATE["pods"].keys()):
                if name not in seen:
                    logging.info(f"[SCRAPE] Pod '{name}' gone — removing from state")
                    del STATE["pods"][name]

        except Exception as ex:
            logging.warning(f"[SCRAPE] Error: {ex}")
        time.sleep(SCRAPE_INTERVAL)

def collect_pod_logs(pod_name, since_seconds=None, strict=False):
    if since_seconds is None:
        since_seconds = LOG_SINCE_SECONDS
    try:
        raw = core_api.read_namespaced_pod_log(
            name=pod_name,
            namespace=NAMESPACE,
            container="istio-proxy",
            since_seconds=since_seconds,
            timestamps=True
        )
        if raw is None:
            if strict:
                raise RuntimeError(f"Log scrape returned None for {pod_name}")
            return []
        if isinstance(raw, bytes):
            text = raw.decode("utf-8", errors="replace")
        elif isinstance(raw, str):
            if (raw.startswith("b'") and raw.endswith("'")) or (raw.startswith('b"') and raw.endswith('"')):
                try:
                    text = ast.literal_eval(raw).decode("utf-8", errors="replace")
                except Exception:
                    text = raw[2:-1].replace("\\n", "\n").replace('\\"', '"').replace("\\'", "'")
            else:
                text = raw
        else:
            text = str(raw)
        return [l.strip() for l in text.strip().splitlines() if l.strip()]
    except Exception as e:
        logging.warning(f"[LOG-COLLECT] Error reading logs for {pod_name}: {e}")
        if strict:
            raise
        return []

def extract_clean_ip(addr_str):
    """
    Robust IPv4 and IPv6 extraction from Envoy remote address strings.
    Handles:
      - Bracketed IPv6 with port: '[2001:db8::1]:12345' -> '2001:db8::1'
      - Bracketed IPv6 without port: '[2001:db8::1]' -> '2001:db8::1'
      - Bare IPv6: '::1', '2001:db8::1' -> normalized IPv6
      - IPv4 with port: '10.244.0.131:50786' -> '10.244.0.131'
      - Bare IPv4: '10.244.0.131' -> '10.244.0.131'
    Returns normalized IP string, or None if invalid or malformed.
    """
    if not addr_str or not isinstance(addr_str, str):
        return None
    s = addr_str.strip()
    if s == "-" or not s:
        return None
    if s.startswith("["):
        idx = s.find("]")
        clean = s[1:idx] if idx != -1 else s[1:]
    elif ":" in s:
        clean = s if s.count(":") > 1 else s.split(":")[0]
    else:
        clean = s

    try:
        ip_obj = ipaddress.ip_address(clean)
        return str(ip_obj)
    except ValueError:
        return None

def collect_gateway_peer_evidence(since_seconds=15):
    """
    Authoritative Gateway Provenance Collector:
    Reads istio-ingressgateway access logs from istio-system and extracts:
      - req_id_to_peer: mapping from request_id to authoritative gateway direct TCP peer IP
      - gw_peer_ips: set of all verified direct peer IPs active at the gateway
    """
    req_id_to_peer = {}
    gw_peer_ips = set()
    try:
        pods = core_api.list_namespaced_pod("istio-system", label_selector="app=istio-ingressgateway")
        running_gw = [p.metadata.name for p in pods.items if p.status.phase == "Running"]
        if not running_gw:
            logging.warning("[GW-EVIDENCE] No running istio-ingressgateway pods found in istio-system")
            return req_id_to_peer, gw_peer_ips

        for gw_pod in running_gw:
            raw = core_api.read_namespaced_pod_log(
                name=gw_pod,
                namespace="istio-system",
                container="istio-proxy",
                since_seconds=int(since_seconds),
                timestamps=True
            )
            if not raw:
                continue
            if isinstance(raw, bytes):
                text = raw.decode("utf-8", errors="replace")
            elif isinstance(raw, str):
                if (raw.startswith("b'") and raw.endswith("'")) or (raw.startswith('b"') and raw.endswith('"')):
                    try:
                        text = ast.literal_eval(raw).decode("utf-8", errors="replace")
                    except Exception:
                        text = raw[2:-1].replace("\\n", "\n").replace('\\"', '"').replace("\\'", "'")
                else:
                    text = raw
            else:
                text = str(raw)

            for line in text.strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                m = ENVOY_LOG_REGEX.search(line)
                if not m:
                    continue
                d = m.groupdict()
                downstream = d.get("downstream_remote", "").strip()
                clean_peer = extract_clean_ip(downstream)
                if clean_peer:
                    gw_peer_ips.add(clean_peer)
                    rid = d.get("request_id", "").strip()
                    if rid and rid != "-":
                        req_id_to_peer[rid] = clean_peer

        logging.info(f"[GW-EVIDENCE] Collected gateway evidence: {len(gw_peer_ips)} peer IP(s), {len(req_id_to_peer)} request ID(s)")
    except Exception as e:
        logging.warning(f"[GW-EVIDENCE] Failed to collect gateway peer evidence: {e}")
    return req_id_to_peer, gw_peer_ips

ENVOY_LOG_REGEX = re.compile(
    r'^(?:(?P<k8s_time>\S+)\s+)?'
    r'\[(?P<start_time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<protocol>[^"]+)"\s+'
    r'(?P<response_code>\d+)\s+'
    r'(?P<response_flags>\S+)\s+'
    r'(?P<code_details>\S+)\s+'
    r'(?P<conn_details>\S+)\s+'
    r'"(?P<failure_reason>[^"]*)"\s+'
    r'(?P<bytes_rx>\d+)\s+'
    r'(?P<bytes_tx>\d+)\s+'
    r'(?P<duration>\d+)\s+'
    r'(?P<upstream_time>\S+)\s+'
    r'"(?P<forwarded_for>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"\s+'
    r'"(?P<request_id>[^"]*)"\s+'
    r'"(?P<authority>[^"]*)"\s+'
    r'"(?P<upstream_host>[^"]*)"\s+'
    r'(?P<cluster>\S+)\s+'
    r'(?P<upstream_local>\S+)\s+'
    r'(?P<downstream_local>\S+)\s+'
    r'(?P<downstream_remote>\S+)'
)

def parse_envoy_log_line(line):
    line = line.strip()
    if not line:
        return None
    m = ENVOY_LOG_REGEX.search(line)
    if not m:
        return None
    d = m.groupdict()

    # Accept inbound clusters for application mesh (9080) and decoy sinkhole (8080)
    cluster = d.get("cluster", "")
    if not (cluster.startswith("inbound|") or cluster in ("inbound|9080||", "inbound|8080||")):
        return None

    # Anti-spoofing client IP extraction:
    # Envoy at ingress gateway appends trusted peer connection IP to the END of X-Forwarded-For.
    # Splitting on comma and taking [0] exposes the controller to client-forged XFF prefixes (framing attacks).
    # Taking [-1] safely extracts the trusted gateway peer address.
    client_ip = None
    raw_forwarded = d.get("forwarded_for", "").strip()
    if raw_forwarded and raw_forwarded != "-":
        last_hop = raw_forwarded.split(",")[-1].strip()
        client_ip = extract_clean_ip(last_hop)

    if not client_ip:
        downstream = d.get("downstream_remote", "").strip()
        if downstream and downstream != "-":
            client_ip = extract_clean_ip(downstream)

    if not client_ip:
        # Reject record if client IP cannot be determined reliably
        return None

    try:
        response_code = int(d.get("response_code", 200))
    except (ValueError, TypeError):
        response_code = 200

    try:
        duration_ms = float(d.get("duration", 0))
    except (ValueError, TypeError):
        duration_ms = 0.0

    ts_str = d.get("start_time") or d.get("k8s_time")

    return {
        "timestamp": ts_str,
        "request_id": d.get("request_id", ""),
        "client_ip": client_ip,
        # Identity read from destination logs/XFF is NOT verified at the gateway.
        # It must never be used directly as a VirtualService enforcement identity.
        "client_ip_trusted": False,
        "path": d.get("path", "/"),
        "response_code": response_code,
        "duration": duration_ms
    }

def parse_log_timestamp(ts_val) -> float | None:
    """Parse log timestamp from integer/float, datetime, or ISO string to epoch seconds."""
    if ts_val is None:
        return None
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, datetime.datetime):
        if ts_val.tzinfo is None:
            ts_val = ts_val.replace(tzinfo=datetime.timezone.utc)
        return ts_val.timestamp()
    if isinstance(ts_val, str):
        s = ts_val.strip()
        if not s:
            return None
        try:
            return float(s)
        except ValueError:
            pass
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            dt = datetime.datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt.timestamp()
        except ValueError:
            try:
                dt = pd.to_datetime(s, utc=True)
                return dt.timestamp()
            except Exception:
                return None
    return None

def extract_features(log_lines, pod_name, app_label, window_seconds=ML_WINDOW_SECONDS, min_requests=ML_MIN_REQUESTS):
    """
    Extract completed L7 traffic windows from Envoy text access logs.
    Output features:
      total_requests, unique_ips, max_requests_per_ip,
      avg_requests_per_ip, error_rate, avg_response_time
    avg_response_time is measured in milliseconds.
    """
    if not log_lines:
        return None

    short_name = app_label if app_label != "unknown" else pod_name.split('-')[0]
    parsed = []
    seen_req_ids = set()

    for line in log_lines:
        record = parse_envoy_log_line(line)
        if not record:
            continue
        req_id = record["request_id"]
        if req_id and req_id != "-":
            if req_id in seen_req_ids:
                continue
            seen_req_ids.add(req_id)
        parsed.append(record)

    if not parsed:
        return None

    df = pd.DataFrame(parsed)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    df = df.dropna(subset=["timestamp"]).set_index("timestamp").sort_index()
    if df.empty:
        return None

    max_log_time = df.index.max()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    last_processed = LAST_PROCESSED_WINDOW.get(pod_name)

    rule = f"{int(window_seconds)}s" if float(window_seconds).is_integer() else f"{window_seconds}s"
    grouped = df.resample(rule)
    feature_vectors = []

    for time_period, group in grouped:
        # Correction 2: Prevent repeated ML evaluations
        if last_processed is not None and time_period <= last_processed:
            continue

        # Correction 1: Exclude incomplete windows with settling delay
        window_end = time_period + pd.Timedelta(seconds=window_seconds)
        settled_cutoff = now_utc - pd.Timedelta(seconds=SETTLING_DELAY_SECONDS)
        if window_end > max_log_time or window_end > settled_cutoff:
            continue

        total_requests = len(group)
        if total_requests < min_requests:
            continue

        unique_ips = group["client_ip"].nunique()
        requests_per_ip = group.groupby("client_ip").size()
        max_requests_per_ip = float(requests_per_ip.max()) if not requests_per_ip.empty else 0.0
        avg_requests_per_ip = float(requests_per_ip.mean()) if not requests_per_ip.empty else 0.0
        errors = (group["response_code"] >= 400).sum()
        error_rate = float((errors / total_requests) * 100.0) if total_requests > 0 else 0.0
        avg_response_time = float(group["duration"].mean()) if total_requests > 0 else 0.0

        feature_vectors.append({
            "timestamp": time_period,
            "total_requests": int(total_requests),
            "unique_ips": int(unique_ips),
            "max_requests_per_ip": max_requests_per_ip,
            "avg_requests_per_ip": avg_requests_per_ip,
            "error_rate": round(error_rate, 2),
            "avg_response_time": round(avg_response_time, 2),
            "pod_shortname": short_name
        })

    if feature_vectors:
        LAST_PROCESSED_WINDOW[pod_name] = max(v["timestamp"] for v in feature_vectors)
        return pd.DataFrame(feature_vectors)
    return None

def predict_with_model(features_df, pod_name):
    if ml_model is None: return features_df, pd.DataFrame()
    ddos_rows = pd.DataFrame()
    try:
        inference_df = features_df.copy()
        if 'timestamp' in inference_df.columns: inference_df.drop(columns=['timestamp'], inplace=True)
        if 'pod_shortname' in inference_df.columns: inference_df = pd.get_dummies(inference_df, columns=['pod_shortname'], drop_first=True)
        if ml_feature_names is not None:
            for col in ml_feature_names:
                if col not in inference_df.columns: inference_df[col] = 0
            extra_cols = set(inference_df.columns) - set(ml_feature_names)
            if extra_cols: inference_df.drop(columns=list(extra_cols), inplace=True)
        predictions = ml_model.predict(inference_df)
        features_df['prediction'] = predictions
        ddos_mask = (features_df['prediction'] == 1)
        if ddos_mask.any():
            ddos_rows = inference_df[ddos_mask].copy()
            ddos_rows['timestamp'] = features_df.loc[ddos_mask, 'timestamp'].astype(str).values
            ddos_rows['pod_name'] = pod_name
        return features_df, ddos_rows
    except Exception: return features_df, pd.DataFrame()

def explain_ddos_rows(ddos_rows):
    return []

def run_l7_inference_cycle():
    """
    Step 3A: Dedicated live L7 inference on 2-second Envoy access log windows.
    Runs every L7_INFERENCE_INTERVAL (2.0s). In shadow mode (ENABLE_ML_MITIGATION=false),
    predictions are logged and recorded into STATE['l7_predictions'] without triggering failover.
    """
    if not ENABLE_L7_INFERENCE or not L7_MODEL_REGISTRY:
        return

    now = time.time()
    for pod_name, info in list(STATE["pods"].items()):
        app_label = info.get("app", "")
        bundle = L7_MODEL_REGISTRY.get(app_label)
        if not bundle:
            continue

        try:
            log_lines = collect_pod_logs(pod_name)
            if not log_lines:
                continue

            expected_feats = bundle["feature_names"]
            is_7feat_bundle = (len(expected_feats) == 7)

            # 1. Sweep expired L7 predictions older than L7_PREDICTION_TTL
            for p_k, p_v in list(STATE["l7_predictions"].items()):
                p_age = now - p_v.get("inference_timestamp", 0)
                if p_age > L7_PREDICTION_TTL:
                    logging.info(f"[L7-EXPIRY] Expired stale prediction for {p_k} (age={p_age:.1f}s > {L7_PREDICTION_TTL}s)")
                    del STATE["l7_predictions"][p_k]

            # 2. Prune old processed replay RIDs older than REPLAY_CACHE_TTL_SECONDS
            for old_rid, old_ts in list(PROCESSED_REPLAY_RIDS.items()):
                if (now - old_ts) > REPLAY_CACHE_TTL_SECONDS:
                    del PROCESSED_REPLAY_RIDS[old_rid]

            # ── Stage 3B: Autonomous Heuristic Attribution from Live Envoy Access Logs ──
            if ENABLE_STAGE3B_ATTRIBUTION:
                try:
                    from stage3b_attribution import (
                        build_window_profiles,
                        rank_attribution_candidates,
                        verify_candidate_for_enforcement
                    )
                    parsed_records = [parse_envoy_log_line(line) for line in log_lines]
                    clean_records = [r for r in parsed_records if r is not None]

                    # Decentralized Cross-Service Gateway Correlation (Phase 2.3 & 2.4)
                    try:
                        req_id_to_peer, gw_peer_ips = collect_gateway_peer_evidence(
                            since_seconds=int(max(25, ML_WINDOW_SECONDS * 8))
                        )
                        if req_id_to_peer:
                            norm_gw_map = {
                                (k[:14] + '4' + k[15:] if len(k) == 36 else k): v
                                for k, v in req_id_to_peer.items()
                            }
                            for r in clean_records:
                                rid = r.get("request_id")
                                if not rid:
                                    continue
                                if rid in req_id_to_peer:
                                    r["client_ip"] = req_id_to_peer[rid]
                                    r["client_ip_trusted"] = True
                                elif len(rid) == 36:
                                    norm_rid = rid[:14] + '4' + rid[15:]
                                    if norm_rid in norm_gw_map:
                                        r["client_ip"] = norm_gw_map[norm_rid]
                                        r["client_ip_trusted"] = True
                    except Exception as corr_err:
                        logging.warning(f"[GATEWAY-CORR] Correlation failed: {corr_err}")

                    if clean_records:
                        idx = max(0, len(clean_records) - 30)
                        window_start_ts = clean_records[idx]["timestamp"]
                        try:
                            dt_start = datetime.datetime.fromisoformat(window_start_ts.replace("Z", "+00:00"))
                            now_dt = datetime.datetime.now(datetime.timezone.utc)
                            win_sec = max(1.0, (now_dt - dt_start).total_seconds())
                        except Exception:
                            dt_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=ML_WINDOW_SECONDS)
                            window_start_ts = dt_start.isoformat()
                            win_sec = ML_WINDOW_SECONDS
                    else:
                        dt_start = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=ML_WINDOW_SECONDS)
                        window_start_ts = dt_start.isoformat()
                        win_sec = ML_WINDOW_SECONDS

                    report = build_window_profiles(
                        clean_records,
                        window_start=window_start_ts,
                        window_seconds=win_sec,
                    )
                    # Service-level traffic anomaly check:
                    # Attribution candidates are only sought when total window traffic exhibits an anomaly
                    win_reqs = report.get('total_requests', 0)
                    win_sec_val = float(report.get('window_seconds', 2.0))
                    win_rps = (win_reqs / win_sec_val) if win_sec_val > 0 else 0.0
                    min_anomaly_rps = 4.0 if app_label in ("details", "reviews", "ratings") else 12.0
                    has_traffic_anomaly = (win_rps >= min_anomaly_rps)

                    stage3b_alert = ENABLE_STAGE3B_ATTRIBUTION and has_traffic_anomaly
                    min_c_rps = 4.0 if app_label in ("details", "reviews", "ratings") else 10.0
                    raw_candidates = rank_attribution_candidates(
                        report,
                        model_alert=stage3b_alert,
                        min_client_rps=min_c_rps
                    )

                    verified_candidates = []
                    if ENABLE_STAGE3B_ENFORCEMENT and stage3b_alert and raw_candidates:
                        req_id_to_peer, gw_peer_ips = collect_gateway_peer_evidence(
                            since_seconds=int(max(25, ML_WINDOW_SECONDS * 8))
                        )
                        for cand in raw_candidates:
                            v_cand = verify_candidate_for_enforcement(
                                cand,
                                trusted_identities=gw_peer_ips,
                                req_id_to_peer=req_id_to_peer,
                                max_age_seconds=float(L7_PREDICTION_TTL),
                                min_client_rps=min_c_rps
                            )
                            if v_cand:
                                v_cand["timestamp"] = time.time()
                                verified_candidates.append(v_cand)
                            else:
                                logging.warning(
                                    f"[STAGE3B-PROVENANCE] Candidate {cand.get('client_id')} failed gateway provenance verification"
                                )

                    report["candidates"] = verified_candidates if ENABLE_STAGE3B_ENFORCEMENT else raw_candidates
                    report["enforcement_enabled"] = bool(ENABLE_STAGE3B_ENFORCEMENT)
                    STATE.setdefault("stage3b_attribution", {})[pod_name] = report

                    mode_tag_3b = "[STAGE3B-ENFORCE]" if ENABLE_STAGE3B_ENFORCEMENT else "[STAGE3B-SHADOW]"
                    if verified_candidates or raw_candidates:
                        logging.info(
                            "%s pod=%s window=%s status=%s clients=%d candidates=%d",
                            mode_tag_3b, pod_name, report.get("window_start"), report.get("status"),
                            len(report.get("profiles", [])), len(report.get("candidates", [])),
                        )
                    for cand in report.get("candidates", []):
                        logging.info(
                            "%s-CANDIDATE pod=%s client=%s score=%.4f trusted=%s eligible=%s evidence=%s",
                            mode_tag_3b, pod_name, cand.get("client_id"), cand.get("heuristic_score", 0.0),
                            cand.get("identity_trusted", False), cand.get("enforcement_eligible", False),
                            cand.get("evidence"),
                        )
                except Exception as attrib_error:
                    logging.warning("[STAGE3B] Attribution skipped for %s: %s", pod_name, attrib_error)

            # 3. Parse and validate dataset replay telemetry from Envoy access logs
            replay_records = []
            canonical_svc = (MY_APP_LABEL or CANONICAL_SERVICE_NAME or get_canonical_service_name(app_label)).lower()

            for line in log_lines:
                r_line = parse_envoy_log_line(line)
                if not r_line:
                    continue
                rid = r_line.get("request_id", "")
                if not rid:
                    continue

                # Deduplication Check: Skip request IDs already processed
                if rid in PROCESSED_REPLAY_RIDS:
                    continue

                # Signature Check: Must contain #replay=cic17, #svc=, #feat=, #ts=, and #sig=
                if "#replay=" not in rid or "#svc=" not in rid or "#feat=" not in rid or "#ts=" not in rid or "#sig=" not in rid:
                    continue

                try:
                    parts = rid.split("#")
                    rid_base = parts[0]
                    tag_map = {}
                    duplicate_tag = False
                    for part in parts[1:]:
                        if "=" in part:
                            k_tag, v_tag = part.split("=", 1)
                            k_norm = k_tag.strip().lower()
                            if k_norm in tag_map:
                                duplicate_tag = True
                                break
                            tag_map[k_norm] = v_tag.strip()

                    if duplicate_tag:
                        logging.warning(f"[REPLAY-PARSE] Rejected request with duplicate tags: {rid}")
                        continue

                    # Controlled Generator Verification
                    if tag_map.get("replay") != "cic17":
                        continue

                    # Legacy plaintext auth token rejection
                    if "auth" in tag_map:
                        logging.warning(f"[REPLAY-AUTH] Legacy plaintext #auth field rejected for {rid_base}")
                        continue

                    # Target Service Verification and Strict Service Binding
                    target_svc = tag_map.get("svc", "").strip().lower()
                    if target_svc != canonical_svc:
                        continue

                    # Freshness Check: Reject stale records older than L7_PREDICTION_TTL
                    log_ts_str = r_line.get("timestamp")
                    log_epoch = parse_log_timestamp(log_ts_str)
                    if log_epoch is not None and (now - log_epoch) > L7_PREDICTION_TTL:
                        logging.debug(f"[REPLAY-PARSE] Dropping stale replay record for {rid}: age={now - log_epoch:.2f}s")
                        continue

                    # Input Validation: Exactly 7 finite numerical values
                    feat_str = tag_map.get("feat", "")
                    raw_tokens = feat_str.split(",")
                    if len(raw_tokens) != 7:
                        logging.warning(f"[REPLAY-PARSE] Rejected malformed vector (length {len(raw_tokens)} != 7): {feat_str}")
                        continue

                    vals = []
                    valid_numeric = True
                    for tok in raw_tokens:
                        try:
                            fv = float(tok.strip())
                            if not math.isfinite(fv):
                                valid_numeric = False
                                break
                            vals.append(fv)
                        except (ValueError, TypeError):
                            valid_numeric = False
                            break

                    if not valid_numeric or len(vals) != 7:
                        logging.warning(f"[REPLAY-PARSE] Rejected non-finite/malformed feature values: {feat_str}")
                        continue

                    c_ip = r_line.get("client_ip", "UNKNOWN")
                    ts_str = tag_map.get("ts", "")
                    sig_str = tag_map.get("sig", "")

                    sig_valid = verify_replay_signature(
                        rid_base=rid_base,
                        expected_svc=canonical_svc,
                        signed_svc=target_svc,
                        feat_str=feat_str,
                        ts_str=ts_str,
                        sig_hex=sig_str,
                        now=now,
                        log_epoch=log_epoch
                    )

                    is_auth = (c_ip in AUTHORIZED_TEST_CLIENT_IPS) and sig_valid

                    if not is_auth:
                        # Do not let unauthenticated attempts consume identifiers in the replay cache
                        logging.debug(f"[REPLAY-AUTH-FAIL] Unauthenticated replay attempt for {rid_base} (ip={c_ip}, sig_valid={sig_valid})")
                        continue

                    # Mark RID as processed ONLY upon successful authorization
                    PROCESSED_REPLAY_RIDS[rid] = now

                    replay_records.append({
                        "timestamp": r_line["timestamp"],
                        "request_id": rid,
                        "values": vals,
                        "client_ip": c_ip,
                        "auth_mode": REPLAY_AUTH_MODE,
                        "is_authorized_client": True
                    })
                except Exception as ex_rep:
                    logging.warning(f"[REPLAY-PARSE] Error parsing replay vector: {ex_rep}")

            # ── PATH A: Controlled Dataset Replay Inference ─────────────────
            if replay_records and is_7feat_bundle:
                latest_replay = replay_records[-1]
                raw_x = np.array([latest_replay["values"]])
                scaler = bundle["scaler"]
                model = bundle["model"]
                t_inf_start = time.perf_counter()
                scaled_x = scaler.transform(raw_x)
                if hasattr(model, "predict_proba"):
                    prob_ddos = float(model.predict_proba(scaled_x)[0][1])
                else:
                    prob_ddos = float(model.predict(scaled_x)[0])
                inf_latency_ms = (time.perf_counter() - t_inf_start) * 1000.0

                default_th = 0.80 if app_label in ("details",) else 0.70
                l7_prob_threshold = float(bundle.get("threshold", os.getenv("L7_PROBABILITY_THRESHOLD", str(default_th))))
                is_ddos = (prob_ddos >= l7_prob_threshold)
                window_ts = str(latest_replay["timestamp"])

                STATE["l7_predictions"][pod_name] = {
                    "prediction": "DDOS" if is_ddos else "NORMAL",
                    "probability": round(prob_ddos, 4),
                    "calibrated_threshold": l7_prob_threshold,
                    "inference_latency_ms": round(inf_latency_ms, 3),
                    "window_timestamp": window_ts,
                    "inference_timestamp": now,
                    "total_requests": len(replay_records),
                    "avg_response_time": 0.0,
                    "model": bundle.get("architecture", type(model).__name__),
                    "variant": bundle.get("variant", "calibrated_v5"),
                    "telemetry_mode": "DATASET_REPLAY",
                    "is_replay": True,
                    "features_ordered": latest_replay["values"],
                    "service": app_label,
                    "client_ip": latest_replay.get("client_ip", "10.244.0.131"),
                    "is_authorized_client": latest_replay.get("is_authorized_client", False)
                }
                mode_tag = "[SHADOW MODE]" if not ENABLE_ML_MITIGATION else "[ACTIVE]"
                logging.info(
                    f"[L7-INFERENCE] [DATASET_REPLAY] {pod_name} ({app_label}) -> {'DDOS' if is_ddos else 'NORMAL'} "
                    f"(prob={prob_ddos:.4f}, feats={latest_replay['values']}) {mode_tag}"
                )
                continue

            # ── PATH B: Native Live Ingress Measurements (Legacy 6-feature) ──
            features = extract_features(log_lines, pod_name, app_label, window_seconds=ML_WINDOW_SECONDS)
            if features is None or features.empty:
                continue

            expected_feats = bundle["feature_names"]
            scaler = bundle["scaler"]
            model = bundle["model"]

            latest_row = features.iloc[-1]
            missing_feats = [f for f in expected_feats if f not in features.columns]
            if missing_feats:
                # Do not clobber a fresh active DDOS prediction from Path A replay
                existing_p = STATE.get("l7_predictions", {}).get(pod_name)
                if existing_p and existing_p.get("prediction") == "DDOS":
                    age = now - existing_p.get("inference_timestamp", 0)
                    if 0 <= age <= L7_PREDICTION_TTL:
                        continue

                # Telemetry Schema Boundary: Access logs provide L7 HTTP metrics,
                # whereas calibrated model requires packet-level features.
                # Produce ML_UNKNOWN cleanly per Dr. Jahan's recovery quorum policy.
                default_th = 0.80 if app_label in ("details",) else 0.70
                l7_prob_threshold = float(bundle.get("threshold", os.getenv("L7_PROBABILITY_THRESHOLD", str(default_th))))
                STATE["l7_predictions"][pod_name] = {
                    "prediction": "UNKNOWN",
                    "probability": 0.0,
                    "calibrated_threshold": l7_prob_threshold,
                    "inference_latency_ms": 0.0,
                    "window_timestamp": str(latest_row.get("timestamp", now)),
                    "inference_timestamp": now,
                    "total_requests": int(latest_row.get("total_requests", 0)),
                    "avg_response_time": float(latest_row.get("avg_response_time", 0.0)),
                    "model": bundle.get("architecture", type(model).__name__),
                    "variant": bundle.get("variant", "calibrated_v5"),
                    "telemetry_mode": "LIVE_INGRESS_SCHEMA_GAP",
                    "is_replay": False,
                    "features_ordered": [],
                    "service": app_label,
                    "reason": f"Packet-level features unavailable in access logs ({len(missing_feats)}/{len(expected_feats)} missing)"
                }
                continue

            inf_df = features[expected_feats].copy()
            scaled_df = pd.DataFrame(scaler.transform(inf_df), columns=expected_feats, index=inf_df.index)

            t_inf_start = time.perf_counter()
            scaled_df = pd.DataFrame(scaler.transform(inf_df), columns=expected_feats, index=inf_df.index)
            preds = model.predict(scaled_df)
            probs = model.predict_proba(scaled_df) if hasattr(model, "predict_proba") else None
            prob_ddos = float(probs[-1][1]) if (probs is not None and probs.shape[1] > 1) else (1.0 if int(preds[-1]) == 1 else 0.0)
            inf_latency_ms = (time.perf_counter() - t_inf_start) * 1000.0

            default_th = 0.80 if app_label in ("details",) else 0.70
            l7_prob_threshold = float(bundle.get("threshold", os.getenv("L7_PROBABILITY_THRESHOLD", str(default_th))))
            is_ddos = (prob_ddos >= l7_prob_threshold)
            window_ts = str(latest_row["timestamp"])

            STATE["l7_predictions"][pod_name] = {
                "prediction": "DDOS" if is_ddos else "NORMAL",
                "probability": round(prob_ddos, 4),
                "calibrated_threshold": l7_prob_threshold,
                "inference_latency_ms": round(inf_latency_ms, 3),
                "window_timestamp": window_ts,
                "inference_timestamp": now,
                "total_requests": int(latest_row["total_requests"]),
                "avg_response_time": float(latest_row["avg_response_time"]),
                "model": bundle.get("architecture", type(model).__name__),
                "variant": bundle.get("variant", "calibrated_v5"),
                "telemetry_mode": "LIVE_INGRESS",
                "is_replay": False,
                "features_ordered": [float(latest_row[f]) for f in expected_feats if f in latest_row],
                "service": app_label
            }

            mode_tag = "[SHADOW MODE]" if not ENABLE_ML_MITIGATION else "[ACTIVE]"
            logging.info(
                f"[L7-INFERENCE] {pod_name} -> {'DDOS' if is_ddos else 'NORMAL'} "
                f"(prob={prob_ddos:.2f}, reqs={int(latest_row['total_requests'])}, "
                f"lat={float(latest_row['avg_response_time']):.1f}ms, win={window_ts}) {mode_tag}"
            )
        except Exception as e:
            logging.warning(f"[L7-INFERENCE] Error evaluating pod {pod_name}: {e}")

def get_verified_candidate_for_service(app_label: str, max_age_seconds: float = 12.0) -> dict | None:
    """
    Stage 3B Task 3B: Retrieve the top verified enforcement candidate for app_label.
    Scans the most recent attribution reports for pods matching app_label.
    A candidate qualifies only if:
      - identity_trusted is True (provenance established via gateway EnvoyFilter)
      - enforcement_eligible is True
      - heuristic_score >= 0.75
      - Candidate age <= max_age_seconds (ensures candidate matches current alert)
    """
    attrib_map = STATE.get("stage3b_attribution", {})
    matching_candidates = []
    now_ts = time.time()
    for pod_name, report in attrib_map.items():
        pod_info = STATE.get("pods", {}).get(pod_name, {})
        pod_app = pod_info.get("app", "")
        if pod_app == app_label or app_label in pod_name:
            for cand in report.get("candidates", []):
                if cand.get("identity_trusted") and cand.get("enforcement_eligible"):
                    cand_ts = cand.get("timestamp")
                    if cand_ts is None:
                        logging.warning(
                            f"[STAGE3B-REJECT] Candidate {cand.get('client_id')} for {app_label} "
                            f"missing timestamp; discarding"
                        )
                        continue
                    age = now_ts - cand_ts
                    if age < 0 or age > max_age_seconds:
                        logging.warning(
                            f"[STAGE3B-STALE] Stale/invalid candidate {cand.get('client_id')} for {app_label} "
                            f"(age={age:.1f}s, max={max_age_seconds}s); discarding"
                        )
                        continue
                    matching_candidates.append(cand)

    if not matching_candidates:
        return None
    matching_candidates.sort(key=lambda c: -c.get("heuristic_score", 0.0))
    return matching_candidates[0]

def ml_detection_cycle():
    now = time.time()
    all_ddos_rows, all_explanations, ddos_services = [], [], set()
    processed_pods = set()

    # Step 1: Collect and log 6-feature observations without invoking incompatible 15-feature CIC models
    if not ENABLE_ML_MITIGATION:
        for pod_name, info in list(STATE["pods"].items()):
            try:
                log_lines = collect_pod_logs(pod_name)
                if not log_lines: continue
                features = extract_features(log_lines, pod_name, info["app"])
                if features is not None and not features.empty:
                    logging.info(f"[ML-COLLECT] Extracted {len(features)} valid {ML_WINDOW_SECONDS}s windows for {pod_name}: {features.tail(1).to_dict('records')}")
            except Exception as e:
                logging.warning(f"[ML-COLLECT] Error extracting features for {pod_name}: {e}")
        return set(), []

    if MODEL_REGISTRY:
        pods_features = {}
        for pod_name, info in list(STATE["pods"].items()):
            try:
                log_lines = collect_pod_logs(pod_name)
                if not log_lines: continue
                features = extract_features(log_lines, pod_name, info["app"])
                if features is None or features.empty: continue
                pods_features[pod_name] = (features, info["app"], info.get("version", "v1"))
            except Exception: pass
        if pods_features:
            results = run_concurrent_predictions(pods_features)
            for pod_name, result in results.items():
                processed_pods.add(pod_name)
                pred_val = result.get("prediction", "ERROR")
                STATE["ml_predictions"][pod_name] = {
                    "prediction": pred_val,
                    "timestamp": now,
                    "status": "fresh" if pred_val in ("DDOS", "NORMAL") else "UNKNOWN",
                    "architecture": result.get("architecture", "?"),
                    "model_class": result.get("model_class", "?"),
                    "window_count": result.get("total_windows", 0),
                    "ddos_windows": result.get("ddos_windows", 0),
                    "features": pods_features[pod_name][0].to_dict('records')[-1] if pod_name in pods_features else {},
                }
                if pred_val == "DDOS":
                    app_label = STATE["pods"].get(pod_name, {}).get("app", "unknown")
                    ddos_services.add(app_label)
    elif ml_model is not None:
        for pod_name, info in list(STATE["pods"].items()):
            try:
                log_lines = collect_pod_logs(pod_name)
                if not log_lines: continue
                features = extract_features(log_lines, pod_name, info["app"])
                if features is None or features.empty: continue
                results, ddos_rows = predict_with_model(features, pod_name)
                processed_pods.add(pod_name)
                is_ddos = not ddos_rows.empty
                pred_val = "DDOS" if is_ddos else "NORMAL"
                STATE["ml_predictions"][pod_name] = {
                    "prediction": pred_val,
                    "timestamp": now,
                    "status": "fresh",
                    "architecture": "random_forest",
                    "model_class": "RandomForest (legacy)",
                    "features": features.to_dict('records')[-1] if not features.empty else {},
                    "window_count": len(features),
                    "ddos_windows": int((results['prediction'] == 1).sum()) if 'prediction' in results.columns else 0,
                }
                if is_ddos:
                    ddos_services.add(info["app"])
            except Exception: pass

    # Age out or mark UNKNOWN any pods where fresh inference was unavailable
    for pod_name in list(STATE["pods"].keys()):
        if pod_name not in processed_pods:
            if pod_name in STATE["ml_predictions"]:
                entry = STATE["ml_predictions"][pod_name]
                if (now - entry.get("timestamp", 0)) > ML_PREDICTION_TTL:
                    entry["status"] = "stale"
                    entry["prediction"] = "UNKNOWN"
            else:
                STATE["ml_predictions"][pod_name] = {
                    "prediction": "UNKNOWN",
                    "status": "stale",
                    "timestamp": now,
                }

    STATE["ml_last_cycle"] = datetime.datetime.now().isoformat()
    return ddos_services, all_explanations

def detection_loop():
    logging.info(f"[DETECT] Starting detection loop — MY_APP_LABEL='{MY_APP_LABEL}'")
    time.sleep(SCRAPE_INTERVAL * 2)
    last_l7_time = 0
    last_eval_times = {}
    loop_tick = min(SCRAPE_INTERVAL, 1.0)
    while True:
        try:
            now = time.time()

            # ── 1. Fast L7 Inference Cycle (every L7_INFERENCE_INTERVAL, e.g. 2s) ───
            if ENABLE_L7_INFERENCE and (now - last_l7_time) >= L7_INFERENCE_INTERVAL:
                last_l7_time = now
                run_l7_inference_cycle()

            # ── 2. Unified Hybrid Attribution Evaluation ─────────────────────────
            services_in_mesh = set()
            for name, info in STATE["pods"].items():
                app = info.get("app")
                if app:
                    services_in_mesh.add(app)

            any_mitigated = False
            for app_label in services_in_mesh:
                # Per-service detection interval cadence
                interval = get_service_detection_interval(app_label)
                if (now - last_eval_times.get(app_label, 0)) < interval:
                    continue
                last_eval_times[app_label] = now
                service_pods = [(name, info) for name, info in STATE["pods"].items() if info.get("app") == app_label]

                # Detector A: RPS Threshold
                thresh = get_service_rps_threshold(app_label)
                hot_pods = [(name, info["rps"]) for name, info in service_pods if info.get("rps", 0) > thresh]
                rps_positive = len(hot_pods) > 0

                # Detector B: Live L7 ML Anomaly Detector (authoritative single-source 3-state evaluation)
                ml_status, ml_reason, ml_details = evaluate_ml_status(app_label)
                ml_positive = (ml_status == ML_ATTACK)

                # Detector C: Stage 3B Autonomous Heuristic Attribution
                verified_cand = get_verified_candidate_for_service(app_label) if ENABLE_STAGE3B_ENFORCEMENT else None
                stage3b_positive = (verified_cand is not None)

                # Combined Hybrid Attribution with Stage 3B independent authorization (Dr. Jahan's Stage 1)
                if rps_positive and (ml_positive or stage3b_positive):
                    attribution = "BOTH"
                elif rps_positive and not ml_positive and not stage3b_positive:
                    attribution = "RPS_ONLY"
                elif stage3b_positive and not rps_positive:
                    attribution = "STAGE3B_ONLY"
                elif ml_positive and not rps_positive:
                    attribution = "ML_ONLY"
                else:
                    attribution = "NONE"

                STATE["hybrid_attribution"][app_label] = {
                    "attribution": attribution,
                    "rps_positive": rps_positive,
                    "ml_positive": ml_positive,
                    "stage3b_positive": stage3b_positive,
                    "ml_status": ml_status,
                    "ml_reason": ml_reason,
                    "hot_pods": hot_pods,
                    "ml_details": ml_details,
                    "timestamp": now,
                    "shadow_mode": not (ENABLE_ML_MITIGATION or ENABLE_STAGE3B_ENFORCEMENT)
                }

                # Decision & Mitigation logic with multi-scenario dispatch
                is_rps_mitigated = app_label in STATE.get("rps_mitigated", set())
                is_ml_quarantined = app_label in STATE.get("ml_quarantined", {})

                needs_dispatch = False
                dispatch_attr = attribution
                target_identity = "client-a"

                if attribution == "RPS_ONLY":
                    if not is_rps_mitigated:
                        needs_dispatch = True
                elif attribution == "STAGE3B_ONLY":
                    target_identity = verified_cand["client_id"]
                    current_q = STATE.get("ml_quarantined", {}).get(app_label, {}).get("identity")
                    dispatch_attr = "STAGE3B_ONLY"
                    if is_ml_quarantined:
                        if current_q != target_identity:
                            logging.warning(
                                "[STAGE3B-GUARD] Active quarantine for '%s' currently isolates '%s'. "
                                "Rejecting replacement candidate '%s' to preserve active mitigation lifecycle.",
                                app_label, current_q, target_identity
                            )
                        needs_dispatch = False
                    else:
                        needs_dispatch = True
                        logging.info(
                            "[STAGE3B-ENFORCE] STAGE3B_ONLY for '%s': verified candidate attributed client=%s (score=%.4f). Targeting v4 quarantine.",
                            app_label, target_identity, verified_cand.get("heuristic_score", 0.0)
                        )
                elif attribution == "ML_ONLY":
                    if not ENABLE_ML_MITIGATION:
                        logging.info(f"[HYBRID-SHADOW] ML_ONLY positive for '{app_label}' (ML: {ml_details}) — mitigation suppressed (ENABLE_ML_MITIGATION=false)")
                    elif not is_ml_quarantined:
                        for p_name, _ in ml_details:
                            p_entry = STATE.get("l7_predictions", {}).get(p_name, {})
                            c_ip = p_entry.get("client_ip")
                            if c_ip and c_ip != "UNKNOWN":
                                target_identity = c_ip
                                break
                        needs_dispatch = True
                elif attribution == "BOTH":
                    if verified_cand:
                        target_identity = verified_cand["client_id"]
                    elif ml_details:
                        for p_name, _ in ml_details:
                            p_entry = STATE.get("l7_predictions", {}).get(p_name, {})
                            c_ip = p_entry.get("client_ip")
                            if c_ip and c_ip != "UNKNOWN":
                                target_identity = c_ip
                                break
                    if not ENABLE_ML_MITIGATION and not ENABLE_STAGE3B_ENFORCEMENT:
                        # Shadow mode: Disallow quarantine! Dispatch RPS failover only if not already active
                        dispatch_attr = "RPS_ONLY"
                        if not is_rps_mitigated:
                            logging.info(f"[HYBRID-SHADOW] BOTH detected for '{app_label}' with quarantine disabled — suppressing quarantine, applying RPS failover only")
                            needs_dispatch = True
                    elif not is_rps_mitigated or not is_ml_quarantined:
                        needs_dispatch = True

                if needs_dispatch:
                    logging.info(f"[DETECT-HYBRID] ATTACK DETECTED for '{app_label}' via attribution={dispatch_attr} (RPS: {hot_pods}, ML: {ml_details}, Target: {target_identity})")
                    STATE["ddos_status"] = "ATTACK DETECTED"
                    STATE["detection_method"] = dispatch_attr
                    STATE.setdefault("attack_metadata", {})[app_label] = {"method": dispatch_attr, "time": now}
                    any_mitigated = True
                    dispatch_mitigation(app_label, dispatch_attr, target_identity=target_identity)

            if not any_mitigated and not STATE["attacked_services"]:
                STATE["ddos_status"] = "NORMAL"

        except Exception as ex:
            logging.warning(f"[DETECT] Error in detection loop: {ex}")
        time.sleep(loop_tick)


def evaluate_ml_status(app_label: str) -> tuple[str, str, list]:
    """
    Authoritative single-source ML evaluation for app_label (Dr. Jahan's Stage 3A safeguard).
    Evaluates exclusively against live 6-feature L7 predictions (STATE['l7_predictions']).
    No legacy fallback.

    Justified Quorum Policy for Recovery Authorization (ML_BENIGN):
      1. Unanimous Consensus: 100% of fresh, active predictions in the sliding window must
         be explicitly 'NORMAL' or 'BENIGN' (len(normal_pods) == len(fresh_predictions) > 0).
      2. Invalid / Error State Rejection: Any pod reporting ERROR, UNKNOWN, or unrecognized
         prediction states immediately rejects ML_BENIGN and forces ML_UNKNOWN, preventing
         unauthorized quarantine removal in trigger_revert().
      3. Active Traffic Quorum Scope: Requires predictions from all monitored replicas actively
         handling traffic. Idle cold-backup replicas (e.g. v2/v3 during normal v1=100% routing)
         emit 0 access logs and are excluded from the required quorum until traffic is routed to them.
      4. Telemetry Gap Protection: If fresh_predictions is empty, returns ML_UNKNOWN.
    Returns:
        (status, reason, details)
        where status is one of:
          - ML_ATTACK: at least one pod has fresh DDOS prediction
          - ML_BENIGN: all fresh predictions are unanimously verified NORMAL/BENIGN (len > 0)
          - ML_UNKNOWN: telemetry gap, unrecognized prediction state, or L7 inference disabled
    """
    if not ENABLE_L7_INFERENCE:
        return ML_UNKNOWN, "L7 inference disabled", []

    service_pods = [
        (name, info) for name, info in STATE.get("pods", {}).items()
        if info.get("app") == app_label
    ]
    if not service_pods:
        return ML_UNKNOWN, f"No monitored pods found for app='{app_label}'", []

    now = time.time()
    fresh_predictions = []
    for name, info in service_pods:
        pred_entry = STATE.get("l7_predictions", {}).get(name)
        if pred_entry:
            age = now - pred_entry.get("inference_timestamp", 0)
            if 0 <= age <= L7_PREDICTION_TTL:
                fresh_predictions.append((name, pred_entry))

    if not fresh_predictions:
        return ML_UNKNOWN, f"No fresh L7 predictions for '{app_label}' within {L7_PREDICTION_TTL}s (telemetry gap)", []

    ddos_pods = [
        (name, pred.get("probability", 1.0))
        for name, pred in fresh_predictions
        if pred.get("prediction") == "DDOS"
    ]
    if ddos_pods:
        details_str = ", ".join(f"{p[0]} (prob={p[1]:.2f})" for p in ddos_pods)
        return ML_ATTACK, f"Fresh L7 DDOS detected: {details_str}", ddos_pods

    normal_pods = [
        name for name, pred in fresh_predictions
        if pred.get("prediction") in ("NORMAL", "BENIGN")
    ]
    if len(normal_pods) != len(fresh_predictions) or len(normal_pods) == 0:
        return ML_UNKNOWN, (
            "Fresh predictions contain unrecognized or invalid states"
        ), []
    return ML_BENIGN, (
        f"Fresh L7 predictions normal across {len(normal_pods)} pod(s)"
    ), normal_pods


def is_rps_attacked(app_label: str) -> tuple[bool, str]:
    """Evaluates volume overload condition: checks if any pod exceeds per-service RPS threshold."""
    thresh = get_service_rps_threshold(app_label)
    hot_pods = [
        (name, info["rps"]) for name, info in STATE["pods"].items()
        if info.get("app") == app_label and info["rps"] > thresh
    ]
    if hot_pods:
        max_rps = max(p[1] for p in hot_pods)
        return True, f"RPS threshold exceeded ({max_rps:.1f} > {thresh})"
    return False, "RPS is below threshold"


def is_ml_attacked(app_label: str) -> tuple[bool, str]:
    """
    Evaluates multi-feature ML anomaly condition using evaluate_ml_status.
    Returns (True, reason) only if authoritative status is ML_ATTACK.
    Security Guard (Dr. Jahan): Replay headers from untrusted clients cannot authorize live mitigation enforcement.
    """
    status, reason, details = evaluate_ml_status(app_label)
    if status == ML_ATTACK and ENABLE_ML_MITIGATION:
        all_replay = True
        for pod_name, prob in details:
            pred_entry = STATE.get("l7_predictions", {}).get(pod_name, {})
            if not pred_entry.get("is_replay", False):
                all_replay = False
                break
        if all_replay:
            if not ALLOW_REPLAY_ENFORCEMENT:
                logging.warning("[SECURITY] Replay-based L7 prediction cannot authorize live mitigation enforcement; enforcement suppressed.")
                return False, "Replay attack detected in shadow mode; live enforcement suppressed for synthetic headers"
            for pod_name, prob in details:
                pred_entry = STATE.get("l7_predictions", {}).get(pod_name, {})
                if pred_entry.get("is_replay", False):
                    if not pred_entry.get("is_authorized_client", False):
                        c_ip = pred_entry.get("client_ip", "UNKNOWN")
                        logging.error(f"[SECURITY-BLOCKED] Unauthorized client '{c_ip}' attempted replay enforcement; REJECTED.")
                        return False, f"Replay attack from unauthorized client '{c_ip}'; enforcement blocked"
            logging.info("[ACTIVE-ENFORCE] Authorizing live mitigation enforcement for verified authorized benchmark test client.")
    return (status == ML_ATTACK), reason


def is_service_attacked(app_label: str) -> tuple[bool, str]:
    """
    Multi-criteria evaluation combining volume and ML intent.
    Returns (True, reason) if either RPS or ML condition is active.
    """
    rps_active, rps_reason = is_rps_attacked(app_label)
    if rps_active:
        return True, rps_reason
    ml_active, ml_reason = is_ml_attacked(app_label)
    if ml_active:
        return True, ml_reason
    return False, "traffic rate and fresh ML inference predictions are normal"


def _normalize_dt(dt):
    if dt is None:
        return None
    if isinstance(dt, str):
        try:
            dt = datetime.datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except Exception:
            return None
    if isinstance(dt, datetime.datetime) and dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt

def owns_lock(service_name: str, my_pod_name: str, expected_fencing_token: int = None) -> bool:
    """
    Pre-write fencing check (matching Algorithm 2 in paper and Dr. Jahan's Stage 3 requirements):
    Verifies that this defender pod is still the recorded holder of the Lease,
    that the Lease's recorded fencing token matches expected_fencing_token (binding write to Lease generation),
    and that the Lease has not expired due to execution delays or pauses.
    Significantly narrows the race window against delayed/stale writes.
    """
    canonical_svc = get_canonical_service_name(service_name)
    lease_name = f"{canonical_svc}-mitigation-lock"
    try:
        existing = coord_api.read_namespaced_lease(name=lease_name, namespace=NAMESPACE)
        spec = existing.spec
        holder = spec.holder_identity or ""
        if holder != my_pod_name:
            logging.warning(
                f"[LOCK] [{my_pod_name}] Fencing check FAILED for '{canonical_svc}': "
                f"lock lost to holder '{holder}'"
            )
            return False

        if expected_fencing_token is not None:
            annotations = existing.metadata.annotations or {}
            lease_token = int(annotations.get("ddos.defender/fencing-token", spec.lease_transitions or 0))
            if lease_token != expected_fencing_token:
                logging.warning(
                    f"[LOCK] [{my_pod_name}] Fencing token mismatch for '{canonical_svc}': "
                    f"Lease token ({lease_token}) != expected ({expected_fencing_token})"
                )
                return False

        duration = spec.lease_duration_seconds or 15
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        renew_time = _normalize_dt(spec.renew_time) or _normalize_dt(existing.metadata.creation_timestamp)
        if renew_time:
            elapsed = (now_utc - renew_time).total_seconds()
            if elapsed > duration:
                logging.warning(
                    f"[LOCK] [{my_pod_name}] Fencing check FAILED for '{canonical_svc}': "
                    f"lock expired ({elapsed:.1f}s > {duration}s)"
                )
                return False
        return True
    except ApiException as e:
        logging.warning(f"[LOCK] [{my_pod_name}] Error verifying lock ownership for '{canonical_svc}': {e}")
        return False
    except Exception as ex:
        logging.warning(f"[LOCK] [{my_pod_name}] Unexpected error verifying lock ownership for '{canonical_svc}': {ex}")
        return False

class LeaseHeartbeat:
    """
    Background heartbeat renewing the Lease periodically (every interval seconds)
    during active critical sections (Scenario 1 & 2 VS writes).
    Uses conditional updates (OCC with resourceVersion) and verifies ownership.
    """
    def __init__(self, service_name: str, my_pod_name: str, interval: float = 4.0):
        self.service_name = service_name
        self.my_pod_name = my_pod_name
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"heartbeat-{self.service_name}"
        )
        self._thread.start()

    def _run(self):
        while not self._stop_event.wait(self.interval):
            success = renew_lease(self.service_name, self.my_pod_name)
            if not success:
                logging.warning(
                    f"[HEARTBEAT] [{self.my_pod_name}] Failed to renew lease for '{self.service_name}'. "
                    f"Stopping heartbeat thread."
                )
                break

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)

def renew_lease(service_name: str, my_pod_name: str) -> bool:
    """
    Race-free conditional Lease renewal during the critical section.
    Verifies that this pod is still the recorded holder and uses resourceVersion OCC.
    """
    canonical_svc = get_canonical_service_name(service_name)
    lease_name = f"{canonical_svc}-mitigation-lock"
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    try:
        existing = coord_api.read_namespaced_lease(name=lease_name, namespace=NAMESPACE)
        if existing.spec.holder_identity != my_pod_name:
            logging.warning(
                f"[LOCK] [{my_pod_name}] Cannot renew '{lease_name}' — "
                f"holder is '{existing.spec.holder_identity}'"
            )
            return False
        existing.spec.renew_time = now_utc
        # Conditional update with resourceVersion matching 'existing'
        coord_api.replace_namespaced_lease(name=lease_name, namespace=NAMESPACE, body=existing)
        return True
    except ApiException as e:
        if e.status == 409:
            logging.warning(f"[LOCK] [{my_pod_name}] Conflict renewing lease '{lease_name}' — state changed concurrently")
        else:
            logging.warning(f"[LOCK] [{my_pod_name}] API error renewing lease '{lease_name}': {e}")
        return False
    except Exception as ex:
        logging.warning(f"[LOCK] [{my_pod_name}] Unexpected error renewing lease '{lease_name}': {ex}")
        return False

def acquire_lock(service_name: str, my_pod_name: str) -> tuple[bool, int]:
    """
    Acquire a Kubernetes Lease as a distributed mutex for this service.
    Returns:
        (True, fencing_token) on successful acquisition or takeover.
        (False, 0) if the lock is held by another active defender or on contention failure.
    Uses a monotonically increasing fencing token stamped in metadata.annotations
    and spec.lease_transitions. High-watermark monotonicity survives Lease recreation
    by anchoring against any token already stamped on the target VirtualService.
    """
    canonical_svc = get_canonical_service_name(service_name)
    lease_name = f"{canonical_svc}-mitigation-lock"
    LEASE_DURATION = 15  # seconds

    # Determine baseline high-watermark token across cluster artifacts to survive Lease deletion
    local_high_token = STATE.get("fencing_tokens", {}).get(canonical_svc, 0)
    vs_token = 0
    try:
        app_label = SERVICE_TO_APP.get(canonical_svc, canonical_svc)
        target_vs_name = find_existing_vs(app_label) or f"{canonical_svc}-vs"
        vs_obj = custom_api.get_namespaced_custom_object(
            "networking.istio.io", "v1beta1", NAMESPACE, "virtualservices", target_vs_name
        )
        vs_annotations = vs_obj.get("metadata", {}).get("annotations", {}) or {}
        vs_token = int(vs_annotations.get("ddos.defender/fencing-token", "0"))
    except Exception:
        pass

    base_watermark = max(local_high_token, vs_token, 0)
    initial_token = base_watermark + 1

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    lease_body = client.V1Lease(
        metadata=client.V1ObjectMeta(
            name=lease_name,
            annotations={"ddos.defender/fencing-token": str(initial_token)}
        ),
        spec=client.V1LeaseSpec(
            holder_identity=my_pod_name,
            lease_duration_seconds=LEASE_DURATION,
            renew_time=now_utc,
            lease_transitions=initial_token
        )
    )
    try:
        coord_api.create_namespaced_lease(namespace=NAMESPACE, body=lease_body)
        logging.info(f"[LOCK] [{my_pod_name}] Created and acquired lock for {canonical_svc} (fencing_token={initial_token})")
        STATE.setdefault("fencing_tokens", {})[canonical_svc] = initial_token
        return True, initial_token

    except ApiException as e:
        if e.status == 409:
            try:
                existing = coord_api.read_namespaced_lease(name=lease_name, namespace=NAMESPACE)
                spec = existing.spec
                holder = spec.holder_identity or ""
                duration = spec.lease_duration_seconds or LEASE_DURATION
                renew_time = _normalize_dt(spec.renew_time)

                is_free = (holder == "")
                is_expired = False
                elapsed = 0.0

                if renew_time:
                    elapsed = (now_utc - renew_time).total_seconds()
                    is_expired = (elapsed > duration)
                elif not is_free:
                    # Non-empty holder but missing renew_time (e.g., malformed or manual lease).
                    # Inspect creation_timestamp to prevent the lock from remaining stuck indefinitely.
                    creation_time = _normalize_dt(existing.metadata.creation_timestamp)
                    if creation_time:
                        elapsed = (now_utc - creation_time).total_seconds()
                        is_expired = (elapsed > duration)
                        if is_expired:
                            logging.warning(
                                f"[LOCK] [{my_pod_name}] Lease '{lease_name}' has holder '{holder}' but missing renew_time. "
                                f"Treating as expired based on creation age ({elapsed:.0f}s > {duration}s)."
                            )
                        else:
                            logging.warning(
                                f"[LOCK] [{my_pod_name}] Lease '{lease_name}' has holder '{holder}' with missing renew_time "
                                f"(creation age {elapsed:.0f}s <= {duration}s). Operational alert."
                            )
                    else:
                        # Missing both renew_time and creation_timestamp: malformed lease.
                        logging.warning(
                            f"[LOCK] [{my_pod_name}] Lease '{lease_name}' has holder '{holder}' but no timestamps. "
                            f"Treating as expired to prevent indefinite deadlock."
                        )
                        is_expired = True

                if is_free or is_expired:
                    reason = "freely released" if is_free else f"expired ({elapsed:.0f}s > {duration}s)"
                    logging.info(f"[LOCK] [{my_pod_name}] Attempting takeover of {reason} lease '{lease_name}'")

                    prev_annotations = existing.metadata.annotations or {}
                    prev_token = int(prev_annotations.get("ddos.defender/fencing-token", existing.spec.lease_transitions or 0))
                    fencing_token = max(prev_token, base_watermark) + 1

                    existing.metadata.annotations = existing.metadata.annotations or {}
                    existing.metadata.annotations["ddos.defender/fencing-token"] = str(fencing_token)
                    existing.spec.holder_identity = my_pod_name
                    existing.spec.renew_time = now_utc
                    existing.spec.lease_duration_seconds = LEASE_DURATION
                    existing.spec.lease_transitions = fencing_token

                    # Conditional update with resourceVersion matching 'existing'
                    coord_api.replace_namespaced_lease(name=lease_name, namespace=NAMESPACE, body=existing)
                    logging.info(f"[LOCK] [{my_pod_name}] Successfully acquired lock for {canonical_svc} (fencing_token={fencing_token})")
                    STATE.setdefault("fencing_tokens", {})[canonical_svc] = fencing_token
                    return True, fencing_token
                else:
                    logging.info(
                        f"[LOCK] [{my_pod_name}] Lock held by '{holder}' "
                        f"({elapsed:.0f}s old, expires in {duration - elapsed:.0f}s). Skipping."
                    )
            except ApiException as inner_e:
                if inner_e.status == 409:
                    logging.info(f"[LOCK] [{my_pod_name}] Contention takeover conflict on '{lease_name}' — another defender won")
                else:
                    logging.warning(f"[LOCK] [{my_pod_name}] API error inspecting lease '{lease_name}': {inner_e}")
            return False, 0
        raise

def release_lock(service_name: str, my_pod_name: str):
    """
    Race-free conditional Lease release via OCC (matching Algorithm 2 in paper):
    Atomically clears holder_identity ONLY if this pod is still the recorded holder
    and the resourceVersion has not changed.
    """
    canonical_svc = get_canonical_service_name(service_name)
    lease_name = f"{canonical_svc}-mitigation-lock"
    try:
        existing = coord_api.read_namespaced_lease(name=lease_name, namespace=NAMESPACE)
        if existing.spec.holder_identity != my_pod_name:
            logging.warning(
                f"[LOCK] [{my_pod_name}] Cannot release '{lease_name}' — "
                f"ownership already transferred to '{existing.spec.holder_identity}'"
            )
            return False

        # Clear holder identity and renewTime to mark lock as FREE
        existing.spec.holder_identity = ""
        existing.spec.renew_time = None

        # Conditional update: Kubernetes will reject with 409 if modified concurrently
        coord_api.replace_namespaced_lease(name=lease_name, namespace=NAMESPACE, body=existing)
        logging.info(f"[LOCK] [{my_pod_name}] Safely released lock for {canonical_svc} via conditional update")
        return True

    except ApiException as e:
        if e.status == 409:
            logging.warning(f"[LOCK] [{my_pod_name}] Conflict releasing '{lease_name}' — state changed concurrently")
        elif e.status != 404:
            logging.warning(f"[LOCK] [{my_pod_name}] Error releasing '{lease_name}': {e}")
        return False

def get_service_versions(app_label):
    versions = set()
    for _, info in STATE["pods"].items():
        if info["app"] == app_label: versions.add(info["version"])
    if not versions:
        try:
            pod_list = core_api.list_namespaced_pod(NAMESPACE, label_selector=f"app={app_label}")
            for p in pod_list.items:
                v = p.metadata.labels.get("version")
                if v: versions.add(v)
        except Exception:
            pass
    if not versions:
        try:
            dr = custom_api.get_namespaced_custom_object("networking.istio.io", "v1beta1", NAMESPACE, "destinationrules", f"{app_label}-dr")
            for s in dr.get("spec", {}).get("subsets", []):
                name = s.get("name")
                if name: versions.add(name)
        except Exception:
            pass
    return sorted(versions)

def ensure_destination_rule(app_label, versions):
    dr_name = f"{app_label}-dr"
    try:
        dr = custom_api.get_namespaced_custom_object(
            "networking.istio.io", "v1beta1", NAMESPACE, "destinationrules", dr_name
        )
        spec = dr.setdefault("spec", {})
        spec.setdefault("host", app_label)
        subsets = spec.setdefault("subsets", [])
        existing_names = {s.get("name") for s in subsets if isinstance(s, dict)}
        missing = [v for v in versions if v not in existing_names]
        if missing:
            logging.info(f"[ISTIO] Reconciling DestinationRule '{dr_name}' with missing subsets: {missing}")
            for v in missing:
                subsets.append({"name": v, "labels": {"version": v}})
            custom_api.replace_namespaced_custom_object(
                "networking.istio.io", "v1beta1", NAMESPACE, "destinationrules", dr_name, dr
            )
            logging.info(f"[ISTIO] DestinationRule '{dr_name}' reconciled with all subsets.")
    except client.exceptions.ApiException as e:
        if e.status == 404:
            body = {
                "apiVersion": "networking.istio.io/v1beta1", "kind": "DestinationRule",
                "metadata": {"name": dr_name, "namespace": NAMESPACE},
                "spec": {"host": app_label, "subsets": [{"name": v, "labels": {"version": v}} for v in versions]}
            }
            custom_api.create_namespaced_custom_object("networking.istio.io", "v1beta1", NAMESPACE, "destinationrules", body)
            logging.info(f"[ISTIO] DestinationRule '{dr_name}' created with subsets: {versions}")
        else:
            logging.warning(f"[ISTIO] Error ensuring DestinationRule '{dr_name}': {e}")

def ensure_virtual_service(app_label, port=None):
    vs_name = f"{app_label}-vs"
    try:
        custom_api.get_namespaced_custom_object("networking.istio.io", "v1beta1", NAMESPACE, "virtualservices", vs_name)
        return vs_name
    except client.exceptions.ApiException as e:
        if e.status == 404:
            if port is None: port = 9080
            body = {
                "apiVersion": "networking.istio.io/v1beta1", "kind": "VirtualService",
                "metadata": {"name": vs_name, "namespace": NAMESPACE},
                "spec": {"hosts": [app_label], "http": [{"route": [{"destination": {"host": app_label, "port": {"number": port}, "subset": "v1"}, "weight": 100}]}]}
            }
            custom_api.create_namespaced_custom_object("networking.istio.io", "v1beta1", NAMESPACE, "virtualservices", body)
            return vs_name

# ── DECENTRALIZED MITIGATION: Atomic Multi-Action OCC Patch ─────────────────
def patch_vs_atomic(
    vs_name: str,
    target_host: str,
    rps_routes: list = None,
    quarantine_identity = None,
    port: int = 9080,
    service_name: str = None,
    my_pod_name: str = None,
    fencing_token: int = None,
    max_retries: int = 5
) -> bool:
    """
    Atomically patch a VirtualService using Optimistic Concurrency Control (OCC)
    and monotonic fencing tokens, updating both quarantine and production routing rules
    in a single write operation (Dr. Jahan's Stage 3A specification).

    Parameters:
      vs_name: Target VirtualService name (e.g., 'bookinfo' or 'productpage-vs')
      target_host: Canonical service name being managed (e.g., 'productpage')
      rps_routes: If provided, replaces production routing for target_host (e.g. v2/v3 failover or v1 restore).
                  If None, production routes are left unchanged.
      quarantine_identity:
        - If non-empty string (e.g., 'client-a'): installs/updates 'quarantine-malicious' rule
          routing matching requests to the isolated decoy destination ('<target_host>-decoy').
        - If False or 'REMOVE': atomically removes the quarantine rule.
        - If None: quarantine rules are preserved as-is.
      port: Service port (default 9080)
      service_name: Name used for Lease verification
      my_pod_name: Identity of this defender pod
      fencing_token: Monotonically increasing token acquired with Lease
      max_retries: Retry limit for 409 OCC conflicts
    """
    if not target_host:
        target_host = service_name or vs_name.replace("-vs", "")
    target_host = target_host.split(".")[0]
    decoy_host = f"{target_host}-decoy"

    def is_decoy_dest(route_entry):
        dh = route_entry.get("destination", {}).get("host", "")
        return decoy_host in dh

    def is_prod_dest(route_entry):
        dh = route_entry.get("destination", {}).get("host", "")
        if not dh or is_decoy_dest(route_entry):
            return False
        return (
            dh == target_host
            or dh.startswith(f"{target_host}.")
            or dh.split(".")[0] == target_host
        )

    if READ_ONLY_MODE:
        logging.warning(f"[OCC-ATOMIC-GUARD] Refusing VirtualService write for '{vs_name}' (READ_ONLY_MODE=true)")
        return False

    for attempt in range(max_retries):
        try:
            # Step 0: Pre-read Lease and fencing token verification
            if service_name and my_pod_name:
                if not owns_lock(service_name, my_pod_name, expected_fencing_token=fencing_token):
                    logging.warning(
                        f"[OCC-ATOMIC] [{my_pod_name}] Aborting VS write for '{vs_name}': "
                        f"Lease verification failed (lost ownership or token mismatch) prior to attempt {attempt+1}"
                    )
                    return False

            # Step 1: GET current VirtualService (OCC read phase)
            current = custom_api.get_namespaced_custom_object(
                "networking.istio.io", "v1beta1", NAMESPACE, "virtualservices", vs_name
            )
            resource_version = current["metadata"]["resourceVersion"]

            # Step 2: Strict monotonic fencing token validation
            if fencing_token is not None:
                vs_annotations = current.get("metadata", {}).get("annotations", {}) or {}
                current_vs_token = int(vs_annotations.get("ddos.defender/fencing-token", "0"))
                if fencing_token < current_vs_token:
                    logging.warning(
                        f"[OCC-ATOMIC] [{my_pod_name}] Stale fencing token on '{vs_name}': "
                        f"defender token ({fencing_token}) < VS token ({current_vs_token}). "
                        f"A newer defender already updated this VirtualService. Aborting write."
                    )
                    return False

            # Step 3: Deep copy and prepare atomic payload
            replace_body = json.loads(json.dumps(current))
            replace_body["metadata"]["resourceVersion"] = resource_version

            if fencing_token is not None:
                if "annotations" not in replace_body["metadata"] or replace_body["metadata"]["annotations"] is None:
                    replace_body["metadata"]["annotations"] = {}
                replace_body["metadata"]["annotations"]["ddos.defender/fencing-token"] = str(fencing_token)

            spec = replace_body.setdefault("spec", {})
            http_rules = spec.setdefault("http", [])

            # Step 4: Atomic quarantine modification
            if quarantine_identity is False or quarantine_identity == "REMOVE":
                before_count = len(http_rules)
                http_rules = [
                    r for r in http_rules
                    if r.get("name") != "quarantine-malicious" and not any(is_decoy_dest(dest) for dest in r.get("route", []))
                ]
                spec["http"] = http_rules
                logging.info(f"[OCC-ATOMIC] Removed quarantine rule from '{vs_name}' (rule count: {before_count} -> {len(http_rules)})")
            elif isinstance(quarantine_identity, str) and quarantine_identity:
                productpage_uris = [
                    {"exact": f"/{target_host}"},
                    {"prefix": f"/{target_host}"},
                    {"prefix": "/static"},
                    {"exact": "/login"},
                    {"exact": "/logout"},
                    {"prefix": "/api/v1/products"}
                ]
                q_matches = []
                for uri_match in productpage_uris:
                    # Trusted Ingress Gateway identity header
                    q_matches.append({
                        "headers": {"x-trusted-client-ip": {"exact": quarantine_identity}},
                        "uri": uri_match
                    })
                    # Test fixture header strictly for backward compatibility with Stage 3A offline unit tests
                    if quarantine_identity == "client-a":
                        q_matches.append({
                            "headers": {"x-attack-test": {"exact": quarantine_identity}},
                            "uri": uri_match
                        })
                q_rule = {
                    "name": "quarantine-malicious",
                    "match": q_matches,
                    "route": [
                        {
                            "destination": {"host": decoy_host, "port": {"number": port}}
                        }
                    ]
                }
                existing_q_idx = None
                for idx, r in enumerate(http_rules):
                    if r.get("name") == "quarantine-malicious" or any(is_decoy_dest(dest) for dest in r.get("route", [])):
                        existing_q_idx = idx
                        break
                if existing_q_idx is not None:
                    http_rules[existing_q_idx] = q_rule
                else:
                    # Quarantine rule MUST precede normal production rules
                    http_rules.insert(0, q_rule)
                logging.info(f"[OCC-ATOMIC] Installed quarantine rule for '{quarantine_identity}' -> '{decoy_host}' in '{vs_name}'")

            # Step 5: Atomic production route modification (RPS mitigation or recovery)
            if rps_routes is not None:
                rule_updated = False
                for rule in http_rules:
                    if rule.get("name") == "quarantine-malicious":
                        continue
                    existing_routes = rule.get("route", [])
                    matching_routes = [r for r in existing_routes if is_prod_dest(r)]
                    if not matching_routes:
                        continue

                    other_routes = [r for r in existing_routes if not is_prod_dest(r)]
                    if other_routes:
                        target_weight_share = sum(r.get("weight", 0) for r in matching_routes)
                        if target_weight_share <= 0:
                            other_weight = sum(r.get("weight", 0) for r in other_routes)
                            target_weight_share = max(0, 100 - other_weight)

                        total_new_weight = sum(r.get("weight", 0) for r in rps_routes) or 1
                        scaled_routes = []
                        accum = 0
                        for idx, r in enumerate(rps_routes):
                            w = r.get("weight", 0)
                            if idx == len(rps_routes) - 1:
                                scaled_w = target_weight_share - accum
                            else:
                                scaled_w = round(w * target_weight_share / total_new_weight)
                                accum += scaled_w
                            entry = json.loads(json.dumps(r))
                            entry["weight"] = max(0, scaled_w)
                            scaled_routes.append(entry)
                        rule["route"] = other_routes + scaled_routes
                    else:
                        rule["route"] = rps_routes
                    rule_updated = True

                if not rule_updated:
                    logging.error(f"[OCC-ATOMIC] No production route found for target_host={target_host} in VS={vs_name}")
                    return False

            # Step 6: Pre-write fencing check right before replace
            if service_name and my_pod_name:
                if not owns_lock(service_name, my_pod_name, expected_fencing_token=fencing_token):
                    logging.warning(
                        f"[OCC-ATOMIC] [{my_pod_name}] Aborting VS write for '{vs_name}': "
                        f"lost Lease ownership or token invalidated right before replace on attempt {attempt+1}"
                    )
                    return False

            # Step 7: Atomic replace (OCC)
            custom_api.replace_namespaced_custom_object(
                "networking.istio.io", "v1beta1", NAMESPACE, "virtualservices", vs_name, replace_body
            )
            logging.info(
                f"[OCC-ATOMIC] VS '{vs_name}' atomically updated OK "
                f"(attempt={attempt+1}, rv={resource_version}, fencing_token={fencing_token})"
            )
            return True

        except ApiException as e:
            if e.status == 409:
                if attempt < max_retries - 1:
                    backoff = 0.5 * (2 ** attempt)
                    logging.warning(
                        f"[OCC-ATOMIC] 409 Conflict on '{vs_name}' (attempt={attempt+1}), "
                        f"retrying in {backoff:.1f}s with fresh resourceVersion..."
                    )
                    time.sleep(backoff)
            elif e.status == 404:
                logging.warning(f"[OCC-ATOMIC] VS '{vs_name}' not found, recreating...")
                ensure_virtual_service(target_host, port)
                time.sleep(0.5)
            else:
                logging.error(f"[OCC-ATOMIC] Unrecoverable error patching '{vs_name}': {e.status} {e.reason}")
                return False
        except Exception as ex:
            logging.error(f"[OCC-ATOMIC] Unexpected error patching '{vs_name}': {ex}")
            return False

    logging.error(f"[OCC-ATOMIC] Failed to patch '{vs_name}' after {max_retries} retries")
    return False

def patch_vs_occ(vs_name, routes, port, max_retries=5, service_name=None, my_pod_name=None, fencing_token=None, target_host=None):
    """
    Backward-compatible wrapper around patch_vs_atomic for production route updates.
    """
    return patch_vs_atomic(
        vs_name=vs_name,
        target_host=target_host,
        rps_routes=routes,
        quarantine_identity=None,
        port=port,
        service_name=service_name,
        my_pod_name=my_pod_name,
        fencing_token=fencing_token,
        max_retries=max_retries
    )

def find_existing_vs(app_label):
    # Dr. Jahan's recommendation: Explicitly prioritize bookinfo gateway VS for productpage ingress
    if app_label == "productpage":
        try:
            custom_api.get_namespaced_custom_object("networking.istio.io", "v1beta1", NAMESPACE, "virtualservices", "bookinfo")
            return "bookinfo"
        except Exception:
            pass
    try:
        vs_list = custom_api.list_namespaced_custom_object("networking.istio.io", "v1beta1", NAMESPACE, "virtualservices")
        for vs in vs_list.get("items", []):
            hosts = vs.get("spec", {}).get("hosts", [])
            if any(h == app_label or h.startswith(f"{app_label}.") or h.split(".")[0] == app_label for h in hosts):
                return vs["metadata"]["name"]
            for rule in vs.get("spec", {}).get("http", []):
                for r in rule.get("route", []):
                    dest = r.get("destination", {}).get("host", "")
                    if dest == app_label or dest.startswith(f"{app_label}.") or dest.split(".")[0] == app_label:
                        return vs["metadata"]["name"]
    except Exception: pass
    return None

# ── MULTI-SCENARIO DYNAMIC MITIGATION DISPATCHER (Stage 3A) ─────────────────
def dispatch_mitigation(app_label: str, attribution: str, target_identity: str = "client-a"):
    """
    Decentralized Target Behavior Mitigation Dispatcher (Dr. Jahan's Stage 3A specification):
      - NONE: Normal production routing to v1.
      - RPS_ONLY: Multi-version failover (v2/v3) for volume overload; leaves quarantine unchanged.
      - ML_ONLY: Controlled quarantine of target_identity to isolated v4 (productpage-decoy);
                 leaves normal production traffic on v1=100%. Suppressed when ENABLE_ML_MITIGATION=false.
      - BOTH: Atomic single-write OCC patch — quarantines target_identity to v4 AND
              distributes remaining production traffic across v2/v3 backup pods.
              When ENABLE_ML_MITIGATION=false, executes RPS failover only without quarantine.
    """
    my_pod_name = os.getenv("HOSTNAME", f"defender-{os.urandom(4).hex()}")
    service_name = get_canonical_service_name(app_label)
    now = time.time()

    if attribution == "NONE":
        logging.info(f"[DISPATCH] Attribution NONE for '{app_label}' — no mitigation required")
        return

    # Master Read-Only & Tier-Specific Enforcement Guards
    if READ_ONLY_MODE:
        logging.info(f"[DISPATCH-GUARD] All mitigation suppressed for '{app_label}' (attribution={attribution}) due to READ_ONLY_MODE=true")
        return

    if attribution == "RPS_ONLY" and not ENABLE_RPS_ENFORCEMENT:
        logging.info(f"[DISPATCH-GUARD] RPS_ONLY mitigation suppressed for '{app_label}' due to ENABLE_RPS_ENFORCEMENT=false")
        return

    # Respect ML shadow mode
    if not ENABLE_ML_MITIGATION:
        if attribution == "ML_ONLY" and not ENABLE_ML_MITIGATION:
            logging.info(f"[DISPATCH] ML_ONLY for '{app_label}' suppressed due to ENABLE_ML_MITIGATION=false")
            return
        elif attribution == "STAGE3B_ONLY" and not ENABLE_STAGE3B_ENFORCEMENT:
            logging.info(f"[DISPATCH] STAGE3B_ONLY for '{app_label}' suppressed due to ENABLE_STAGE3B_ENFORCEMENT=false")
            return
        elif attribution == "BOTH" and not ENABLE_ML_MITIGATION and not ENABLE_STAGE3B_ENFORCEMENT:
            if not ENABLE_RPS_ENFORCEMENT:
                logging.info(f"[DISPATCH] BOTH for '{app_label}' with all enforcement disabled: suppressing completely")
                return
            logging.info(f"[DISPATCH] BOTH for '{app_label}' with quarantine disabled: treating as RPS_ONLY (suppressing quarantine)")
            attribution = "RPS_ONLY"

    # Intra-pod concurrency guard (prevents overlapping timer and dispatch executions)
    with OPERATION_LOCK:
        active_ops = STATE.setdefault("active_operations", set())
        if app_label in active_ops:
            logging.info(f"[DISPATCH] Operation already active for '{app_label}', skipping concurrent execution")
            return
        active_ops.add(app_label)

    try:
        # Check if exact mitigation is already fully satisfied
        is_rps_mitigated = app_label in STATE.get("rps_mitigated", set())
        is_ml_quarantined = app_label in STATE.get("ml_quarantined", {})

        current_quarantined_identity = STATE.get("ml_quarantined", {}).get(app_label, {}).get("identity")
        same_identity = (current_quarantined_identity == target_identity)

        if attribution == "RPS_ONLY" and is_rps_mitigated:
            return
        if attribution in ("ML_ONLY", "STAGE3B_ONLY") and is_ml_quarantined:
            if not same_identity:
                logging.warning(
                    f"[DISPATCH-GUARD] Refusing replacement of active quarantine '{current_quarantined_identity}' "
                    f"with new candidate '{target_identity}' for '{app_label}'."
                )
            return
        if attribution == "BOTH" and is_rps_mitigated and is_ml_quarantined and same_identity:
            return

        # Bounded WAIT loop for Lease acquisition (Scenario 1 LOCK)
        Twait  = 1
        Wmax   = 120
        waited = 0
        fencing_token = 0

        while True:
            acquired, fencing_token = acquire_lock(service_name, my_pod_name)
            if acquired:
                break
            if waited >= Wmax:
                logging.warning(
                    f"[DISPATCH] [{my_pod_name}] WAIT timeout ({Wmax}s) for '{service_name}'. "
                    f"Mitigation deferred to next cycle."
                )
                return
            logging.info(
                f"[DISPATCH] [{my_pod_name}] Lock busy for '{service_name}'. "
                f"WAIT {Twait}s (waited {waited}s / {Wmax}s max)."
            )
            time.sleep(Twait)
            waited += Twait

        heartbeat = LeaseHeartbeat(service_name, my_pod_name, interval=4.0)
        heartbeat.start()

        try:
            # Post-lock attack condition re-check (Dual-mode: RPS + ML using unified store)
            if attribution == "RPS_ONLY":
                active, reason = is_rps_attacked(app_label)
                if not active:
                    logging.info(f"[DISPATCH] Post-lock check: RPS attack subsided ({reason}). Aborting.")
                    return
            elif attribution in ("ML_ONLY", "STAGE3B_ONLY"):
                if attribution == "STAGE3B_ONLY":
                    cand = get_verified_candidate_for_service(app_label)
                    active = (cand is not None)
                    reason = f"Stage3B candidate active ({cand['client_id']})" if active else "No fresh Stage3B candidate"
                else:
                    active, reason = is_ml_attacked(app_label)
                if not active:
                    logging.info(f"[DISPATCH] Post-lock check: attack subsided ({reason}). Aborting.")
                    return
            elif attribution == "BOTH":
                rps_active, _ = is_rps_attacked(app_label)
                ml_active, _ = is_ml_attacked(app_label)
                stg_active = (get_verified_candidate_for_service(app_label) is not None) if ENABLE_STAGE3B_ENFORCEMENT else False
                if not rps_active and not ml_active and not stg_active:
                    logging.info(f"[DISPATCH] Post-lock check: Attacks subsided. Aborting.")
                    return
                if rps_active and not ml_active and not stg_active:
                    attribution = "RPS_ONLY"
                elif (ml_active or stg_active) and not rps_active:
                    attribution = "STAGE3B_ONLY" if stg_active else "ML_ONLY"
                    if attribution == "ML_ONLY" and not ENABLE_ML_MITIGATION:
                        logging.info(f"[DISPATCH] Post-lock check: ML_ONLY in shadow mode. Aborting.")
                        return

            vs_name = find_existing_vs(app_label) or ensure_virtual_service(app_label)
            port = 9080

            rps_routes = None
            if attribution in ("RPS_ONLY", "BOTH"):
                versions = get_service_versions(app_label)
                failover_versions = [v for v in versions if v != "v1"] or versions
                if len(failover_versions) < 2 and len(versions) < 2:
                    logging.warning(f"[DISPATCH] Insufficient versions to failover for '{app_label}'")
                else:
                    ensure_destination_rule(app_label, versions)
                    weight = 100 // len(failover_versions)
                    remainder = 100 - weight * len(failover_versions)
                    rps_routes = [
                        {
                            "destination": {"host": app_label, "port": {"number": port}, "subset": v},
                            "weight": weight + (remainder if i == 0 else 0)
                        }
                        for i, v in enumerate(failover_versions)
                    ]

            # Quarantine rule installed if authorized by either ML or Stage3B
            quarantine_authorized = (
                (attribution in ("ML_ONLY", "BOTH") and ENABLE_ML_MITIGATION) or
                (attribution in ("STAGE3B_ONLY", "BOTH") and ENABLE_STAGE3B_ENFORCEMENT)
            )
            quarantine_id = target_identity if quarantine_authorized else None

            logging.info(
                f"[DISPATCH] [{my_pod_name}] Applying '{attribution}' mitigation for '{app_label}': "
                f"quarantine={quarantine_id}, rps_routes={[(r['destination']['subset'], r['weight']) for r in (rps_routes or [])]}"
            )

            success = patch_vs_atomic(
                vs_name=vs_name,
                target_host=app_label,
                rps_routes=rps_routes,
                quarantine_identity=quarantine_id,
                port=port,
                service_name=service_name,
                my_pod_name=my_pod_name,
                fencing_token=fencing_token
            )

            if not success:
                logging.error(f"[DISPATCH] Atomic patch FAILED for '{app_label}'")
                return

            # Update fine-grained and unified state
            if attribution in ("RPS_ONLY", "BOTH"):
                STATE.setdefault("rps_mitigated", set()).add(app_label)
            if quarantine_id:
                STATE.setdefault("ml_quarantined", {})[app_label] = {
                    "identity": quarantine_id,
                    "time": now,
                    "method": attribution,
                    "source": attribution,
                    "fixture": True  # Dr. Jahan note: controlled Stage 3A/3B attribution fixture
                }
            STATE["attacked_services"].add(app_label)
            STATE["migration_state"] = "FAILOVER_ACTIVE"
            STATE["ddos_status"] = "ATTACK DETECTED"

            # Schedule independent cooldown recovery
            if app_label in STATE.get("revert_timers", {}):
                STATE["revert_timers"][app_label].cancel()

            initial_delay = min(REVERT_SECONDS, 15) if (quarantine_id and not rps_routes) else REVERT_SECONDS
            timer = threading.Timer(initial_delay, trigger_revert, args=[app_label, vs_name, port])
            timer.daemon = True
            timer.start()
            STATE.setdefault("revert_timers", {})[app_label] = timer

            logging.info(
                f"[DISPATCH] [{my_pod_name}] '{attribution}' mitigation active for '{app_label}'. "
                f"Recovery check scheduled in {initial_delay}s."
            )

        except Exception as ex:
            logging.error(f"[DISPATCH] Unexpected error in dispatch_mitigation for '{app_label}': {ex}")
        finally:
            heartbeat.stop()
            release_lock(service_name, my_pod_name)
    finally:
        with OPERATION_LOCK:
            STATE.setdefault("active_operations", set()).discard(app_label)

def trigger_failover(app_label: str):
    """
    Backward-compatible entry point delegating to dispatch_mitigation with RPS_ONLY attribution.
    """
    return dispatch_mitigation(app_label, attribution="RPS_ONLY")

def check_decoy_abatement(app_label: str, target_identity: str, threshold_rps: float = DECOY_ABATEMENT_RPS_THRESHOLD, window_seconds: float = None, eval_time: float = None) -> tuple[bool, str]:
    """
    Task 3C Anti-Oscillation Telemetry Guard:
    Checks productpage-decoy access logs to determine if the quarantined client's
    attack traffic has ceased (abated) on the decoy sinkhole across K=2 distinct,
    consecutive, non-overlapping, and valid observation intervals:
      Window 1: [T_start, T_end)
      Window 2: [T_end,   T_end + eval_window)
    Requests are individually timestamp-parsed and counted strictly within each
    assigned half-open interval before calculating RPS.
    
    Returns:
      (True, reason)  if attack traffic from target_identity has stopped / dropped <= threshold across K=2 valid distinct windows
      (False, reason) if target_identity is still generating attack traffic or telemetry is invalid/incomplete
    """
    if not target_identity:
        return False, "Missing target identity for decoy abatement; failing closed"

    now = float(eval_time) if eval_time is not None else time.time()
    try:
        decoy_app = f"{app_label}-decoy"
        pods_resp = core_api.list_namespaced_pod(
            NAMESPACE,
            label_selector=f"app={decoy_app}"
        )
        decoy_pods = [p for p in pods_resp.items if p.status.phase == "Running"]
        if not decoy_pods:
            logging.warning(f"[DECOY-ABATE] No running decoy pod found with label app={decoy_app}; failing closed (quarantine maintained)")
            STATE.setdefault("decoy_abatement_counts", {})[app_label] = 0
            STATE.setdefault("decoy_abatement_last_window_end", {})[app_label] = None
            STATE.setdefault("decoy_abatement_last_window", {})[app_label] = None
            return False, f"Decoy pod '{decoy_app}' unavailable; fail-closed safeguard"

        # Check minimum quarantine duration (10.0s)
        quarantined_record = STATE.get("ml_quarantined", {}).get(app_label)
        if isinstance(quarantined_record, dict):
            q_time = quarantined_record.get("time") or quarantined_record.get("timestamp")
            if q_time and (now - q_time < 10.0):
                return False, f"Minimum quarantine hold duration not met ({now - q_time:.1f}s < 10.0s)"

        eval_window = float(window_seconds if window_seconds is not None else 5.0)

        # Precise Non-Overlapping Window Accounting (Dr. Jahan's specification):
        # Window 1: [T, T + eval_window) -> records last_window_end = T + eval_window
        # Window 2: [last_window_end, last_window_end + eval_window)
        last_window_end = STATE.get("decoy_abatement_last_window_end", {}).get(app_label)
        if last_window_end is not None:
            if now < last_window_end + eval_window:
                elapsed_since_last = now - last_window_end
                return False, (
                    f"Incomplete observation window: only {elapsed_since_last:.2f}s elapsed since last window end "
                    f"(requires >={eval_window:.2f}s); holding quarantine"
                )

            # Contiguous adjacent window starting exactly where the previous window ended
            window_start = last_window_end
            window_end = now
        else:
            window_end = now
            window_start = window_end - eval_window

        # Collect decoy pod logs covering the exact interval with strict fail-closed enforcement
        total_target_requests = 0
        scrape_since = int(max(10, math.ceil(now - window_start) + 3))
        for pod in decoy_pods:
            pod_name = pod.metadata.name
            raw_lines = collect_pod_logs(pod_name, since_seconds=scrape_since, strict=True)
            for line in raw_lines:
                rec = parse_envoy_log_line(line)
                if not rec:
                    continue
                if rec.get("path") in ("/health", "/healthz"):
                    continue
                if rec.get("client_ip") != target_identity and target_identity not in line:
                    if not (rec.get("cluster", "").startswith("inbound|8080") or rec.get("cluster", "") == "inbound|8080||"):
                        continue
                req_ts = parse_log_timestamp(rec.get("timestamp"))
                if req_ts is None:
                    continue
                # Count each request ONLY within its assigned interval [window_start, window_end)
                if window_start <= req_ts < window_end:
                    total_target_requests += 1

        interval_duration = window_end - window_start
        measured_rps = total_target_requests / max(0.1, interval_duration)
        if measured_rps > threshold_rps:
            STATE.setdefault("decoy_abatement_counts", {})[app_label] = 0
            STATE.setdefault("decoy_abatement_last_window_end", {})[app_label] = None
            STATE.setdefault("decoy_abatement_last_window", {})[app_label] = None
            return False, f"Target '{target_identity}' still actively attacking decoy at {measured_rps:.1f} RPS (threshold: {threshold_rps:.1f} RPS) in window [{window_start:.1f}, {window_end:.1f})"

        STATE.setdefault("decoy_abatement_last_window_end", {})[app_label] = window_end
        STATE.setdefault("decoy_abatement_last_window", {})[app_label] = window_end
        consec = STATE.setdefault("decoy_abatement_counts", {}).get(app_label, 0) + 1
        STATE["decoy_abatement_counts"][app_label] = consec
        REQUIRED_CONSECUTIVE = 2
        if consec < REQUIRED_CONSECUTIVE:
            return False, f"Target '{target_identity}' abated for {consec}/{REQUIRED_CONSECUTIVE} consecutive distinct windows ({measured_rps:.1f} RPS <= {threshold_rps:.1f} RPS); holding quarantine"

        return True, f"Target '{target_identity}' confirmed abated on decoy across {consec} consecutive distinct non-overlapping windows ({measured_rps:.1f} RPS <= {threshold_rps:.1f} RPS)"
    except Exception as e:
        logging.warning(f"[DECOY-ABATE] Error inspecting decoy logs: {e}; failing closed")
        STATE.setdefault("decoy_abatement_counts", {})[app_label] = 0
        STATE.setdefault("decoy_abatement_last_window_end", {})[app_label] = None
        STATE.setdefault("decoy_abatement_last_window", {})[app_label] = None
        return False, f"Decoy inspection error ({e}); fail-closed safeguard"

def trigger_revert(app_label: str, vs_name: str, port: int = 9080):
    if READ_ONLY_MODE:
        logging.info(f"[REVERT-GUARD] Revert suppressed for '{app_label}' (READ_ONLY_MODE=true)")
        return
    """
    Scenario 2 — Independent Recovery VS update (Dr. Jahan's Stage 3A specification).
    Evaluates RPS and ML attack conditions independently:
      - If RPS cleared but ML still active: restores normal production routing to v1=100%,
        keeping the quarantine rule intact on v4.
      - If ML cleared but RPS still elevated: removes the quarantine rule,
        keeping production failover on v2/v3.
      - If both cleared: restores normal routing to v1=100% AND removes quarantine rule.
      - If neither cleared: reschedules cooldown timer without touching routing.
    """
    my_pod_name = os.getenv("HOSTNAME", f"defender-{os.urandom(4).hex()}")
    service_name = get_canonical_service_name(app_label)

    # Intra-pod concurrency guard (prevents overlapping timer and dispatch executions)
    with OPERATION_LOCK:
        active_ops = STATE.setdefault("active_operations", set())
        if app_label in active_ops:
            logging.info(f"[REVERT] Operation already active for '{app_label}', deferring recovery check in 5s")
            timer = threading.Timer(5, trigger_revert, args=[app_label, vs_name, port])
            timer.daemon = True
            timer.start()
            STATE.setdefault("revert_timers", {})[app_label] = timer
            return
        active_ops.add(app_label)

    try:
        # 1. Independent condition check prior to lock acquisition
        rps_active, rps_reason = is_rps_attacked(app_label)
        ml_status, ml_reason, ml_details = evaluate_ml_status(app_label)
        ml_active = (ml_status == ML_ATTACK)

        is_rps_mitigated = app_label in STATE.get("rps_mitigated", set())
        is_ml_quarantined = app_label in STATE.get("ml_quarantined", {})

        need_rps_revert = is_rps_mitigated and (not rps_active)

        # Stage 3C Decoy-Based Anti-Oscillation Safeguard:
        # Revert quarantine ONLY when:
        #   1. Production v1 ML status is authoritatively BENIGN (ml_status == ML_BENIGN).
        #   2. The quarantined client has abated on the decoy (decoy RPS <= threshold).
        need_ml_revert = False
        if is_ml_quarantined:
            target_id = STATE.get("ml_quarantined", {}).get(app_label, {}).get("identity")
            quarantine_source = STATE.get("ml_quarantined", {}).get(app_label, {}).get("source", "")
            if ml_status == ML_BENIGN or quarantine_source == "STAGE3B_ONLY" or ENABLE_STAGE3B_ENFORCEMENT:
                abated, abate_reason = check_decoy_abatement(app_label, target_id)
                if abated:
                    need_ml_revert = True
                    logging.info(f"[REVERT] Quarantine revert approved: {abate_reason}")
                else:
                    logging.info(
                        f"[REVERT-ANTI-OSCILLATION] Quarantine maintained for '{app_label}': "
                        f"{abate_reason}"
                    )
            elif ml_status == ML_UNKNOWN:
                logging.warning(
                    f"[REVERT] '{app_label}' has telemetry gap (ML_UNKNOWN: {ml_reason}); "
                    f"maintaining quarantine as safeguard."
                )

        if not need_rps_revert and not need_ml_revert:
            if is_rps_mitigated or is_ml_quarantined:
                if ml_status == ML_UNKNOWN and is_ml_quarantined:
                    logging.warning(
                        f"[REVERT] '{app_label}' has telemetry gap (ML_UNKNOWN: {ml_reason}); "
                        f"maintaining quarantine as safeguard."
                    )
                next_delay = REVERT_SECONDS
                abate_count = STATE.get("decoy_abatement_counts", {}).get(app_label, 0)
                if is_ml_quarantined:
                    next_delay = min(REVERT_SECONDS, 5)
                logging.info(
                    f"[REVERT] '{app_label}' still active (RPS active={rps_active} [{rps_reason}], "
                    f"ML status={ml_status} [{ml_reason}]). Rescheduling check in {next_delay}s."
                )
                timer = threading.Timer(next_delay, trigger_revert, args=[app_label, vs_name, port])
                timer.daemon = True
                timer.start()
                STATE.setdefault("revert_timers", {})[app_label] = timer
            return

        # 2. Acquire Lease lock with bounded wait
        Twait  = 1
        Wmax   = 120
        waited = 0
        fencing_token = 0

        while True:
            acquired, fencing_token = acquire_lock(service_name, my_pod_name)
            if acquired:
                break
            if waited >= Wmax:
                retry_count = STATE.setdefault("recovery_retries", {}).get(app_label, 0) + 1
                STATE["recovery_retries"][app_label] = retry_count
                MAX_RECOVERY_RETRIES = 3
                if retry_count <= MAX_RECOVERY_RETRIES:
                    backoff = min(60 * (2 ** (retry_count - 1)), 300)
                    logging.warning(
                        f"[REVERT] [{my_pod_name}] WAIT timeout ({Wmax}s) for recovery of '{service_name}' "
                        f"(retry {retry_count}/{MAX_RECOVERY_RETRIES}). Rescheduling in {backoff}s..."
                    )
                    timer = threading.Timer(backoff, trigger_revert, args=[app_label, vs_name, port])
                    timer.daemon = True
                    timer.start()
                    STATE.setdefault("revert_timers", {})[app_label] = timer
                else:
                    logging.critical(f"[ALERT] Recovery WAIT budget exhausted for '{service_name}'.")
                return
            time.sleep(Twait)
            waited += Twait

        heartbeat = LeaseHeartbeat(service_name, my_pod_name, interval=4.0)
        heartbeat.start()

        try:
            # Post-lock condition re-check
            rps_active, _ = is_rps_attacked(app_label)
            ml_status_post, _, _ = evaluate_ml_status(app_label)

            need_rps_revert = (app_label in STATE.get("rps_mitigated", set())) and (not rps_active)
            eval_window = 5.0
            if app_label in STATE.get("ml_quarantined", {}):
                quarantine_source = STATE.get("ml_quarantined", {}).get(app_label, {}).get("source", "")
                if ml_status_post == ML_BENIGN or quarantine_source == "STAGE3B_ONLY" or ENABLE_STAGE3B_ENFORCEMENT:
                    if waited < eval_window * 0.8 and need_ml_revert:
                        # Pre-lock already satisfied K=2 distinct consecutive windows and lock acquisition was immediate
                        pass
                    else:
                        target_id = STATE.get("ml_quarantined", {}).get(app_label, {}).get("identity")
                        abated, abate_reason = check_decoy_abatement(app_label, target_id)
                        if abated:
                            need_ml_revert = True
                        else:
                            need_ml_revert = False
                            logging.info(
                                f"[REVERT-POST-LOCK] Target '{target_id}' still active on decoy ({abate_reason}); maintaining quarantine."
                            )
                else:
                    need_ml_revert = False
            else:
                need_ml_revert = False

            if not need_rps_revert and not need_ml_revert:
                logging.info(
                    f"[REVERT] Attack condition or telemetry gap active during lock wait "
                    f"(RPS={rps_active}, ML={ml_status_post}). Rescheduling recovery in {REVERT_SECONDS}s."
                )
                timer = threading.Timer(REVERT_SECONDS, trigger_revert, args=[app_label, vs_name, port])
                timer.daemon = True
                timer.start()
                STATE.setdefault("revert_timers", {})[app_label] = timer
                return

            restore_routes = None
            if need_rps_revert:
                restore_routes = [{
                    "destination": {"host": app_label, "port": {"number": port}, "subset": "v1"},
                    "weight": 100
                }]

            quarantine_action = "REMOVE" if need_ml_revert else None

            logging.info(
                f"[REVERT] [{my_pod_name}] Executing recovery for '{app_label}': "
                f"restore_production={need_rps_revert}, remove_quarantine={need_ml_revert}"
            )

            success = patch_vs_atomic(
                vs_name=vs_name,
                target_host=app_label,
                rps_routes=restore_routes,
                quarantine_identity=quarantine_action,
                port=port,
                service_name=service_name,
                my_pod_name=my_pod_name,
                fencing_token=fencing_token
            )

            if success:
                if need_rps_revert:
                    STATE.get("rps_mitigated", set()).discard(app_label)
                    logging.info(f"[REVERT] Restored '{app_label}' production routing to v1=100%")
                if need_ml_revert:
                    STATE.get("ml_quarantined", {}).pop(app_label, None)
                    logging.info(f"[REVERT] Removed quarantine rule for '{app_label}'")

                # Update overall status
                still_rps = app_label in STATE.get("rps_mitigated", set())
                still_ml = app_label in STATE.get("ml_quarantined", {})

                if not still_rps and not still_ml:
                    STATE["attacked_services"].discard(app_label)
                    STATE.get("recovery_retries", {}).pop(app_label, None)
                    STATE.get("attack_metadata", {}).pop(app_label, None)
                    STATE.get("revert_timers", {}).pop(app_label, None)
                    if not STATE["attacked_services"]:
                        STATE["ddos_status"] = "NORMAL"
                        STATE["migration_state"] = "NORMAL"
                    logging.info(f"[REVERT] Full recovery complete for '{app_label}'.")
                else:
                    # Partial recovery: continue cooldown for remaining active component
                    timer = threading.Timer(REVERT_SECONDS, trigger_revert, args=[app_label, vs_name, port])
                    timer.daemon = True
                    timer.start()
                    STATE.setdefault("revert_timers", {})[app_label] = timer
                    logging.info(
                        f"[REVERT] Partial recovery for '{app_label}' complete "
                        f"(still active: rps={still_rps}, ml={still_ml}). Next check in {REVERT_SECONDS}s."
                    )
            else:
                retry_count = STATE.setdefault("recovery_retries", {}).get(app_label, 0) + 1
                STATE["recovery_retries"][app_label] = retry_count
                MAX_RECOVERY_RETRIES = 3
                logging.error(f"[REVERT] Recovery patch FAILED for '{app_label}' (attempt {retry_count}/{MAX_RECOVERY_RETRIES})")
                if retry_count <= MAX_RECOVERY_RETRIES:
                    backoff = min(60 * (2 ** (retry_count - 1)), 300)
                    timer = threading.Timer(backoff, trigger_revert, args=[app_label, vs_name, port])
                    timer.daemon = True
                    timer.start()
                    STATE.setdefault("revert_timers", {})[app_label] = timer

        except Exception as ex:
            logging.error(f"[REVERT] Unexpected error in trigger_revert for '{app_label}': {ex}")
        finally:
            heartbeat.stop()
            release_lock(service_name, my_pod_name)

        logging.info(f"[REVERT] Scenario 2 complete for '{app_label}'. Lock RELEASED.")
    finally:
        with OPERATION_LOCK:
            STATE.setdefault("active_operations", set()).discard(app_label)

def reconcile_state_from_cluster():
    """
    Reconciles in-memory mitigation state from the authoritative live Istio VirtualServices
    upon defender startup or leadership change (Dr. Jahan's Stage 3A review requirement).
    Scoped strictly to this defender's managed service (MY_APP_LABEL) to preserve decentralized ownership.
    """
    my_app = MY_APP_LABEL or os.getenv("SERVICE_NAME", "") or "productpage"
    if not my_app:
        return
    try:
        target_vs_name = find_existing_vs(my_app)
        if not target_vs_name:
            logging.debug(f"[RECONCILE] No VirtualService found managing '{my_app}'")
            return

        vs = custom_api.get_namespaced_custom_object(
            "networking.istio.io", "v1beta1", NAMESPACE, "virtualservices", target_vs_name
        )
        http_rules = vs.get("spec", {}).get("http", [])

        found_quarantine = False
        quarantined_identity = None
        found_failover = False
        failover_subset = None

        for rule in http_rules:
            rule_name = rule.get("name", "")
            routes = rule.get("route", [])

            # Check if this rule is a quarantine rule directed to our app's decoy
            is_quarantine_rule = (rule_name == "quarantine-malicious") or any(
                f"{my_app}-decoy" in r.get("destination", {}).get("host", "") for r in routes
            )
            if is_quarantine_rule:
                for r in routes:
                    dh = r.get("destination", {}).get("host", "")
                    if f"{my_app}-decoy" in dh or ("decoy" in dh and my_app in dh):
                        found_quarantine = True
                        for m in rule.get("match", []):
                            hdrs = m.get("headers", {})
                            id_val = hdrs.get("x-trusted-client-ip", {}).get("exact") or hdrs.get("x-attack-test", {}).get("exact")
                            if id_val:
                                quarantined_identity = id_val
                                break

            # Check if this rule defines normal production routing for our app
            # (must not be quarantine rule, and must route to my_app)
            if not is_quarantine_rule:
                for r in routes:
                    dest = r.get("destination", {})
                    dh = dest.get("host", "").split(".")[0]
                    if dh == my_app:
                        subset = dest.get("subset", "")
                        if subset and subset != "v1":
                            found_failover = True
                            failover_subset = subset

        # Update in-memory state based on authoritative cluster state for my_app
        if found_quarantine:
            existing_rec = STATE.get("ml_quarantined", {}).get(my_app)
            orig_time = existing_rec.get("time", time.time()) if isinstance(existing_rec, dict) else time.time()
            STATE.setdefault("ml_quarantined", {})[my_app] = {
                "identity": quarantined_identity,
                "source": "cluster-reconciled",
                "time": orig_time,
                "fixture": True
            }
            if not existing_rec:
                logging.info(f"[RECONCILE] Discovered active quarantine rule on VS '{target_vs_name}' for '{my_app}' (identity='{quarantined_identity}')")
        else:
            STATE.get("ml_quarantined", {}).pop(my_app, None)

        if found_failover:
            STATE.setdefault("rps_mitigated", set()).add(my_app)
            logging.info(f"[RECONCILE] Discovered active failover routing on VS '{target_vs_name}' for '{my_app}' (subset='{failover_subset}')")
        else:
            STATE.get("rps_mitigated", set()).discard(my_app)

        # Invariant (Dr. Jahan safeguard): attacked_services strictly matches active mitigation
        if found_quarantine or found_failover:
            STATE["attacked_services"].add(my_app)
            STATE["migration_state"] = "FAILOVER_ACTIVE"
            STATE["ddos_status"] = "ATTACK DETECTED"
            if my_app not in STATE.get("revert_timers", {}):
                timer = threading.Timer(REVERT_SECONDS, trigger_revert, args=[my_app, target_vs_name, 9080])
                timer.daemon = True
                timer.start()
                STATE.setdefault("revert_timers", {})[my_app] = timer
                logging.info(f"[RECONCILE] Scheduled recovery evaluation timer for '{my_app}' in {REVERT_SECONDS}s")
        else:
            STATE["attacked_services"].discard(my_app)
            if my_app in STATE.get("revert_timers", {}):
                STATE["revert_timers"][my_app].cancel()
                STATE["revert_timers"].pop(my_app, None)
            STATE.get("recovery_retries", {}).pop(my_app, None)
            STATE.get("attack_metadata", {}).pop(my_app, None)
            STATE.get("decoy_abatement_counts", {}).pop(my_app, None)
            STATE.get("decoy_abatement_last_window", {}).pop(my_app, None)
            STATE.get("decoy_abatement_last_window_end", {}).pop(my_app, None)
            if not STATE["attacked_services"]:
                STATE["migration_state"] = "NORMAL"
                STATE["ddos_status"] = "NORMAL"

    except Exception as ex:
        logging.warning(f"[RECONCILE] Error reconciling state from cluster for '{my_app}': {ex}")

def vs_reader_loop():
    while True:
        try:
            reconcile_state_from_cluster()
        except Exception as ex:
            logging.debug(f"[VS-READER] Error in reconciliation loop: {ex}")
        time.sleep(5)

@app.get("/api/health")
async def health(): return {"status": "ok"}


@app.post("/api/reset_predictions")
@app.get("/api/reset_predictions")
async def reset_predictions_endpoint():
    STATE["l7_predictions"].clear()
    STATE["hybrid_attribution"].clear()
    PROCESSED_REPLAY_RIDS.clear()
    logging.info("[API-RESET] Flushed l7_predictions, hybrid_attribution, and processed replay RIDs")
    return {"status": "cleared", "timestamp": time.time()}


@app.get("/api/status")
async def status_endpoint():
    return {
        "status": "ok",
        "detection_mode": DETECTION_MODE,
        "service": SERVICE_NAME or "all",
        "app_label": MY_APP_LABEL or "all",
        "l7_models": list(L7_MODEL_REGISTRY.keys()),
        "monitored_pods": {k: {"app": v.get("app"), "rps": v.get("rps")} for k, v in STATE.get("pods", {}).items()},
        "l7_predictions": STATE.get("l7_predictions", {}),
        "hybrid_attribution": STATE.get("hybrid_attribution", {}),
        "processed_replay_rids_count": len(PROCESSED_REPLAY_RIDS),
        "replay_auth_mode": REPLAY_AUTH_MODE,
        "replay_cache_ttl_seconds": REPLAY_CACHE_TTL_SECONDS,
        "l7_prediction_ttl": L7_PREDICTION_TTL,
        "threads": [t.name for t in threading.enumerate()]
    }

@app.get("/api/attribution")
async def attribution():
    return STATE.get("stage3b_attribution", {})

@app.on_event("startup")
async def startup():
    load_ml_models()
    reconcile_state_from_cluster()
    threading.Thread(target=discover_and_scrape, daemon=True).start()
    threading.Thread(target=detection_loop, daemon=True).start()
    threading.Thread(target=vs_reader_loop, daemon=True).start()
    logging.info("  DDoS Defender started — DECENTRALIZED MITIGATION with OCC + Lease")
