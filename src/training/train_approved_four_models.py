import zipfile
import io
import time
import os
import json
import numpy as np
import pandas as pd
import joblib

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.model_selection import GroupShuffleSplit
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    recall_score,
    precision_score,
    f1_score,
    confusion_matrix
)

ZIP_PATH = r"C:\Users\mdbohos\Downloads\CICIDS2017_improved.zip"
OUTPUT_DIR = r"C:\Users\mdbohos\Desktop\ddos_detector\models_improved_cic"
os.makedirs(OUTPUT_DIR, exist_ok=True)

print("=" * 80)
print("TRAINING AND PACKAGING APPROVED FOUR-SERVICE MODEL ARCHITECTURE")
print("=" * 80)

# 1. Feature Specifications
FOUR_SERVICES = {
    "productpage": {
        "service_name": "productpage",
        "app_label": "productpage",
        "canonical_name": "product",
        "model_type": "random_forest",
        "features": [
            "Flow Packets/s",
            "Total Fwd Packet",
            "Total Length of Fwd Packet",
            "Fwd Packet Length Mean",
            "ACK Flag Count",
            "PSH Flag Count",
            "Packet Length Variance"
        ],
        "units": ["pkts/s", "count", "bytes", "bytes", "count", "count", "bytes^2"],
        "instantiator": lambda: RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1, random_state=42)
    },
    "details": {
        "service_name": "details",
        "app_label": "details",
        "canonical_name": "details",
        "model_type": "hist_gradient_boosting",
        "features": [
            "Total Fwd Packet",
            "Total Bwd packets",
            "Total Length of Fwd Packet",
            "Total Length of Bwd Packet",
            "Fwd Packet Length Mean",
            "Bwd Packet Length Mean",
            "Down/Up Ratio"
        ],
        "units": ["count", "count", "bytes", "bytes", "bytes", "bytes", "ratio"],
        "instantiator": lambda: HistGradientBoostingClassifier(max_iter=100, random_state=42)
    },
    "reviews": {
        "service_name": "reviews",
        "app_label": "reviews",
        "canonical_name": "reviews",
        "model_type": "hist_gradient_boosting",
        "features": [
            "Total Length of Bwd Packet",
            "Bwd Packet Length Mean",
            "Packet Length Variance",
            "Packet Length Std",
            "Total Bwd packets",
            "Down/Up Ratio",
            "Flow IAT Mean"
        ],
        "units": ["bytes", "bytes", "bytes^2", "bytes", "count", "ratio", "us"],
        "instantiator": lambda: HistGradientBoostingClassifier(max_iter=100, random_state=42)
    },
    "ratings": {
        "service_name": "ratings",
        "app_label": "ratings",
        "canonical_name": "ratings",
        "model_type": "random_forest",
        "features": [
            "Total Fwd Packet",
            "Total Bwd packets",
            "Packet Length Mean",
            "Packet Length Std",
            "Packet Length Variance",
            "PSH Flag Count",
            "ACK Flag Count"
        ],
        "units": ["count", "count", "bytes", "bytes", "bytes^2", "count", "count"],
        "instantiator": lambda: RandomForestClassifier(n_estimators=100, max_depth=15, n_jobs=-1, random_state=42)
    }
}

all_needed_cols = list(set([f for s in FOUR_SERVICES.values() for f in s["features"]] + ["Flow ID", "Dst Port", "Label", "Attempted Category", "Flow Duration"]))

# 2. Load Wednesday Training Data
print("\n[DATA-LOAD] Loading Wednesday training dataset...")
with zipfile.ZipFile(ZIP_PATH, 'r') as z:
    with z.open('wednesday.csv') as f:
        df_wed = pd.read_csv(f, usecols=all_needed_cols)
        df_wed = df_wed[(df_wed['Attempted Category'] == -1) & (df_wed['Flow Duration'] > 0)]
        sub_hulk = df_wed[df_wed['Label'] == 'DoS Hulk'].sample(n=15000, random_state=42)
        sub_gold = df_wed[df_wed['Label'] == 'DoS GoldenEye']
        sub_loris = df_wed[df_wed['Label'] == 'DoS Slowloris']
        sub_http = df_wed[df_wed['Label'] == 'DoS Slowhttptest']
        sub_benign_w = df_wed[(df_wed['Label'] == 'BENIGN') & (df_wed['Dst Port'] == 80)].sample(n=15000, random_state=42)
        train_df = pd.concat([sub_hulk, sub_gold, sub_loris, sub_http, sub_benign_w], ignore_index=True)
        train_df['Binary_Label'] = (train_df['Label'] != 'BENIGN').astype(int)

print(f"Training corpus: {len(train_df):,d} flows ({train_df['Binary_Label'].mean():.1%} attacks)")

# 3. Train each model, compute in-distribution validation, and save bundles
registry = {}

for svc_name, cfg in FOUR_SERVICES.items():
    print(f"\n" + "-" * 60)
    print(f"TRAINING SERVICE: {svc_name.upper()} ({cfg['model_type']})")
    print("-" * 60)
    feats = cfg["features"]
    
    # In-distribution split by Flow ID (80/20)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=42)
    tr_idx, val_idx = next(gss.split(train_df, groups=train_df["Flow ID"]))
    
    df_tr = train_df.iloc[tr_idx]
    df_val = train_df.iloc[val_idx]
    
    scaler = StandardScaler()
    X_tr = scaler.fit_transform(df_tr[feats].values)
    y_tr = df_tr['Binary_Label'].values
    
    X_val = scaler.transform(df_val[feats].values)
    y_val = df_val['Binary_Label'].values
    
    model = cfg["instantiator"]()
    t0 = time.perf_counter()
    model.fit(X_tr, y_tr)
    fit_time = time.perf_counter() - t0
    
    # Validate on held-out Wednesday split
    preds_val = model.predict(X_val)
    acc_val = accuracy_score(y_val, preds_val)
    rec_val = recall_score(y_val, preds_val)
    prec_val = precision_score(y_val, preds_val, zero_division=0)
    f1_val = f1_score(y_val, preds_val, zero_division=0)
    fpr_val = confusion_matrix(y_val, preds_val)[0,1] / np.sum(y_val == 0)
    
    # Fit final model on full training corpus
    X_full = scaler.fit_transform(train_df[feats].values)
    y_full = train_df['Binary_Label'].values
    model_final = cfg["instantiator"]()
    model_final.fit(X_full, y_full)
    
    svc_dir = os.path.join(OUTPUT_DIR, svc_name)
    os.makedirs(svc_dir, exist_ok=True)
    
    # Save standalone model & scaler
    joblib.dump(model_final, os.path.join(svc_dir, "model.joblib"))
    joblib.dump(scaler, os.path.join(svc_dir, "scaler.joblib"))
    
    # Save unified self-contained bundle for defender.py
    bundle = {
        "service_name": svc_name,
        "app_label": cfg["app_label"],
        "canonical_name": cfg["canonical_name"],
        "architecture": cfg["model_type"],
        "feature_names": feats,
        "units": cfg["units"],
        "model": model_final,
        "scaler": scaler,
        "classes": [0, 1],
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "metrics_wednesday_val": {
            "accuracy": round(float(acc_val), 4),
            "recall": round(float(rec_val), 4),
            "precision": round(float(prec_val), 4),
            "f1": round(float(f1_val), 4),
            "fpr": round(float(fpr_val), 4)
        }
    }
    bundle_path = os.path.join(svc_dir, f"{svc_name}_bundle_7feat.joblib")
    joblib.dump(bundle, bundle_path)
    
    # Config json
    cfg_json = {
        "service": svc_name,
        "app_label": cfg["app_label"],
        "canonical_name": cfg["canonical_name"],
        "architecture": cfg["model_type"],
        "feature_count": 7,
        "features": feats,
        "units": cfg["units"],
        "model_file": f"{svc_name}_bundle_7feat.joblib",
        "in_distribution_validation": bundle["metrics_wednesday_val"]
    }
    with open(os.path.join(svc_dir, "model_config.json"), "w") as f_cfg:
        json.dump(cfg_json, f_cfg, indent=2)
        
    print(f"  Wed Val Acc: {acc_val:.2%} | Rec: {rec_val:.2%} | Prec: {prec_val:.2%} | F1: {f1_val:.4f} | FPR: {fpr_val:.2%}")
    print(f"  Saved bundle to: {bundle_path} ({os.path.getsize(bundle_path)/1024:.1f} KB)")
    
    registry[svc_name] = cfg_json

# Save master manifest
with open(os.path.join(OUTPUT_DIR, "approved_four_models_manifest.json"), "w") as f:
    json.dump(registry, f, indent=2)

print("\n" + "=" * 80)
print(f"All 4 models trained and saved to {OUTPUT_DIR}")
print("=" * 80)
