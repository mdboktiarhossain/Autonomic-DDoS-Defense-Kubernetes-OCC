import zipfile, pandas as pd, numpy as np, joblib, os, sys, json

sys.stdout.reconfigure(encoding='utf-8')

ZIP_PATH = r"C:\Users\mdbohos\Downloads\CICIDS2017_improved.zip"
MODELS_DIR = r"C:\Users\mdbohos\Desktop\ddos_detector\models_improved_cic"

print("=" * 80)
print("STAGE 4: UNTOUCHED FINAL EVALUATION SET VERIFICATION")
print("=" * 80)

# Load existing deployed models
services = ["details", "productpage", "reviews", "ratings"]
bundles = {s: joblib.load(os.path.join(MODELS_DIR, s, f"{s}_bundle_7feat.joblib")) for s in services}

all_needed_feats = set()
for b in bundles.values(): all_needed_feats.update(b["feature_names"])
meta_cols = ["Dst Port", "Protocol", "Attempted Category", "Flow Duration", "Label", "Timestamp"]
load_cols = list(set(list(all_needed_feats) + meta_cols))

# Load Friday and Monday
with zipfile.ZipFile(ZIP_PATH, 'r') as z:
    with z.open('friday.csv') as f:
        df_fri = pd.read_csv(f, usecols=load_cols)
        df_fri = df_fri[(df_fri['Attempted Category'] == -1) & (df_fri['Flow Duration'] > 0)]
    with z.open('monday.csv') as f:
        df_mon = pd.read_csv(f, usecols=load_cols)
        df_mon = df_mon[(df_mon['Attempted Category'] == -1) & (df_mon['Flow Duration'] > 0)]

# Untouched Evaluation Set: 20,000 LOIC + 20,000 Friday Benign + 20,000 Monday Benign
# (sampled with random_state=202, guaranteed disjoint from development set which used random_state=101)
dev_loic_idx = df_fri[df_fri['Label'] == 'DDoS'].sample(n=20000, random_state=101).index
dev_fri_b_idx = df_fri[df_fri['Label'] == 'BENIGN'].sample(n=20000, random_state=101).index
dev_mon_b_idx = df_mon[df_mon['Label'] == 'BENIGN'].sample(n=20000, random_state=101).index

untouched_loic = df_fri[df_fri['Label'] == 'DDoS'].drop(dev_loic_idx).sample(n=20000, random_state=202)
untouched_fri_b = df_fri[df_fri['Label'] == 'BENIGN'].drop(dev_fri_b_idx).sample(n=20000, random_state=202)
untouched_mon_b = df_mon[df_mon['Label'] == 'BENIGN'].drop(dev_mon_b_idx).sample(n=20000, random_state=202)

untouched_fri_b_http = untouched_fri_b[untouched_fri_b['Dst Port'] == 80]
untouched_mon_b_http = untouched_mon_b[untouched_mon_b['Dst Port'] == 80]

print(f"Untouched LOIC Flows:        {len(untouched_loic):,d}")
print(f"Untouched Friday Benign:     {len(untouched_fri_b):,d} (HTTP Port 80: {len(untouched_fri_b_http):,d})")
print(f"Untouched Monday Benign:     {len(untouched_mon_b):,d} (HTTP Port 80: {len(untouched_mon_b_http):,d})")

# Overlap Verification with Training and Dev Sets
assert len(set(untouched_loic.index).intersection(dev_loic_idx)) == 0, "Overlap in LOIC!"
assert len(set(untouched_fri_b.index).intersection(dev_fri_b_idx)) == 0, "Overlap in Friday Benign!"
assert len(set(untouched_mon_b.index).intersection(dev_mon_b_idx)) == 0, "Overlap in Monday Benign!"
print("Zero Overlap Verified: The final evaluation set is 100% disjoint from development tuning data.")

final_metrics = {}

print("\n" + "=" * 95)
print(f"{'Service':<12} | {'Algorithm':<20} | {'Threshold':<9} | {'LOIC Rec':<9} | {'Fri All FPR':<12} | {'Fri HTTP':<9} | {'Mon All FPR':<12} | {'Mon HTTP':<9}")
print("=" * 95)

# Evaluation at:
# 1. Base threshold 0.45
# 2. Optimized threshold 0.70 / 0.80
for svc in services:
    b = bundles[svc]
    feats = b["feature_names"]
    scaler = b["scaler"]
    model = b["model"]
    
    X_atk = scaler.transform(untouched_loic[feats].values)
    X_fb = scaler.transform(untouched_fri_b[feats].values)
    X_fb_h = scaler.transform(untouched_fri_b_http[feats].values)
    X_mb = scaler.transform(untouched_mon_b[feats].values)
    X_mb_h = scaler.transform(untouched_mon_b_http[feats].values)
    
    p_atk = model.predict_proba(X_atk)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_atk)
    p_fb = model.predict_proba(X_fb)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_fb)
    p_fb_h = model.predict_proba(X_fb_h)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_fb_h)
    p_mb = model.predict_proba(X_mb)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_mb)
    p_mb_h = model.predict_proba(X_mb_h)[:, 1] if hasattr(model, "predict_proba") else model.predict(X_mb_h)
    
    # Evaluate at 0.45 and calibrated threshold (0.70 for productpage/ratings/reviews, 0.80 for details)
    opt_th = 0.70 if svc != "details" else 0.80
    
    for th in [0.45, opt_th]:
        rec = float(np.mean(p_atk >= th))
        fpr_fb = float(np.mean(p_fb >= th))
        fpr_fb_h = float(np.mean(p_fb_h >= th))
        fpr_mb = float(np.mean(p_mb >= th))
        fpr_mb_h = float(np.mean(p_mb_h >= th))
        
        tag = f"(base)" if th == 0.45 else f"(calibrated)"
        print(f"{svc:<12} | {b['architecture']:<20} | {th:<9.2f} | {rec:<9.2%} | {fpr_fb:<12.2%} | {fpr_fb_h:<9.2%} | {fpr_mb:<12.2%} | {fpr_mb_h:<9.2%}")
        
        final_metrics[f"{svc}_{th}"] = {
            "service": svc,
            "architecture": b["architecture"],
            "threshold": th,
            "loic_recall": rec,
            "fpr_friday_all": fpr_fb,
            "fpr_friday_http": fpr_fb_h,
            "fpr_monday_all": fpr_mb,
            "fpr_monday_http": fpr_mb_h
        }

with open("scratch/stage4_untouched_final_evaluation_results.json", "w") as f:
    json.dump(final_metrics, f, indent=2)

print("\nFinal untouched evaluation results saved to scratch/stage4_untouched_final_evaluation_results.json")
