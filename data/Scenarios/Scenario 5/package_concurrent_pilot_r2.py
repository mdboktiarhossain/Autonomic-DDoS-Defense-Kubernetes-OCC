import os, zipfile, hashlib

raw_dir = "PAPER/Backup/SCENARIO_5_BENCHMARK_RESULTS/raw"
zip_path = "PAPER/Backup/SCENARIO_5_CONCURRENT_PILOT_R2_PACKAGE.zip"
manifest_path = "PAPER/Backup/SCENARIO_5_CONCURRENT_PILOT_R2_MANIFEST.sha256"

files_to_pack = [
    os.path.join(raw_dir, "trial_concurrent_pilot_r2_concurrent_autonomous.json"),
    os.path.join(raw_dir, "controller_trace_trial_concurrent_pilot_r2_productpage.log"),
    os.path.join(raw_dir, "controller_trace_trial_concurrent_pilot_r2_details.log"),
    os.path.join(raw_dir, "controller_trace_trial_concurrent_pilot_r2_reviews.log"),
    os.path.join(raw_dir, "controller_trace_trial_concurrent_pilot_r2_ratings.log"),
    os.path.join(raw_dir, "trial_concurrent_pilot_r2_benign_productpage.jsonl"),
    os.path.join(raw_dir, "trial_concurrent_pilot_r2_benign_details.jsonl"),
    os.path.join(raw_dir, "trial_concurrent_pilot_r2_benign_reviews.jsonl"),
    os.path.join(raw_dir, "trial_concurrent_pilot_r2_benign_ratings.jsonl")
]

manifest_lines = []
with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
    for f in files_to_pack:
        if os.path.exists(f):
            arcname = os.path.basename(f)
            z.write(f, arcname)
            data = open(f, "rb").read()
            sha = hashlib.sha256(data).hexdigest()
            size = len(data)
            manifest_lines.append(f"{sha}  {arcname}  ({size} bytes)")
            print(f"Packaged {arcname} ({size} bytes, sha256={sha})")

zip_data = open(zip_path, "rb").read()
zip_sha = hashlib.sha256(zip_data).hexdigest()
manifest_lines.append(f"\n# ZIP Archive SHA-256:\n# {zip_sha}  {os.path.basename(zip_path)}  ({len(zip_data)} bytes)")

with open(manifest_path, "w") as mf:
    mf.write("\n".join(manifest_lines) + "\n")

print(f"\nCreated {manifest_path}")
print(f"ZIP Archive SHA-256: {zip_sha} ({len(zip_data)} bytes)")
