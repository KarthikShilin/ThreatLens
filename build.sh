#!/bin/bash
set -e

echo ">>> Installing Python dependencies..."
pip install -r requirements.txt

echo ">>> Setting up vulnerability scanning engine..."
python - << 'EOF'
import os
import platform
import urllib.request
import zipfile
import shutil
import subprocess

base_dir = os.path.dirname(os.path.abspath(__file__)) if "__file__" in globals() else os.getcwd()
bin_dir = os.path.join(base_dir, "bin")
os.makedirs(bin_dir, exist_ok=True)

system = platform.system().lower()
machine = platform.machine().lower()

arch = "amd64"
if "arm" in machine or "aarch" in machine:
    arch = "arm64"

nuclei_bin_name = "nuclei.exe" if system == "windows" else "nuclei"
target_bin = os.path.join(bin_dir, nuclei_bin_name)

if not os.path.exists(target_bin):
    print(f">>> Downloading scanning engine for {system}_{arch}...")
    version = "3.3.7"
    url = f"https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_{system}_{arch}.zip"
    zip_path = os.path.join(bin_dir, "engine.zip")
    try:
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            for member in zip_ref.namelist():
                if member in ("nuclei", "nuclei.exe"):
                    zip_ref.extract(member, bin_dir)
                    break
        if os.path.exists(zip_path):
            os.remove(zip_path)
        if system != "windows" and os.path.exists(target_bin):
            os.chmod(target_bin, 0o755)
        print(">>> Engine installed successfully at", target_bin)
    except Exception as e:
        print(">>> Warning: Engine download skipped:", e)

# Download / clone templates into ./nuclei-templates if not present
templates_dir = os.path.join(base_dir, "nuclei-templates")
if not os.path.isdir(templates_dir) and os.path.exists(target_bin):
    print(">>> Initializing templates...")
    try:
        subprocess.run([target_bin, "-ut", "-ud", templates_dir, "-duc", "-silent"], check=False)
        print(">>> Templates initialized.")
    except Exception as e:
        print(">>> Warning: Template setup error:", e)
EOF

echo ">>> Build complete!"
