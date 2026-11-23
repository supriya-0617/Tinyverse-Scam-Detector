# 13 — Setup and Offline Deployment Guide

> **Strict Privacy Note:** This application is an **on-device local tool**. Do NOT deploy it to public cloud servers, shared remote hosts, or `0.0.0.0` network bindings. All commands below set up and execute the detector locally on your own computer (`127.0.0.1`).

---

## 1. Prerequisites

- **Operating System:** Windows 10/11 (PowerShell recommended), macOS 12+, or Linux (Ubuntu/Debian/Fedora).
- **Python Version:** Python `3.11` or newer (verified on `Python 3.12.10`).
- **Internet Connection Needed?**
  - **Setup Phase (`pip install`):** Only required once if dependencies are not yet installed.
  - **Training, Testing & Runtime Prediction:** **0% internet required.** Works completely offline with Wi-Fi turned off.

---

## 2. Step-by-Step Setup Instructions (Windows PowerShell)

### Step 1: Open PowerShell and Navigate to the Project Folder
```powershell
cd "C:\Users\supri\Downloads\Tinyverse-Scam-Detector\Tinyverse_Scam_Detector_Starter_Pack"
```

### Step 2: Check Your Python Version
```powershell
python --version
```
*Expected Output:* `Python 3.12.10` (or any `Python 3.11.x` / `3.12.x`).

### Step 3: (Optional but Recommended for Clean Setup) Create and Activate a Virtual Environment
If you want an isolated environment separate from global Python packages:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
*(Note: If your global Python environment already has all packages installed—as verified on this machine—you can also run `python` directly.)*

### Step 4: Install / Verify Required Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 5: Train and Evaluate the Local Machine Learning Models
Run `train.py` to validate `data/sample_messages.csv`, train the Stage-1 Binary (`SCAM`/`SAFE`) and Stage-2 Category classifiers, save `models/scam_detector.joblib`, and generate evaluation reports in `reports/`:
```powershell
python train.py
```
*Expected Output:* Prints dataset validation summary, split sizes (`102 train / 22 val / 22 test`), binary and category metrics, latency benchmarks, and confirms `models/scam_detector.joblib` and `reports/evaluation_report.json` were saved.

### Step 6: Test Local CLI Predictions
Test a scam message and a safe message directly from the terminal:
```powershell
python predict.py "Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately."
python predict.py "Your OTP is 482913. Do not share it with anyone."
```

### Step 7: Run the Automated Pytest Verification Suite
```powershell
python -m pytest -q
```
*Expected Output:* All unit tests pass (`100% passed`).

### Step 8: Launch the Local Streamlit Dashboard (Milestone 4+)
Always bind strictly to `127.0.0.1`:
```powershell
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```
Open your local web browser to: `http://127.0.0.1:8501`

---

## 3. Linux / macOS Commands (Bash / Zsh)

```bash
cd /path/to/Tinyverse_Scam_Detector_Starter_Pack
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python train.py
python predict.py "Aapka KYC band ho jayega. Link par OTP bhejo."
python -m pytest -q
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

---

## 4. Verifiable Offline Execution Procedure (For Hackathon Demo)

To prove to judges that the system runs 100% offline:
1. Complete **Steps 1–7** above while on your laptop.
2. **Disconnect Wi-Fi** (turn on Airplane Mode or turn off Wi-Fi in Windows taskbar).
3. Run a CLI prediction with Wi-Fi off:
   ```powershell
   python predict.py "Congratulations! You won Rs 25 Lakh in KBC lottery. Pay Rs 5000 processing fee."
   ```
4. Launch or refresh the local Streamlit UI at `http://127.0.0.1:8501` and test multiple scam and safe messages.
5. Point out to judges that `127.0.0.1` is the operating system's internal loopback address—the browser and Python process are talking inside your laptop's RAM with zero external network connectivity.

---

## 5. Beginner Troubleshooting Guide

| Symptom / Error Message | Cause | Exact Fix |
|---|---|---|
| `Activate.ps1 cannot be loaded because running scripts is disabled` | Windows PowerShell default execution policy blocks `.ps1` scripts. | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in PowerShell, then re-run `.\.venv\Scripts\Activate.ps1`. |
| `FileNotFoundError: Model artifact not found at models/scam_detector.joblib` | `predict.py` or `app.py` was run before training the model. | Run `python train.py` first to generate `models/scam_detector.joblib`. |
| `Port 8501 is already in use` | Another Streamlit instance is still running in the background. | Press `Ctrl + C` in the old terminal, or specify `--server.port 8502`. |
| `ModuleNotFoundError: No module named 'src'` | Running a script from outside the project root directory. | Run `cd "C:\Users\supri\Downloads\Tinyverse-Scam-Detector\Tinyverse_Scam_Detector_Starter_Pack"` first. |
