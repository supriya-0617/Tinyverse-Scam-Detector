# 10 — Privacy and Security Specification

## 1. Privacy & Security Objectives

1. **Complete Data Sovereignty:** Private SMS and WhatsApp texts pasted by the user must never leave the local machine (`127.0.0.1`).
2. **Zero Ephemeral or Persistent Leakage:** User-submitted inference messages must never be written to application log files, command history files, SQLite/NoSQL databases, crash reports, or browser analytics.
3. **Air-Gapped Runtime Independence:** Once Python dependencies are installed and `python train.py` has saved `models/scam_detector.joblib`, the application must start and classify messages with all network adapters disabled.
4. **Defense Against Malicious Message Payloads:** Because users paste untrusted scam messages containing phishing links, IP addresses, or HTML/script fragments, the application must never auto-visit URLs, execute shell strings, or render unescaped HTML.

---

## 2. Assets Being Protected

| Asset ID | Asset Name | Sensitivity Level | Protection Goal |
|---|---|---|---|
| **A-01** | User-Submitted SMS/WhatsApp Text | **Critical (High PII)** | May contain real OTPs, partial bank account numbers, UPI references, or private chats. Must stay in volatile RAM only. |
| **A-02** | Local Host Network Interface | **High** | Prevent unauthorized LAN/WAN exposure of the local Streamlit web server. |
| **A-03** | Local Model Artifact (`models/scam_detector.joblib`) | **Medium** | Prevent loading untrusted remote pickle/joblib files or silent tampering. |
| **A-04** | User Web Browser Session | **High** | Prevent Cross-Site Scripting (XSS) or accidental click-through to phishing links inside analyzed messages. |

---

## 3. Threat Model & Mitigation Matrix

| Threat ID | Threat Description | Attack Surface | Likelihood | Impact | Mitigation Implemented | Verification Method |
|---|---|---|---|---|---|---|
| **T-01** | Accidental outbound network call during inference (e.g., cloud API, translation, remote tokenizer download). | Python inference runtime (`predict.py`, `src/`) | Low | Critical | Use only local `scikit-learn` TF-IDF + LogisticRegression; zero HTTP/cloud SDK imports; monkeypatch socket blocker in tests. | Static AST audit (`src/privacy_audit.py`) + socket-blocked test (`tests/test_privacy.py`) + Wi-Fi off test. |
| **T-02** | Local UI exposed to other devices on public/shared Wi-Fi via `0.0.0.0` binding. | Streamlit server startup | Medium | High | Explicitly enforce `--server.address 127.0.0.1` in launch scripts, `.streamlit/config.toml`, and docs. | Inspect startup configuration and verify socket binds only to `127.0.0.1`. |
| **T-03** | Submitted private messages leaked into disk logs or database tables. | Logging calls / file writes in `predict.py` or `app.py` | Medium | High | Strict zero-persistence policy: no `logging.info(text)` or file writes inside inference path; stateless session memory only. | AST check for file-write calls in `predict.py` + disk modification check during test run. |
| **T-04** | Streamlit telemetry or external CDN font/script loading leaks usage metadata. | Browser UI / Streamlit config | Medium | Medium | Configure `gatherUsageStats = false` and `headless` settings; avoid any external `<link>` or CDN CSS/font imports. | Verify `.streamlit/config.toml` and UI source inspection. |
| **T-05** | Malicious URL in scam message is automatically probed or clicked by user in results view. | URL extraction & UI rendering | Medium | High | Extract URL patterns strictly via offline regex (`src/features.py`, `src/rules.py`); display suspicious URLs as non-clickable code spans in UI. | Unit test verifying zero HTTP requests on URL-containing messages. |
| **T-06** | Algorithmic Complexity / Regex Denial of Service (ReDoS) via huge pasted input. | Input text area / regex normalizer | Medium | Medium | Enforce hard input cap `MAX_MESSAGE_LENGTH = 2000` characters in `validate_message_input()` before regex or TF-IDF execution. | `test_long_input_handling` with `10,000+` char payload in `tests/test_prediction.py`. |
| **T-07** | Cross-Site Scripting (XSS) via `<script>` tags pasted inside a message. | Streamlit UI rendering | Low | High | Render user messages and dynamic text using safe escaped text components (`st.text`, `st.code`, or `html.escape`). | Test payload `"<script>alert(1)</script>"` in unit tests. |
| **T-08** | Arbitrary code execution via loading an untrusted external `.joblib` file. | `joblib.load()` in `src/classifier.py` | Low | High | Restrict model loading to resolved paths inside the local project directory and verify expected dictionary structure. | Path validation check in `load_model_bundle()`. |

---

## 4. Data Handling, Retention & Logging Policy

1. **Inference Data Retention Policy:**
   - **In-Memory Lifespan:** When a user clicks **Analyze Message**, the string is held in a local Python variable for `< 50 ms` to compute the `PredictionResult` and rendered to the local browser over `127.0.0.1`.
   - **Clear Action:** Clicking **Clear** in the UI immediately resets `st.session_state` message variables in RAM.
   - **Disk Retention:** `0 bytes`. Submitted messages are never appended to `data/sample_messages.csv` or any log file.
2. **Logging Policy:**
   - System diagnostics (such as model load timing or training progress in `train.py`) may log aggregate counts (`146 rows loaded`), file paths, and evaluation metrics, **never raw user-submitted message strings**.

---

## 5. Offline Verification Procedure (Air-Gapped Protocol)

Because static source code inspection alone cannot prove the absence of OS-level network traffic, verification combines **three independent layers**:
1. **Layer 1 — Static AST Code & Dependency Audit (`src/privacy_audit.py`):** Scans all project `.py` files to confirm zero imports of `requests`, `httpx`, `urllib.request`, `aiohttp`, `openai`, `google.generativeai`, `groq`, or telemetry SDKs.
2. **Layer 2 — Runtime Socket Interception Test (`tests/test_privacy.py`):** Replaces Python's `socket.socket` constructor with a guard that raises `RuntimeError("Outbound network access is prohibited")` and runs full scam/safe predictions to prove inference never touches the network stack.
3. **Layer 3 — Physical Wi-Fi Disconnection Demo:**
   - Install dependencies and run `python train.py`.
   - Turn **OFF Wi-Fi** (and unplug Ethernet) in Windows Network Settings.
   - Start the app: `python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501`.
   - Open `http://127.0.0.1:8501` and verify both `SCAM` and `SAFE` predictions execute instantaneously.
   - *Technical Note for Judges:* The browser communicates with the Python process on the same laptop via the operating system's internal `127.0.0.1` loopback virtual interface—no packets ever reach a router or external network card.

---

## 6. Milestone 6 Verification Matrix & Privacy Limitations

### 6.1 Executed Verification Matrix (`python -m src.privacy_audit` & `tests/test_privacy.py`)

| Check ID | Layer | Verification Method | Result |
|---|---|---|---|
| **PA-AST-01** | Static Code (AST) | `inspect_ast_imports()` across all 8 project `.py` files (plus negative test injecting `import requests` into a temp file to prove detection). | **PASS** |
| **PA-UI-01** | Static UI Assets | `inspect_ui_remote_assets()` scanning `app.py` for Google Fonts, CDNs, and remote scripts. | **PASS** |
| **PA-AST-02** | Static Write Check | `inspect_inference_write_calls()` verifying zero file-write or DB calls in `app.py`, `predict.py`, `src/features.py`, `src/rules.py` (plus negative test injecting `open(..., 'a')`). | **PASS** |
| **PA-CFG-01** | Server Config | `inspect_streamlit_config()` verifying `.streamlit/config.toml` sets `address = "127.0.0.1"` and `gatherUsageStats = false`. | **PASS** |
| **PA-CFG-02** | Dependency Audit | `inspect_requirements_file()` verifying only the 6 approved offline-capable packages are declared. | **PASS** |
| **PA-RUN-01** | Controlled Socket/DNS Lock | `run_network_isolated_prediction_probe()` & `test_prediction_succeeds_with_all_network_and_dns_apis_blocked` blocking `socket.socket`, `create_connection`, `getaddrinfo`, `gethostbyname`, and `urllib.request.urlopen`. | **PASS** |
| **PA-RUN-02** | Runtime Non-Persistence & Logging | `run_canary_non_persistence_probe()`, `builtins.open` write-mode guard, and `caplog`/`capsys` verification that a unique canary message string never appears in logs, console streams, or files. | **PASS** |
| **PA-MAN-01** | Physical Air-Gap | Turning off Wi-Fi/Ethernet at the OS level and running scam and genuine bank debit predictions in the browser at `http://127.0.0.1:8501`. | **PASS (Manually Verified)** *(Reported as `NOT_VERIFIED` inside `src/privacy_audit.py` because Python code alone cannot self-certify physical OS adapter state)* |
| **PA-MAN-02** | OS Network Stack | Inspecting Windows TCP endpoints via `Get-NetTCPConnection -LocalPort 8501` (`Listen` on `127.0.0.1:8501`, `Established` strictly between `127.0.0.1` and `127.0.0.1`). | **PASS (Manually Verified)** *(Reported as `NOT_VERIFIED` inside `src/privacy_audit.py` to preserve strict separation between Python-level and OS-level checks)* |

### 6.2 Honest Privacy & Verification Limitations
1. **Why Static & Python-Level Tests Do Not Replace Physical Air-Gap Testing:** While AST scanning (`PA-AST-01`) and Python `socket` monkeypatching (`PA-RUN-01`) prove that our Python inference pipeline makes zero network calls, C-extensions or the browser itself operate outside Python's `socket` wrapper. Therefore, physical Wi-Fi disconnection (`PA-MAN-01`) and OS TCP table checks (`PA-MAN-02`) are explicitly marked `NOT_VERIFIED` in automated reports until performed manually during the demo.
2. **Localhost Browser Memory:** While `Clear` removes the message from Streamlit's Python `st.session_state` in RAM, the user's web browser tab may still hold normal DOM undo history until the browser tab is closed or refreshed.
