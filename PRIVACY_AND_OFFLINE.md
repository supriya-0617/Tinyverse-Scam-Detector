# Privacy and Offline Verification

> **Authoritative Engineering Reference:** See [docs/10_Privacy_and_Security_Specification.md](docs/10_Privacy_and_Security_Specification.md) for the complete threat model (`T-01`–`T-08`), zero-retention policy, static AST audit specification, and runtime socket-blocking verification procedure.

## Privacy promise

The application is designed so message text is processed locally and is not transmitted to external services. This promise is valid only if the implementation follows this document and is verified on the final build.

## Required safeguards

- Bind the local UI to `127.0.0.1`, not `0.0.0.0`.
- No cloud APIs, hosted inference, external translation, telemetry, analytics, crash reporting, remote logging, or remote database.
- No message content in application logs.
- Do not persist submitted messages. Keep input in memory only for the current interaction.
- Model, vectorizer, and training data remain in local project files.
- Do not load remote fonts, scripts, images, or CDN assets.
- Pin and document dependencies.
- Never add a public tunnel or expose the app to the LAN.

## Verification checklist

1. Install Python packages before the demo.
2. Train the model locally.
3. Disconnect Wi-Fi / disable network adapters.
4. Start the app using `--server.address 127.0.0.1`.
5. Submit multiple messages and verify predictions still work.
6. Inspect source code for network libraries and outbound calls (`requests`, `httpx`, `urllib`, sockets, cloud SDKs).
7. Inspect dependency list for unnecessary network-capable SDKs.
8. Optionally use the operating system firewall or a network monitor to confirm no outbound connections occur while predicting.
9. Confirm messages are not written to files, logs, databases, or telemetry.
10. Capture evidence for the presentation: Wi-Fi disconnected, local URL, successful prediction, and source-code/network audit.

## Important limitation

A local web UI still uses a loopback HTTP connection between the browser and the local app. This is not an external server or internet transmission. Explain this distinction to judges. Also, dependency installation may require internet beforehand; the runtime prediction must not.

## Evidence to prepare

- Screenshot of app running at `127.0.0.1`.
- Screenshot of successful prediction with Wi-Fi disabled.
- Terminal output showing tests passed.
- `pip freeze` or dependency file.
- Source audit summary and statement of what was checked.

---

## Milestone 6 — Executed Privacy & Offline Verification Results

The multi-layer privacy audit module (`python -m src.privacy_audit` and `tests/test_privacy.py`) was executed against the completed codebase. We explicitly separate **automated software verification (`PASS`)** from **physical operating-system network verification (`NOT_VERIFIED` by Python alone)**:

| Check ID | Verification Layer | What Was Inspected / Tested | Status |
|---|---|---|---|
| **PA-AST-01** | Static AST Code Inspection | Parsed the Python Abstract Syntax Tree (AST) of all 8 application `.py` modules (`app.py`, `predict.py`, `train.py`, `src/*.py`) for 27 banned HTTP, socket, cloud AI (`openai`, `google.generativeai`, `groq`, `anthropic`), translation, and telemetry libraries. | **PASS** (`0` banned imports) |
| **PA-UI-01** | Static UI Asset Inspection | Inspected `app.py` for remote fonts (`fonts.googleapis.com`), external CDNs (`cdnjs`, `jsdelivr`, `unpkg`), and external API links. | **PASS** (`0` remote assets) |
| **PA-AST-02** | Static Write-Call Inspection | Parsed AST of all inference modules (`app.py`, `predict.py`, `src/features.py`, `src/rules.py`) for `open(..., 'w'/'a')`, `.write_text()`, `.write_bytes()`, `.to_csv()`, and `.to_sql()`. | **PASS** (`0` write calls) |
| **PA-CFG-01** | Configuration Inspection | Verified `.streamlit/config.toml` sets `address = "127.0.0.1"`, `gatherUsageStats = false`, and excludes `0.0.0.0`. | **PASS** |
| **PA-CFG-02** | Dependency Inspection | Verified `requirements.txt` contains only the 6 approved local packages (`streamlit`, `scikit-learn`, `pandas`, `joblib`, `pytest`, `matplotlib`). | **PASS** |
| **PA-RUN-01** | Controlled Runtime Socket & DNS Lock | Monkeypatched `socket.socket`, `socket.create_connection`, `socket.getaddrinfo`, `socket.gethostbyname`, and `urllib.request.urlopen` to raise `RuntimeError` and ran English scam (with URL/IP), Hinglish scam, and safe OTP predictions. | **PASS** (`0` socket/DNS calls) |
| **PA-RUN-02** | Runtime Canary Non-Persistence & `open()` Hook | Intercepted `builtins.open` during `predict_message()`, captured `stdout`/`stderr`/`logging`, and scanned all files in `data/`, `reports/`, and `models/` for a synthetic canary string. | **PASS** (`0` bytes persisted or logged) |
| **PA-MAN-01** | Physical Wi-Fi Disconnection Test | Disconnecting the physical Wi-Fi/Ethernet adapter in Windows Network Settings while submitting scam and safe messages in the browser at `http://127.0.0.1:8501`. | **PASS (Manually Verified by User)** *(Automatable Python status remains `NOT_VERIFIED` as it is an OS/physical check)* |
| **PA-MAN-02** | OS-Level TCP Table Inspection | Running `Get-NetTCPConnection -LocalPort 8501` in PowerShell; confirmed `Listen` (`LocalAddress 127.0.0.1:8501`) and `Established` (`127.0.0.1 <-> 127.0.0.1`) loopback-only connections. | **PASS (Manually Verified by User)** *(Automatable Python status remains `NOT_VERIFIED` as it is an OS-level check)* |
