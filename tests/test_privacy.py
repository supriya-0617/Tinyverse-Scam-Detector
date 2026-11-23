"""Automated unit tests for privacy and offline operation guarantees (Milestone 6).

These tests verify real code, file-system, socket, and logging behavior rather
than asserting static assumptions:
1. Static AST verification that zero banned network/cloud/telemetry modules are
   imported across all project `.py` files, and that the detector correctly
   catches a synthetic banned import if injected into an AST.
2. Static AST verification that inference modules (`app.py`, `predict.py`,
   `src/features.py`, `src/rules.py`) contain zero file-write or database calls.
3. Configuration verification of `.streamlit/config.toml` (`127.0.0.1` loopback,
   no `0.0.0.0`, `gatherUsageStats = false`) and `requirements.txt`.
4. Controlled runtime network-isolation test blocking `socket.socket`,
   `socket.create_connection`, `socket.getaddrinfo`, and `urllib.request.urlopen`
   during live predictions containing URLs, IP addresses, and Hinglish text.
5. Runtime file-write interception test verifying that after model warmup,
   `predict_message()` never opens any file in write (`'w'`), append (`'a'`),
   or exclusive creation (`'x'`) mode.
6. Runtime logging & stdout/stderr capture test proving that a unique canary
   secret inside a submitted message is never emitted to Python `logging`,
   `stdout`, `stderr`, `reports/evaluation_report.json`, or `data/sample_messages.csv`.
7. Honest separation between automated software checks (`PASS`) and manual
   OS-level physical checks (`NOT_VERIFIED`) in `run_privacy_audit()`.
"""

from __future__ import annotations

import ast
import builtins
import logging
import socket
import urllib.request
from pathlib import Path

import pytest

from predict import DEFAULT_MODEL_PATH, get_cached_model_bundle, predict_message
from src.privacy_audit import (
    BANNED_NETWORK_IMPORTS,
    PROJECT_ROOT,
    inspect_ast_imports,
    inspect_inference_write_calls,
    inspect_requirements_file,
    inspect_streamlit_config,
    inspect_ui_remote_assets,
    run_canary_non_persistence_probe,
    run_network_isolated_prediction_probe,
    run_privacy_audit,
)


def test_ast_import_scanner_passes_on_project_and_catches_violations(tmp_path: Path):
    """Verify AST import scanner passes on real codebase and catches injected banned imports."""
    real_check = inspect_ast_imports(PROJECT_ROOT)
    assert real_check.status == "PASS"
    assert "0 banned" in real_check.evidence

    # Create a temporary project layout with an injected 'import requests' violation
    for rel in (
        "app.py",
        "predict.py",
        "train.py",
        "src/__init__.py",
        "src/features.py",
        "src/classifier.py",
        "src/rules.py",
        "src/privacy_audit.py",
    ):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x = 1\n", encoding="utf-8")

    # Inject banned cloud/HTTP imports into predict.py in tmp_path
    (tmp_path / "predict.py").write_text(
        "import requests\nfrom openai import OpenAI\n",
        encoding="utf-8",
    )
    bad_check = inspect_ast_imports(tmp_path)
    assert bad_check.status == "FAIL"
    assert "requests" in bad_check.evidence
    assert "openai" in bad_check.evidence


def test_inference_modules_have_no_file_write_calls_and_scanner_catches_writes(tmp_path: Path):
    """Verify inference modules have zero file-write calls and scanner catches injected writes."""
    real_check = inspect_inference_write_calls(PROJECT_ROOT)
    assert real_check.status == "PASS"

    for rel in ("app.py", "predict.py", "src/features.py", "src/rules.py"):
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x = 1\n", encoding="utf-8")

    (tmp_path / "app.py").write_text(
        "open('user_messages.log', 'a').write('secret')\n",
        encoding="utf-8",
    )
    bad_check = inspect_inference_write_calls(tmp_path)
    assert bad_check.status == "FAIL"
    assert "open()" in bad_check.evidence


def test_ui_contains_no_remote_cdns_or_external_fonts():
    """Verify app.py contains zero references to external CDNs or Google Fonts."""
    check = inspect_ui_remote_assets(PROJECT_ROOT)
    assert check.status == "PASS"


def test_streamlit_config_enforces_loopback_and_disables_telemetry():
    """Verify .streamlit/config.toml binds strictly to 127.0.0.1 and disables usage stats."""
    check = inspect_streamlit_config(PROJECT_ROOT)
    assert check.status == "PASS"


def test_requirements_contain_only_approved_local_packages():
    """Verify requirements.txt declares only approved offline-capable packages."""
    check = inspect_requirements_file(PROJECT_ROOT)
    assert check.status == "PASS"


def test_prediction_succeeds_with_all_network_and_dns_apis_blocked(monkeypatch):
    """Verify predictions containing URLs, IPs, and shorteners never touch socket, DNS, or urllib."""
    # Ensure model is loaded into memory before locking all network primitives
    _ = get_cached_model_bundle(DEFAULT_MODEL_PATH)

    def _deny_network(*args, **kwargs):
        raise RuntimeError("Outbound network or DNS access attempted during prediction!")

    monkeypatch.setattr(socket, "socket", _deny_network)
    monkeypatch.setattr(socket, "create_connection", _deny_network)
    monkeypatch.setattr(socket, "getaddrinfo", _deny_network)
    monkeypatch.setattr(socket, "gethostbyname", _deny_network)
    monkeypatch.setattr(urllib.request, "urlopen", _deny_network)

    messages_with_links = [
        "Dear customer, update your SBI KYC immediately at http://sbi-kyc-online.xyz or bit.ly/sbi-kyc",
        "Axis Bank Notice: Click http://192.168.10.45/axis-pan and enter your OTP and ATM PIN.",
        "Check out the official Python documentation at https://docs.python.org/3/ for tomorrow's workshop.",
    ]

    r1 = predict_message(messages_with_links[0])
    r2 = predict_message(messages_with_links[1])
    r3 = predict_message(messages_with_links[2])

    assert r1.verdict == "SCAM" and r1.category == "KYC/Bank"
    assert r2.verdict == "SCAM" and r2.category == "KYC/Bank"
    assert r3.verdict == "SAFE" and r3.category is None


def test_runtime_open_hook_verifies_zero_file_writes_during_prediction(monkeypatch):
    """Intercept builtins.open during predict_message() to prove zero files are opened for writing."""
    # Warm up model cache first so model reading is complete
    _ = get_cached_model_bundle(DEFAULT_MODEL_PATH)

    real_open = builtins.open
    write_attempts: list[tuple[str, str]] = []

    def _guarded_open(file, mode="r", *args, **kwargs):
        if any(flag in str(mode) for flag in ("w", "a", "x", "+")):
            write_attempts.append((str(file), str(mode)))
            raise PermissionError(f"Inference attempted to open file for writing: {file} ({mode})")
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _guarded_open)

    res_scam = predict_message("Pay Rs 4500 processing fee to claim your KBC lottery prize now!")
    res_safe = predict_message("Your OTP is 482913. Do not share it with anyone.")

    assert res_scam.verdict == "SCAM"
    assert res_safe.verdict == "SAFE"
    assert len(write_attempts) == 0


def test_canary_message_not_logged_printed_or_saved(caplog, capsys):
    """Verify a unique secret canary string in a message is never logged, printed, or written to disk."""
    canary_secret = "SECRET_OTP_902104_PRIVATE_BANK_BALANCE_RS_84920"
    msg = f"Your OTP is {canary_secret}. Do not share it with anyone."

    with caplog.at_level(logging.DEBUG):
        res = predict_message(msg)

    captured = capsys.readouterr()

    assert res.verdict == "SAFE"
    assert res.category is None
    # Verify canary never appeared in stdout, stderr, or Python logging records
    assert canary_secret not in captured.out
    assert canary_secret not in captured.err
    assert canary_secret not in caplog.text

    # Also run full filesystem non-persistence probe
    probe_item = run_canary_non_persistence_probe(PROJECT_ROOT)
    assert probe_item.status == "PASS"


def test_full_privacy_audit_report_distinguishes_automated_and_manual_checks():
    """Verify run_privacy_audit() passes all 7 automated checks and marks 2 OS-level checks as NOT_VERIFIED."""
    report = run_privacy_audit(PROJECT_ROOT)
    assert report.overall_automated_passed is True
    assert report.pass_count == 7
    assert report.fail_count == 0
    assert report.not_verified_count == 2

    statuses_by_id = {c.check_id: c.status for c in report.checks}
    assert statuses_by_id["PA-AST-01"] == "PASS"
    assert statuses_by_id["PA-UI-01"] == "PASS"
    assert statuses_by_id["PA-AST-02"] == "PASS"
    assert statuses_by_id["PA-CFG-01"] == "PASS"
    assert statuses_by_id["PA-CFG-02"] == "PASS"
    assert statuses_by_id["PA-Drv-01" if "PA-Drv-01" in statuses_by_id else "PA-RUN-01"] == "PASS"
    assert statuses_by_id["PA-RUN-02"] == "PASS"
    assert statuses_by_id["PA-MAN-01"] == "NOT_VERIFIED"
    assert statuses_by_id["PA-MAN-02"] == "NOT_VERIFIED"
