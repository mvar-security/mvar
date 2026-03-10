from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from mvar_core.cli_ledger import main_verify_witness, verify_witness_file
from mvar_core.decision_ledger import MVARDecisionLedger, generate_signature


def _build_signed_witness_jsonl(tmp_path, monkeypatch, *, count: int = 2):
    monkeypatch.setenv("QSEAL_SECRET", "unit-test-secret")
    witness_path = tmp_path / "witness.jsonl"
    ledger = MVARDecisionLedger(ledger_path=str(witness_path), enable_qseal_signing=True)
    sink = SimpleNamespace(tool="bash", action="exec")
    for idx in range(count):
        ledger.record_decision(
            outcome="BLOCK" if idx % 2 == 0 else "STEP_UP",
            sink=sink,
            target=f"cmd-{idx}",
            provenance_node_id=f"node-{idx}",
            evaluation_trace=[f"trace-{idx}"],
            reason=f"reason-{idx}",
        )
    return witness_path


def _read_jsonl(path):
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [json.loads(line) for line in lines]


def _resign_scroll(tmp_path, scroll):
    ledger = MVARDecisionLedger(ledger_path=str(tmp_path / "noop.jsonl"), enable_qseal_signing=True)
    scroll["meta_hash"] = ledger._compute_meta_hash(scroll)  # noqa: SLF001
    payload = {
        k: v
        for k, v in scroll.items()
        if k not in ("qseal_signature", "qseal_verified", "qseal_meta_hash", "qseal_algorithm")
    }
    scroll["qseal_signature"] = generate_signature(payload)
    return scroll


def test_valid_single_json_witness(tmp_path, monkeypatch):
    jsonl_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=1)
    witness = _read_jsonl(jsonl_path)[0]
    json_path = tmp_path / "witness.json"
    json_path.write_text(json.dumps(witness), encoding="utf-8")

    report = verify_witness_file(str(json_path))
    assert report["total_scrolls"] == 1
    assert report["verified_scrolls"] == 1
    assert report["all_signatures_valid"] is True
    assert report["chain_valid"] is True
    assert report["errors"] == []


def test_valid_jsonl_witness_chain(tmp_path, monkeypatch):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=2)
    report = verify_witness_file(str(witness_path), require_chain=True)
    assert report["total_scrolls"] == 2
    assert report["verified_scrolls"] == 2
    assert report["all_signatures_valid"] is True
    assert report["chain_valid"] is True
    assert report["errors"] == []


def test_first_record_without_prev_signature_is_valid_chain(tmp_path, monkeypatch):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=1)
    rows = _read_jsonl(witness_path)
    rows[0].pop("qseal_prev_signature", None)
    witness_path.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")

    report = verify_witness_file(str(witness_path), require_chain=True)
    assert report["all_signatures_valid"] is True
    assert report["chain_valid"] is True
    assert report["errors"] == []


def test_tampered_signature_detected(tmp_path, monkeypatch):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=1)
    witness = _read_jsonl(witness_path)[0]
    witness["reason"] = "tampered"
    witness_path.write_text(json.dumps(witness) + "\n", encoding="utf-8")

    report = verify_witness_file(str(witness_path))
    assert report["all_signatures_valid"] is False
    assert report["chain_valid"] is True
    assert report["errors"] == [f"signature_invalid:{witness['scroll_id']}"]


def test_missing_file_reported(tmp_path):
    missing = tmp_path / "does-not-exist.jsonl"
    report = verify_witness_file(str(missing))
    assert report["total_scrolls"] == 0
    assert report["verified_scrolls"] == 0
    assert report["all_signatures_valid"] is False
    assert report["chain_valid"] is False
    assert report["errors"] == ["missing_file"]


def test_empty_file_reported(tmp_path):
    witness_path = tmp_path / "empty.jsonl"
    witness_path.write_text("", encoding="utf-8")

    report = verify_witness_file(str(witness_path))
    assert report["errors"] == ["witness_file_empty"]
    assert report["all_signatures_valid"] is False
    assert report["chain_valid"] is False


def test_second_record_missing_prev_signature_fails_when_require_chain(tmp_path, monkeypatch):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=2)
    rows = _read_jsonl(witness_path)

    # First record without prev pointer is acceptable as genesis.
    rows[0].pop("qseal_prev_signature", None)
    rows[1].pop("qseal_prev_signature", None)
    rows[1] = _resign_scroll(tmp_path, rows[1])
    witness_path.write_text("\n".join(json.dumps(item) for item in rows) + "\n", encoding="utf-8")

    report = verify_witness_file(str(witness_path), require_chain=True)
    assert report["all_signatures_valid"] is True
    assert report["chain_valid"] is False
    assert "chain_missing_prev_signature:line_2" in report["errors"]


def test_chain_mismatch_reported(tmp_path, monkeypatch):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=2)
    rows = _read_jsonl(witness_path)
    rows[1]["qseal_prev_signature"] = "broken-pointer"
    rows[1] = _resign_scroll(tmp_path, rows[1])
    witness_path.write_text("\n".join(json.dumps(item) for item in rows) + "\n", encoding="utf-8")

    report = verify_witness_file(str(witness_path), require_chain=True)
    assert report["all_signatures_valid"] is True
    assert report["chain_valid"] is False
    assert "chain_mismatch:line_2" in report["errors"]


def test_malformed_json_reported(tmp_path):
    witness_path = tmp_path / "bad.json"
    witness_path.write_text("{not-json", encoding="utf-8")

    report = verify_witness_file(str(witness_path))
    assert report["errors"] == ["malformed_json"]


def test_malformed_jsonl_line_reported(tmp_path):
    witness_path = tmp_path / "bad.jsonl"
    witness_path.write_text("{\n", encoding="utf-8")

    report = verify_witness_file(str(witness_path))
    assert report["errors"] == ["malformed_json:line_1"]


def test_non_object_jsonl_line_reported(tmp_path):
    witness_path = tmp_path / "bad.jsonl"
    witness_path.write_text("\"string-line\"\n", encoding="utf-8")

    report = verify_witness_file(str(witness_path))
    assert report["errors"] == ["non_object_jsonl_line:line_1"]


def test_missing_qseal_signature_reported(tmp_path, monkeypatch):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=1)
    witness = _read_jsonl(witness_path)[0]
    witness.pop("qseal_signature", None)
    witness_path.write_text(json.dumps(witness) + "\n", encoding="utf-8")

    report = verify_witness_file(str(witness_path))
    assert report["all_signatures_valid"] is False
    assert report["chain_valid"] is True
    assert report["errors"] == ["missing_signature:line_1"]


def test_signature_invalid_but_chain_intact(tmp_path, monkeypatch):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=2)
    rows = _read_jsonl(witness_path)
    rows[1]["reason"] = "tampered-second-record"
    witness_path.write_text("\n".join(json.dumps(item) for item in rows) + "\n", encoding="utf-8")

    report = verify_witness_file(str(witness_path), require_chain=True)
    assert report["all_signatures_valid"] is False
    assert report["chain_valid"] is True
    assert any(err.startswith("signature_invalid:") for err in report["errors"])
    assert not any(err.startswith("chain_") for err in report["errors"])


def test_cli_exit_zero_for_valid_file(tmp_path, monkeypatch, capsys):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=2)
    monkeypatch.setattr(sys, "argv", ["mvar-verify-witness", str(witness_path), "--require-chain"])

    with pytest.raises(SystemExit) as exc:
        main_verify_witness()
    assert exc.value.code == 0

    out = capsys.readouterr().out.strip()
    assert out == "witness verification PASS"


def test_cli_exit_one_for_invalid_file(tmp_path, monkeypatch, capsys):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=1)
    witness = _read_jsonl(witness_path)[0]
    witness["reason"] = "tampered"
    witness_path.write_text(json.dumps(witness) + "\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["mvar-verify-witness", str(witness_path)])

    with pytest.raises(SystemExit) as exc:
        main_verify_witness()
    assert exc.value.code == 1

    out = capsys.readouterr().out.strip()
    assert out == "witness verification FAIL"


def test_cli_json_flag_outputs_structured_report(tmp_path, monkeypatch, capsys):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=2)
    monkeypatch.setattr(
        sys,
        "argv",
        ["mvar-verify-witness", str(witness_path), "--require-chain", "--json"],
    )

    with pytest.raises(SystemExit) as exc:
        main_verify_witness()
    assert exc.value.code == 0

    out = capsys.readouterr().out.strip()
    report = json.loads(out)
    assert report["all_signatures_valid"] is True
    assert report["chain_valid"] is True


def test_cli_help_outputs_exact_text(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mvar-verify-witness", "--help"])

    with pytest.raises(SystemExit) as exc:
        main_verify_witness()
    assert exc.value.code == 0

    out = capsys.readouterr().out.rstrip("\n")
    assert out == (
        "Usage: mvar-verify-witness <ledger.jsonl> [options]\n\n"
        "Options:\n"
        "  --require-chain     Require valid signature chain\n"
        "  --qseal-key PATH    Verify using provided QSEAL key\n"
        "  --quiet             Minimal output\n"
        "  --json              JSON verification output\n"
        "  -h, --help          Show help"
    )


def test_cli_invalid_args_exit_two(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["mvar-verify-witness"])

    with pytest.raises(SystemExit) as exc:
        main_verify_witness()
    assert exc.value.code == 2

    out = capsys.readouterr().out.rstrip("\n")
    assert out.startswith("Usage: mvar-verify-witness <ledger.jsonl> [options]")


def test_cli_qseal_key_path_is_applied(tmp_path, monkeypatch, capsys):
    witness_path = _build_signed_witness_jsonl(tmp_path, monkeypatch, count=1)
    key_path = tmp_path / "qseal.key"
    key_path.write_text("unit-test-secret\n", encoding="utf-8")

    # Ensure verifier uses --qseal-key and not pre-existing env from test helper.
    monkeypatch.delenv("QSEAL_SECRET", raising=False)
    monkeypatch.setattr(
        sys,
        "argv",
        ["mvar-verify-witness", str(witness_path), "--qseal-key", str(key_path), "--json"],
    )

    with pytest.raises(SystemExit) as exc:
        main_verify_witness()
    assert exc.value.code == 0

    out = capsys.readouterr().out.strip()
    report = json.loads(out)
    assert report["all_signatures_valid"] is True
    assert report["chain_valid"] is True
