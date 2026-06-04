import json
from pathlib import Path

import pytest
from conftest import import_pixie_module


def test_scan_files_best_effort_continues_after_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pixie = import_pixie_module()

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for fname in ["a.mem", "b.mem", "c.raw", "d.pcap", "skip.txt"]:
        (evidence / fname).write_bytes(b"x")

    calls: list[tuple[str, str] | tuple[str, str, str]] = []

    def fake_scan_memory(indir: str, fname: str, action: str) -> None:
        calls.append(("scan_memory", fname, action))
        if fname == "a.mem" and action == pixie.WIN_FILESCAN:
            raise RuntimeError("boom")

    def fake_scan_pcap(indir: str, fname: str) -> None:
        calls.append(("scan_pcap", fname))

    def fake_scan_disk(indir: str, fname: str) -> None:
        calls.append(("scan_disk", fname))

    monkeypatch.setattr(pixie, "scan_memory", fake_scan_memory)
    monkeypatch.setattr(pixie, "scan_pcap", fake_scan_pcap)
    monkeypatch.setattr(pixie, "scan_disk", fake_scan_disk)

    pixie.scan_files(str(evidence))

    # a.mem fails but b.mem/c.raw/d.pcap are still processed.
    assert ("scan_memory", "b.mem", pixie.WIN_FILESCAN) in calls
    assert ("scan_disk", "c.raw") in calls
    assert ("scan_pcap", "d.pcap") in calls


def test_scan_memory_is_single_process_and_non_fatal(monkeypatch: pytest.MonkeyPatch) -> None:
    pixie = import_pixie_module()

    called = {"count": 0}

    def fake_scan_mem_subproc(indir: str, fname: str, action: str) -> None:
        called["count"] += 1
        raise RuntimeError("subproc failed")

    monkeypatch.setattr(pixie, "scan_mem_subproc", fake_scan_mem_subproc)

    # Should not raise; scan_memory handles exceptions internally.
    pixie.scan_memory("in", "sample.mem", pixie.WIN_FILESCAN)
    assert called["count"] == 1


def test_parse_timestamp_supports_common_formats() -> None:
    pixie = import_pixie_module()

    assert pixie.parse_timestamp("2024-01-02T03:04:05") is not None
    assert pixie.parse_timestamp("2024-01-02 03:04:05") is not None
    assert pixie.parse_timestamp("2024-01-02T03:04:05.123456") is not None
    assert pixie.parse_timestamp("1970-01-01T00:00:00") is None
    assert pixie.parse_timestamp("not-a-time") is None


def test_auto_triage_invokes_pipeline_in_order(monkeypatch: pytest.MonkeyPatch) -> None:
    pixie = import_pixie_module()
    calls: list[tuple[str, str] | tuple[str]] = []

    monkeypatch.setattr(pixie, "scan_files", lambda indir: calls.append(("scan_files", indir)))
    monkeypatch.setattr(pixie, "normalize_artifacts", lambda: calls.append(("normalize_artifacts",)))
    monkeypatch.setattr(pixie, "run_correlations", lambda: calls.append(("run_correlations",)))

    pixie.auto_triage("evidence_dir")

    assert calls == [
        ("scan_files", "evidence_dir"),
        ("normalize_artifacts",),
        ("run_correlations",),
    ]


def test_auto_triage_extract_only_skips_correlations(monkeypatch: pytest.MonkeyPatch) -> None:
    pixie = import_pixie_module()
    calls: list[tuple[str, str] | tuple[str]] = []

    monkeypatch.setattr(pixie, "scan_files", lambda indir: calls.append(("scan_files", indir)))
    monkeypatch.setattr(pixie, "normalize_artifacts", lambda: calls.append(("normalize_artifacts",)))
    monkeypatch.setattr(pixie, "run_correlations", lambda: calls.append(("run_correlations",)))

    pixie.auto_triage("evidence_dir", include_correlations=False)

    assert calls == [
        ("scan_files", "evidence_dir"),
        ("normalize_artifacts",),
    ]


def test_main_cli_smoke_mixed_evidence_best_effort(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pixie = import_pixie_module()

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for fname in ["bad.mem", "net.pcap", "disk.raw", "note.txt"]:
        (evidence / fname).write_bytes(b"x")

    outdir = tmp_path / "data"
    errdir = tmp_path / "err"
    monkeypatch.setattr(pixie, "OUTDIR", str(outdir))
    monkeypatch.setattr(pixie, "ERRDIR", str(errdir))

    calls: list[tuple[str, str] | tuple[str, str, str] | tuple[str]] = []

    def fake_scan_memory(indir: str, fname: str, action: str) -> None:
        calls.append(("scan_memory", fname, action))
        if fname == "bad.mem":
            raise RuntimeError("simulated scan failure")

    def fake_scan_pcap(indir: str, fname: str) -> None:
        calls.append(("scan_pcap", fname))

    def fake_scan_disk(indir: str, fname: str) -> None:
        calls.append(("scan_disk", fname))

    def fake_normalize_artifacts() -> None:
        calls.append(("normalize_artifacts",))

    def fake_run_correlations() -> None:
        calls.append(("run_correlations",))

    monkeypatch.setattr(pixie, "scan_memory", fake_scan_memory)
    monkeypatch.setattr(pixie, "scan_pcap", fake_scan_pcap)
    monkeypatch.setattr(pixie, "scan_disk", fake_scan_disk)
    monkeypatch.setattr(pixie, "normalize_artifacts", fake_normalize_artifacts)
    monkeypatch.setattr(pixie, "run_correlations", fake_run_correlations)
    monkeypatch.setattr(pixie.sys, "argv", ["pixie.py", str(evidence)])

    pixie.main()

    assert outdir.exists()
    assert errdir.exists()
    assert ("scan_pcap", "net.pcap") in calls
    assert ("scan_disk", "disk.raw") in calls
    assert ("normalize_artifacts",) in calls
    assert ("run_correlations",) in calls


def test_main_cli_extract_only_skips_correlations(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pixie = import_pixie_module()

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "sample.mem").write_bytes(b"x")

    outdir = tmp_path / "data"
    errdir = tmp_path / "err"
    monkeypatch.setattr(pixie, "OUTDIR", str(outdir))
    monkeypatch.setattr(pixie, "ERRDIR", str(errdir))

    calls: list[tuple[str, str, str] | tuple[str]] = []

    monkeypatch.setattr(pixie, "scan_memory", lambda indir, fname, action: calls.append(("scan_memory", fname, action)))
    monkeypatch.setattr(pixie, "normalize_artifacts", lambda: calls.append(("normalize_artifacts",)))
    monkeypatch.setattr(pixie, "run_correlations", lambda: calls.append(("run_correlations",)))
    monkeypatch.setattr(pixie.sys, "argv", ["pixie.py", pixie.C.CLI_EXTRACT_ONLY, str(evidence)])

    pixie.main()

    assert outdir.exists()
    assert errdir.exists()
    assert ("normalize_artifacts",) in calls
    assert ("run_correlations",) not in calls


def test_normalize_artifacts_generates_expected_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pixie = import_pixie_module()
    monkeypatch.setattr(pixie, "OUTDIR", str(tmp_path))

    (tmp_path / f"{pixie.WIN_PSSCAN}{pixie.SEP}mem1.json").write_text(
        json.dumps([
            {
                "PID": 111,
                "PPID": 4,
                "ImageFileName": "evil.exe",
                "CreateTime": "2024-01-01T10:00:00",
                "CommandLine": "C:/Users/Public/evil.exe -q",
                "Path": "C:/Users/Public/evil.exe",
            }
        ]),
        encoding="utf-8",
    )
    (tmp_path / f"{pixie.WIN_NETSCAN}{pixie.SEP}mem1.json").write_text(
        json.dumps([
            {
                "PID": 111,
                "LocalAddr": "10.0.0.5:50000",
                "ForeignAddr": "8.8.8.8:443",
                "Protocol": "TCP",
            }
        ]),
        encoding="utf-8",
    )
    (tmp_path / "files_T_disk1.raw.json").write_text(
        json.dumps(
            {
                "C:/Users/Public/evil.exe": {
                    "name": "evil.exe",
                    "atime": "2024-01-01T10:01:00",
                    "created": "2024-01-01T09:59:50",
                    "modified": "2024-01-01T10:00:10",
                    "is_executable": True,
                }
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "sample.pcap.json").write_text(
        json.dumps([
            {
                "src": "10.0.0.5",
                "dst": "8.8.8.8",
                "src_port": 50000,
                "dst_port": 443,
                "timestamp": "2024-01-01T10:00:05+00:00",
            }
        ]),
        encoding="utf-8",
    )

    pixie.normalize_artifacts()

    mem = json.loads((tmp_path / "memory_artifacts.json").read_text(encoding="utf-8"))
    disk = json.loads((tmp_path / "disk_artifacts.json").read_text(encoding="utf-8"))
    net = json.loads((tmp_path / "network_artifacts.json").read_text(encoding="utf-8"))

    assert len(mem) == 1
    assert mem[0]["processes"][0]["pid"] == "111"
    assert mem[0]["processes"][0]["ppid"] == "4"
    assert mem[0]["sockets"][0]["remote_ip"] == "8.8.8.8"
    assert mem[0]["sockets"][0]["remote_port"] == 443

    assert len(disk) == 1
    assert disk[0]["files"][0]["file_name"] == "evil.exe"
    assert disk[0]["files"][0]["execution_indicator"] is True

    assert len(net) == 1
    assert net[0]["connections"][0]["dst_ip"] == "8.8.8.8"
    assert net[0]["connections"][0]["timestamp"]


def test_run_correlations_process_and_fileless_scenarios(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    pixie = import_pixie_module()
    monkeypatch.setattr(pixie, "OUTDIR", str(tmp_path))

    (tmp_path / "memory_artifacts.json").write_text(
        json.dumps([
            {
                "evidence": "mem1",
                "processes": [
                    {
                        "pid": "111",
                        "ppid": "4",
                        "process_name": "evil.exe",
                        "command_line": "C:/Users/Public/evil.exe -q",
                        "image_path": "C:/Users/Public/evil.exe",
                        "start_time": "2024-01-01T10:00:00",
                    }
                ],
                "sockets": [
                    {
                        "pid": "111",
                        "process_name": "evil.exe",
                        "local_endpoint": "10.0.0.5:50000",
                        "remote_endpoint": "8.8.8.8:443",
                        "remote_ip": "8.8.8.8",
                        "remote_port": 443,
                        "protocol": "TCP",
                        "state": "ESTABLISHED",
                    }
                ],
            }
        ]),
        encoding="utf-8",
    )
    (tmp_path / "disk_artifacts.json").write_text(
        json.dumps([
            {
                "evidence": "disk1",
                "files": [
                    {
                        "file_name": "evil.exe",
                        "file_path": "C:/Users/Public/evil.exe",
                        "created_time": "2024-01-01T09:59:50",
                        "modified_time": "2024-01-01T10:00:10",
                        "access_time": "2024-01-01T10:01:00",
                        "execution_indicator": True,
                    }
                ],
            }
        ]),
        encoding="utf-8",
    )
    (tmp_path / "network_artifacts.json").write_text(
        json.dumps([
            {
                "evidence": "net1",
                "connections": [
                    {
                        "src_ip": "10.0.0.5",
                        "dst_ip": "8.8.8.8",
                        "src_port": 50000,
                        "dst_port": 443,
                        "timestamp": "2024-01-01T10:00:05+00:00",
                    }
                ],
            }
        ]),
        encoding="utf-8",
    )

    pixie.run_correlations(time_window_seconds=600)

    output = json.loads((tmp_path / "correlations.json").read_text(encoding="utf-8"))
    assert any(row.get("scenario") == "process-centric" for row in output)
    assert any(row.get("scenario") == "fileless" for row in output)

    proc = [row for row in output if row.get("scenario") == "process-centric"][0]
    assert proc["match_strength"] in {"medium", "strong"}
    assert proc["process"]["process_name"].lower() == "evil.exe"

    fileless = [row for row in output if row.get("scenario") == "fileless"][0]
    assert fileless["socket"]["remote_ip"] == "8.8.8.8"
    assert fileless["notes"]["port_match"] is True


def test_scan_mem_subproc_uses_adapter_contract(tmp_path, monkeypatch):
    pixie = import_pixie_module()
    monkeypatch.setattr(pixie, "OUTDIR", str(tmp_path / "data"))
    monkeypatch.setattr(pixie, "ERRDIR", str(tmp_path / "err"))
    (tmp_path / "data").mkdir()
    (tmp_path / "err").mkdir()

    calls = []

    class FakeAdapter:
        def run_plugin(self, image_path, plugin_name, out_path, err_path):
            calls.append((image_path, plugin_name, out_path, err_path))
            # Simulate successful plugin with non-empty output
            Path(out_path).write_text("[]", encoding="utf-8")
            Path(err_path).write_text("", encoding="utf-8")
            return "library"

    monkeypatch.setattr(pixie, "VOLATILITY_ADAPTER", FakeAdapter())

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    mem_file = evidence_dir / "a.mem"
    mem_file.write_bytes(b"x")

    pixie.scan_mem_subproc(str(evidence_dir), "a.mem", pixie.WIN_PSSCAN)

    assert len(calls) == 1
    assert calls[0][0] == str(mem_file)
    assert calls[0][1] == pixie.WIN_PSSCAN
    assert Path(calls[0][2]).exists()
    assert Path(calls[0][3]).exists()
