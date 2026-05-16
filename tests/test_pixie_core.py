import json
from pathlib import Path

from conftest import import_pixie_module


def test_scan_files_best_effort_continues_after_failure(tmp_path, monkeypatch):
    pixie = import_pixie_module()

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for fname in ["a.mem", "b.mem", "c.raw", "d.pcap", "skip.txt"]:
        (evidence / fname).write_bytes(b"x")

    calls = []

    def fake_get_conns(indir, fname):
        calls.append(("get_conns", fname))

    def fake_scan_memory(indir, fname, action):
        calls.append(("scan_memory", fname, action))
        if fname == "a.mem" and action == pixie.WIN_FILESCAN:
            raise RuntimeError("boom")

    def fake_scan_pcap(indir, fname):
        calls.append(("scan_pcap", fname))

    def fake_scan_disk(indir, fname):
        calls.append(("scan_disk", fname))

    monkeypatch.setattr(pixie, "get_conns", fake_get_conns)
    monkeypatch.setattr(pixie, "scan_memory", fake_scan_memory)
    monkeypatch.setattr(pixie, "scan_pcap", fake_scan_pcap)
    monkeypatch.setattr(pixie, "scan_disk", fake_scan_disk)

    pixie.scan_files(str(evidence))

    # a.mem fails but b.mem/c.raw/d.pcap are still processed.
    assert ("scan_memory", "b.mem", pixie.WIN_FILESCAN) in calls
    assert ("scan_disk", "c.raw") in calls
    assert ("scan_pcap", "d.pcap") in calls


def test_scan_memory_is_single_process_and_non_fatal(monkeypatch):
    pixie = import_pixie_module()

    called = {"count": 0}

    def fake_scan_mem_subproc(indir, fname, action):
        called["count"] += 1
        raise RuntimeError("subproc failed")

    monkeypatch.setattr(pixie, "scan_mem_subproc", fake_scan_mem_subproc)

    # Should not raise; scan_memory handles exceptions internally.
    pixie.scan_memory("in", "sample.mem", pixie.WIN_FILESCAN)
    assert called["count"] == 1


def test_parse_timestamp_supports_common_formats():
    pixie = import_pixie_module()

    assert pixie.parse_timestamp("2024-01-02T03:04:05") is not None
    assert pixie.parse_timestamp("2024-01-02 03:04:05") is not None
    assert pixie.parse_timestamp("2024-01-02T03:04:05.123456") is not None
    assert pixie.parse_timestamp("1970-01-01T00:00:00") is None
    assert pixie.parse_timestamp("not-a-time") is None


def test_ps_match_generates_expected_output(tmp_path, monkeypatch):
    pixie = import_pixie_module()

    monkeypatch.setattr(pixie, "OUTDIR", str(tmp_path))

    psscan = tmp_path / f"{pixie.WIN_PSSCAN}{pixie.SEP}mem1.json"
    dlllist = tmp_path / f"{pixie.WIN_DLLLIST}{pixie.SEP}mem1.json"
    files = tmp_path / "files_T_disk1.raw.json"

    psscan.write_text(
        json.dumps([
            {
                "PID": 123,
                "ImageFileName": "calc.exe",
                "CreateTime": "2024-01-01T10:00:00"
            }
        ]),
        encoding="utf-8",
    )
    dlllist.write_text(
        json.dumps([
            {
                "PID": 123,
                "Path": "C:\\Windows\\System32\\calc.exe",
                "Name": "kernel32.dll",
                "LoadTime": "2024-01-01T10:00:01"
            }
        ]),
        encoding="utf-8",
    )
    files.write_text(
        json.dumps(
            {
                "C:/Windows/System32/calc.exe": {
                    "name": "calc.exe",
                    "atime": "2024-01-01T10:00:30"
                }
            }
        ),
        encoding="utf-8",
    )

    pixie.ps_match(100)

    out = tmp_path / "procmatches.json"
    assert out.exists()

    matches = json.loads(out.read_text(encoding="utf-8"))
    assert len(matches) == 1
    assert matches[0]["evi"] == "disk1.raw"
    assert matches[0]["fpath"].lower().endswith("calc.exe")
    assert len(matches[0]["relations"]) == 1


def test_common_report_skips_malformed_input_file(tmp_path, monkeypatch):
    pixie = import_pixie_module()
    monkeypatch.setattr(pixie, "OUTDIR", str(tmp_path))

    bad = tmp_path / f"{pixie.WIN_FILESCAN}{pixie.SEP}evi1.mem.json"
    bad.write_text("{not-json", encoding="utf-8")

    # Should safely degrade to an empty aggregate output.
    pixie.common_report(bad.name, "files.json", "Name")
    out = tmp_path / "files.json"
    assert out.exists()
    assert json.loads(out.read_text(encoding="utf-8")) == {}


def test_common_conns_skips_non_list_json(tmp_path, monkeypatch):
    pixie = import_pixie_module()
    monkeypatch.setattr(pixie, "OUTDIR", str(tmp_path))

    src = tmp_path / f"conns{pixie.SEP}evi1.mem.json"
    src.write_text(json.dumps({"not": "a-list"}), encoding="utf-8")

    pixie.common_conns(src.name, "conns.json")
    assert not (tmp_path / "conns.json").exists()


def test_common_files_skips_non_dict_json(tmp_path, monkeypatch):
    pixie = import_pixie_module()
    monkeypatch.setattr(pixie, "OUTDIR", str(tmp_path))

    src = tmp_path / f"files{pixie.SEP}disk1.raw.json"
    src.write_text(json.dumps(["not-a-dict"]), encoding="utf-8")

    pixie.common_files(src.name, "files.json")
    assert not (tmp_path / "files.json").exists()


def test_auto_triage_invokes_pipeline_in_order(monkeypatch):
    pixie = import_pixie_module()
    calls = []

    monkeypatch.setattr(pixie, "scan_files", lambda indir: calls.append(("scan_files", indir)))
    monkeypatch.setattr(pixie, "commonality", lambda: calls.append(("commonality",)))
    monkeypatch.setattr(pixie, "ps_match", lambda deviation: calls.append(("ps_match", deviation)))

    pixie.auto_triage("evidence_dir")

    assert calls == [
        ("scan_files", "evidence_dir"),
        ("commonality",),
        ("ps_match", 100),
    ]


def test_main_cli_smoke_mixed_evidence_best_effort(tmp_path, monkeypatch):
    pixie = import_pixie_module()

    evidence = tmp_path / "evidence"
    evidence.mkdir()
    for fname in ["bad.mem", "net.pcap", "disk.raw", "note.txt"]:
        (evidence / fname).write_bytes(b"x")

    outdir = tmp_path / "data"
    errdir = tmp_path / "err"
    monkeypatch.setattr(pixie, "OUTDIR", str(outdir))
    monkeypatch.setattr(pixie, "ERRDIR", str(errdir))

    calls = []

    def fake_get_conns(indir, fname):
        calls.append(("get_conns", fname))

    def fake_scan_memory(indir, fname, action):
        calls.append(("scan_memory", fname, action))
        if fname == "bad.mem":
            raise RuntimeError("simulated scan failure")

    def fake_scan_pcap(indir, fname):
        calls.append(("scan_pcap", fname))

    def fake_scan_disk(indir, fname):
        calls.append(("scan_disk", fname))

    def fake_commonality():
        calls.append(("commonality",))

    def fake_ps_match(deviation):
        calls.append(("ps_match", deviation))

    monkeypatch.setattr(pixie, "get_conns", fake_get_conns)
    monkeypatch.setattr(pixie, "scan_memory", fake_scan_memory)
    monkeypatch.setattr(pixie, "scan_pcap", fake_scan_pcap)
    monkeypatch.setattr(pixie, "scan_disk", fake_scan_disk)
    monkeypatch.setattr(pixie, "commonality", fake_commonality)
    monkeypatch.setattr(pixie, "ps_match", fake_ps_match)
    monkeypatch.setattr(pixie.sys, "argv", ["pixie.py", str(evidence)])

    pixie.main()

    assert outdir.exists()
    assert errdir.exists()
    assert ("scan_pcap", "net.pcap") in calls
    assert ("scan_disk", "disk.raw") in calls
    assert ("commonality",) in calls
    assert ("ps_match", 100) in calls


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
