import json
from pathlib import Path

import pytest

from volatility_adapter import VolatilityAdapter


PLUGIN_FIXTURES = {
    "windows.filescan": [
        {"Name": "\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe"}
    ],
    "windows.psscan": [
        {
            "PID": 4242,
            "ImageFileName": "cmd.exe",
            "CreateTime": "2024-01-01T10:00:00",
        }
    ],
    "windows.dlllist": [
        {
            "PID": 4242,
            "Name": "kernel32.dll",
            "Path": "C:\\Windows\\System32\\kernel32.dll",
            "LoadTime": "2024-01-01T10:00:01",
        }
    ],
    "windows.netscan": [
        {
            "LocalAddr": "10.0.0.5:4444",
            "ForeignAddr": "93.184.216.34:443",
        }
    ],
}

REQUIRED_KEYS = {
    "windows.filescan": {"Name"},
    "windows.psscan": {"PID", "ImageFileName", "CreateTime"},
    "windows.dlllist": {"PID", "Name", "Path", "LoadTime"},
    "windows.netscan": {"LocalAddr", "ForeignAddr"},
}


@pytest.mark.parametrize("plugin_name", sorted(PLUGIN_FIXTURES.keys()))
def test_library_and_cli_json_shape_parity(monkeypatch, tmp_path, plugin_name):
    out_library = tmp_path / f"{plugin_name}.library.json"
    err_library = tmp_path / f"{plugin_name}.library.err"
    out_cli = tmp_path / f"{plugin_name}.cli.json"
    err_cli = tmp_path / f"{plugin_name}.cli.err"

    fixture = PLUGIN_FIXTURES[plugin_name]

    adapter_lib = VolatilityAdapter(prefer_library=True, enable_cli_fallback=False)

    def fake_library(image_path, requested_plugin, out_path, err_path):
        assert requested_plugin == plugin_name
        Path(out_path).write_text(json.dumps(fixture), encoding="utf-8")
        Path(err_path).write_text("", encoding="utf-8")

    monkeypatch.setattr(adapter_lib, "_run_plugin_library", fake_library)

    adapter_lib.run_plugin("sample.mem", plugin_name, str(out_library), str(err_library))

    adapter_cli = VolatilityAdapter(prefer_library=False, enable_cli_fallback=True)

    def fake_cli(image_path, requested_plugin, out_path, err_path):
        assert requested_plugin == plugin_name
        Path(out_path).write_text(json.dumps(fixture), encoding="utf-8")
        Path(err_path).write_text("", encoding="utf-8")

    monkeypatch.setattr(adapter_cli, "_run_plugin_cli", fake_cli)

    adapter_cli.run_plugin("sample.mem", plugin_name, str(out_cli), str(err_cli))

    lib_data = json.loads(out_library.read_text(encoding="utf-8"))
    cli_data = json.loads(out_cli.read_text(encoding="utf-8"))

    assert isinstance(lib_data, list)
    assert isinstance(cli_data, list)
    assert len(lib_data) == len(cli_data)

    required = REQUIRED_KEYS[plugin_name]
    assert required.issubset(set(lib_data[0].keys()))
    assert required.issubset(set(cli_data[0].keys()))

    # For our migration gate we currently require exact payload parity.
    assert lib_data == cli_data
