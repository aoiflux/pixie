from volatility_adapter import VolatilityAdapter
from pathlib import Path
import pytest


def test_adapter_uses_library_for_psscan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls: list[tuple[str, str]] = []

    def fake_lib(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("library", plugin_name))
        (tmp_path / "out.json").write_text("[]", encoding="utf-8")
        (tmp_path / "err.log").write_text("", encoding="utf-8")

    def fake_cli(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.psscan", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "library"
    assert calls == [("library", "windows.psscan")]


def test_adapter_uses_cli_for_non_migrated_plugin(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls: list[tuple[str, str]] = []

    def fake_lib(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("library", plugin_name))

    def fake_cli(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.handles", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "cli"
    assert calls == [("cli", "windows.handles")]


def test_adapter_uses_library_for_dlllist(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls: list[tuple[str, str]] = []

    def fake_lib(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("library", plugin_name))
        (tmp_path / "out.json").write_text("[]", encoding="utf-8")
        (tmp_path / "err.log").write_text("", encoding="utf-8")

    def fake_cli(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.dlllist", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "library"
    assert calls == [("library", "windows.dlllist")]


def test_adapter_uses_library_for_netscan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls: list[tuple[str, str]] = []

    def fake_lib(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("library", plugin_name))
        (tmp_path / "out.json").write_text("[]", encoding="utf-8")
        (tmp_path / "err.log").write_text("", encoding="utf-8")

    def fake_cli(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.netscan", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "library"
    assert calls == [("library", "windows.netscan")]


def test_adapter_uses_library_for_filescan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls: list[tuple[str, str]] = []

    def fake_lib(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("library", plugin_name))
        (tmp_path / "out.json").write_text("[]", encoding="utf-8")
        (tmp_path / "err.log").write_text("", encoding="utf-8")

    def fake_cli(image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.filescan", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "library"
    assert calls == [("library", "windows.filescan")]
