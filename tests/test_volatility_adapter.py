from volatility_adapter import VolatilityAdapter


def test_adapter_uses_library_for_psscan(monkeypatch, tmp_path):
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls = []

    def fake_lib(image_path, plugin_name, out_path, err_path):
        calls.append(("library", plugin_name))
        (tmp_path / "out.json").write_text("[]", encoding="utf-8")
        (tmp_path / "err.log").write_text("", encoding="utf-8")

    def fake_cli(image_path, plugin_name, out_path, err_path):
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.psscan", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "library"
    assert calls == [("library", "windows.psscan")]


def test_adapter_uses_cli_for_non_migrated_plugin(monkeypatch, tmp_path):
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls = []

    def fake_lib(image_path, plugin_name, out_path, err_path):
        calls.append(("library", plugin_name))

    def fake_cli(image_path, plugin_name, out_path, err_path):
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.handles", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "cli"
    assert calls == [("cli", "windows.handles")]


def test_adapter_uses_library_for_dlllist(monkeypatch, tmp_path):
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls = []

    def fake_lib(image_path, plugin_name, out_path, err_path):
        calls.append(("library", plugin_name))
        (tmp_path / "out.json").write_text("[]", encoding="utf-8")
        (tmp_path / "err.log").write_text("", encoding="utf-8")

    def fake_cli(image_path, plugin_name, out_path, err_path):
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.dlllist", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "library"
    assert calls == [("library", "windows.dlllist")]


def test_adapter_uses_library_for_netscan(monkeypatch, tmp_path):
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls = []

    def fake_lib(image_path, plugin_name, out_path, err_path):
        calls.append(("library", plugin_name))
        (tmp_path / "out.json").write_text("[]", encoding="utf-8")
        (tmp_path / "err.log").write_text("", encoding="utf-8")

    def fake_cli(image_path, plugin_name, out_path, err_path):
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.netscan", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "library"
    assert calls == [("library", "windows.netscan")]


def test_adapter_uses_library_for_filescan(monkeypatch, tmp_path):
    adapter = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)
    calls = []

    def fake_lib(image_path, plugin_name, out_path, err_path):
        calls.append(("library", plugin_name))
        (tmp_path / "out.json").write_text("[]", encoding="utf-8")
        (tmp_path / "err.log").write_text("", encoding="utf-8")

    def fake_cli(image_path, plugin_name, out_path, err_path):
        calls.append(("cli", plugin_name))

    monkeypatch.setattr(adapter, "_run_plugin_library", fake_lib)
    monkeypatch.setattr(adapter, "_run_plugin_cli", fake_cli)

    mode = adapter.run_plugin("mem.raw", "windows.filescan", str(tmp_path / "out.json"), str(tmp_path / "err.log"))

    assert mode == "library"
    assert calls == [("library", "windows.filescan")]
