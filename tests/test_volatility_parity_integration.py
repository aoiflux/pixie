import json
import os
from pathlib import Path
from typing import Any

import pytest

from volatility_adapter import VolatilityAdapter

PLUGIN_REQUIRED_KEYS: dict[str, set[str]] = {
    "windows.filescan": {"Name"},
    "windows.psscan": {"PID", "ImageFileName", "CreateTime"},
    "windows.dlllist": {"PID", "Name", "Path", "LoadTime"},
    "windows.netscan": {"LocalAddr", "ForeignAddr"},
}


def _shape_signature(rows: list[dict[str, Any]]) -> set[str]:
    keys = set()
    for row in rows:
        keys.update(row.keys())
    return keys


@pytest.mark.integration
@pytest.mark.parametrize("plugin_name", sorted(PLUGIN_REQUIRED_KEYS.keys()))
def test_live_library_cli_parity(plugin_name: str, tmp_path: Path):
    """Runs real volatility adapter paths against one memory image.

    This is opt-in and skipped unless PIXIE_INTEGRATION_MEM_IMAGE is provided.
    """
    mem_image = os.environ.get("PIXIE_INTEGRATION_MEM_IMAGE", "").strip()
    if not mem_image:
        pytest.skip("Set PIXIE_INTEGRATION_MEM_IMAGE to run live parity tests")

    mem_path = Path(mem_image)
    if not mem_path.exists() or not mem_path.is_file():
        pytest.skip("PIXIE_INTEGRATION_MEM_IMAGE does not point to a readable file")

    out_library = tmp_path / f"{plugin_name}.library.json"
    err_library = tmp_path / f"{plugin_name}.library.err"
    out_cli = tmp_path / f"{plugin_name}.cli.json"
    err_cli = tmp_path / f"{plugin_name}.cli.err"

    adapter_library = VolatilityAdapter(prefer_library=True, enable_cli_fallback=False)
    mode_library = adapter_library.run_plugin(
        str(mem_path),
        plugin_name,
        str(out_library),
        str(err_library),
    )
    assert mode_library == "library"

    adapter_cli = VolatilityAdapter(prefer_library=False, enable_cli_fallback=True)
    mode_cli = adapter_cli.run_plugin(
        str(mem_path),
        plugin_name,
        str(out_cli),
        str(err_cli),
    )
    assert mode_cli == "cli"

    lib_data = json.loads(out_library.read_text(encoding="utf-8"))
    cli_data = json.loads(out_cli.read_text(encoding="utf-8"))

    assert isinstance(lib_data, list)
    assert isinstance(cli_data, list)

    required_keys = PLUGIN_REQUIRED_KEYS[plugin_name]
    lib_keys = _shape_signature(lib_data)
    cli_keys = _shape_signature(cli_data)

    # Schema compatibility gate for downstream consumers.
    assert required_keys.issubset(lib_keys)
    assert required_keys.issubset(cli_keys)

    # Runtime parity contract: row count and discovered key-shape should match.
    assert len(lib_data) == len(cli_data)
    assert lib_keys == cli_keys
