import datetime
import json
import os
from typing import Any


def load_json_file(fpath: str, default: Any) -> Any:
    try:
        with open(fpath, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def write_json(fpath: str, data: Any) -> None:
    with open(fpath, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=4)


def parse_timestamp(value: str) -> int | None:
    """Parse known timestamp formats into unix seconds."""
    if not value:
        return None

    value = str(value).strip()
    if not value or value.startswith("1970"):
        return None

    try:
        return int(datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp())
    except ValueError:
        pass

    layouts = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S.%f",
    ]
    for layout in layouts:
        try:
            return int(datetime.datetime.strptime(value, layout).timestamp())
        except ValueError:
            continue

    return None


def normalize_output_evidence_name(fname: str, sep: str) -> str:
    """Extract evidence id from output file names like plugin_T_input.ext.json."""
    evidence_name = fname.split(sep)[-1]
    return evidence_name.split(".json")[0]


def skip_missing_or_empty_file(fpath: str) -> bool:
    return (not os.path.exists(fpath)) or os.path.getsize(fpath) == 0


def load_evidence_map(outdir: str, rname: str) -> dict[str, list[Any]]:
    """Load aggregate map file from outdir, returning empty map if unavailable."""
    report_path = os.path.join(outdir, rname)
    report_data: dict[str, list[Any]] = {}
    if os.path.exists(report_path):
        loaded = load_json_file(report_path, {})
        if isinstance(loaded, dict):
            report_data = loaded
    return report_data


def ensure_runtime_dirs(*directories: str) -> None:
    for directory in directories:
        if not os.path.exists(directory):
            os.mkdir(directory)


def is_playbook_path(inpath: str) -> bool:
    # Keep historical behavior while making intent explicit.
    return "playbook" in inpath
