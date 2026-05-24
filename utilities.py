import datetime
import json
import os
from typing import Any, cast

import constants as C


def load_json_file(fpath: str, default: Any) -> Any:
    try:
        with open(fpath, C.FILE_MODE_READ, encoding=C.ENCODING_UTF8) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return default


def write_json(fpath: str, data: Any) -> None:
    with open(fpath, C.FILE_MODE_WRITE, encoding=C.ENCODING_UTF8) as fh:
        json.dump(data, fh, indent=C.JSON_INDENT)


def parse_timestamp(value: str) -> int | None:
    """Parse known timestamp formats into unix seconds."""
    if not value:
        return None

    value = str(value).strip()
    if not value or value.startswith(C.TIMESTAMP_INVALID_PREFIX):
        return None

    try:
        normalized = value.replace(C.TIMESTAMP_Z_SUFFIX, C.TIMESTAMP_UTC_OFFSET)
        return int(datetime.datetime.fromisoformat(normalized).timestamp())
    except ValueError:
        pass

    for layout in C.TIMESTAMP_LAYOUTS:
        try:
            return int(datetime.datetime.strptime(value, layout).timestamp())
        except ValueError:
            continue

    return None


def normalize_output_evidence_name(fname: str, sep: str) -> str:
    """Extract evidence id from output file names like plugin_T_input.ext.json."""
    evidence_name = fname.split(sep)[-1]
    return evidence_name.split(C.EXT_JSON)[0]


def skip_missing_or_empty_file(fpath: str) -> bool:
    return (not os.path.exists(fpath)) or os.path.getsize(fpath) == 0


def load_evidence_map(outdir: str, rname: str) -> dict[str, list[Any]]:
    """Load aggregate map file from outdir, returning empty map if unavailable."""
    report_path = os.path.join(outdir, rname)
    report_data: dict[str, list[Any]] = {}
    if os.path.exists(report_path):
        loaded = load_json_file(report_path, {})
        if isinstance(loaded, dict):
            report_data = cast(dict[str, list[Any]], loaded)
    return report_data


def ensure_runtime_dirs(*directories: str) -> None:
    for directory in directories:
        if not os.path.exists(directory):
            os.mkdir(directory)
