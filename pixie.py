from typing import Any, Mapping, TypedDict, cast
import datetime
from pathlib import Path
import glob
import sys
import os
import socket
import logging

import constants as C
from utilities import ensure_runtime_dirs, load_json_file, normalize_output_evidence_name, parse_timestamp, write_json
from volatility_adapter import VolatilityAdapter
import pytsk3
import dpkt  # type: ignore[import-untyped]

# Backward-compatible exports expected by tests/callers.
WIN_FILESCAN = C.WIN_FILESCAN
WIN_PSSCAN = C.WIN_PSSCAN
WIN_NETSCAN = C.WIN_NETSCAN
WIN_DLLLIST = C.WIN_DLLLIST
SEP = C.SEP
OUTDIR = C.OUTDIR
ERRDIR = C.ERRDIR
DEFAULT_TIME_WINDOW_SECONDS = C.DEFAULT_TIME_WINDOW_SECONDS

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format=C.LOG_FORMAT)

JsonMap = dict[str, Any]
PathMetaMap = dict[str, dict[str, str | bool]]
ConnRecord = dict[str, str | int | None]


class ProcessRow(TypedDict):
    pid: str
    ppid: str
    process_name: str
    command_line: str
    image_path: str
    start_time: str
    parent_name: str


class SocketRow(TypedDict):
    pid: str
    process_name: str
    local_endpoint: str
    remote_endpoint: str
    remote_ip: str
    remote_port: int | None
    protocol: str
    state: str


class DiskFileRow(TypedDict):
    file_name: str
    file_path: str
    created_time: str
    modified_time: str
    access_time: str
    execution_indicator: bool


class NetworkConnRow(TypedDict):
    src_ip: str
    dst_ip: str
    src_port: Any
    dst_port: Any
    timestamp: str
    remote_candidates: list[str]


class MemoryArtifact(TypedDict):
    evidence: str
    processes: list[ProcessRow]
    sockets: list[SocketRow]


class DiskArtifact(TypedDict):
    evidence: str
    files: list[DiskFileRow]


class NetworkArtifact(TypedDict):
    evidence: str
    connections: list[NetworkConnRow]


class ProcessEvidence(TypedDict):
    memory: str
    disk: str


class FilelessEvidence(TypedDict):
    memory: str
    network: str


class ProcessNotes(TypedDict):
    path_match: bool
    time_aligned: bool
    uncertainty: list[str]


class FilelessNotes(TypedDict):
    port_match: bool
    process_attributed: bool
    uncertainty: list[str]


class ProcessCorrelation(TypedDict):
    scenario: str
    match_strength: str
    confidence_score: int
    join_keys: list[str]
    evidence: ProcessEvidence
    process: ProcessRow
    disk_file: DiskFileRow
    notes: ProcessNotes
    statement: str


class FilelessCorrelation(TypedDict):
    scenario: str
    match_strength: str
    confidence_score: int
    join_keys: list[str]
    evidence: FilelessEvidence
    socket: SocketRow
    network_connection: NetworkConnRow
    notes: FilelessNotes
    statement: str


ProcessRecord = tuple[str, ProcessRow]
SocketRecord = tuple[str, SocketRow]
DiskRecord = tuple[str, DiskFileRow]
NetworkRecord = tuple[str, NetworkConnRow]
CorrelationRow = ProcessCorrelation | FilelessCorrelation

VOLATILITY_ADAPTER = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)


def _norm_join_path(value: str) -> str:
    return str(value).replace(C.KEY_BACKSLASH, C.KEY_SLASH).lower()


def _path_basename(value: str) -> str:
    return Path(_norm_join_path(value)).name


def _safe_str(row: Mapping[str, Any], key: str, default: str = C.KEY_EMPTY) -> str:
    return str(row.get(key, default)).strip()


def _as_any_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return cast(list[Any], value)
    return []


def _as_json_map(value: Any) -> JsonMap:
    if isinstance(value, dict):
        return cast(JsonMap, value)
    return {}


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _first_present(row: Mapping[str, Any], keys: tuple[str, ...], default: str = C.KEY_EMPTY) -> str:
    for key in keys:
        value = row.get(key)
        if value is None:
            continue
        sval = str(value).strip()
        if sval:
            return sval
    return default


def _scan_error_path(action: str, fname: str) -> str:
    return os.path.join(ERRDIR, C.ERR_PREFIX + C.SEP + action + C.SEP + fname + C.EXT_LOG)


def _scan_output_path(action: str, fname: str) -> str:
    return os.path.join(OUTDIR, action + C.SEP + fname + C.EXT_JSON)


def scan_memory(indir: str, fname: str, action: str) -> None:
    try:
        scan_mem_subproc(indir, fname, action)
    except Exception as e:
        logger.exception(C.MSG_SCAN_ERROR, fname, action, e)


def scan_mem_subproc(indir: str, fname: str, action: str) -> None:
    inpath = os.path.join(indir, fname)
    outpath = _scan_output_path(action, fname)
    errpath = _scan_error_path(action, fname)
    VOLATILITY_ADAPTER.run_plugin(inpath, action, outpath, errpath)
    if os.path.exists(outpath) and os.path.getsize(outpath) == 0:
        os.remove(outpath)


def scan_pcap(indir: str, fname: str) -> None:
    rows: list[ConnRecord] = []
    fpath = os.path.join(indir, fname)
    with open(fpath, C.FILE_MODE_READ_BINARY) as fh:
        dpkt_api = cast(Any, dpkt)
        reader = dpkt_api.pcapng.Reader if fname.lower().endswith(C.EXT_PCAPNG) else dpkt_api.pcap.Reader
        for ts, buf in reader(fh):
            row = _parse_packet_row(dpkt_api, ts, buf)
            if row:
                rows.append(row)
    write_json(os.path.join(OUTDIR, fname + C.EXT_JSON), rows)


def _parse_packet_row(dpkt_api: Any, ts: Any, buf: bytes) -> ConnRecord | None:
    try:
        eth = dpkt_api.ethernet.Ethernet(buf)
        ip = eth.data
        if not hasattr(ip, C.ATTR_SRC) or not hasattr(ip, C.ATTR_DST):
            return None
        src_ip = socket.inet_ntoa(cast(bytes, getattr(ip, C.ATTR_SRC)))
        dst_ip = socket.inet_ntoa(cast(bytes, getattr(ip, C.ATTR_DST)))
        src_port = getattr(ip.data, C.ATTR_SPORT, None)
        dst_port = getattr(ip.data, C.ATTR_DPORT, None)
        ts_iso = datetime.datetime.fromtimestamp(float(ts), tz=datetime.timezone.utc).isoformat()
        return {
            C.IN_SRC: src_ip,
            C.IN_DST: dst_ip,
            C.IN_SRC_PORT: src_port,
            C.IN_DST_PORT: dst_port,
            C.IN_TIMESTAMP: ts_iso,
        }
    except (ValueError, AttributeError, dpkt_api.dpkt.NeedData):
        return None


def scan_disk(indir: str, fname: str) -> None:
    tsk = cast(Any, pytsk3)
    img = tsk.Img_Info(os.path.join(indir, fname))
    fs = tsk.FS_Info(img)
    root = fs.open_dir(path=C.KEY_SLASH)
    write_json(os.path.join(OUTDIR, C.FILES_PREFIX + C.SEP + fname + C.EXT_JSON), list_files(root))


def list_files(root: Any) -> PathMetaMap:
    stack: list[tuple[Any, str]] = [(root, C.KEY_EMPTY)]
    output: PathMetaMap = {}
    while stack:
        current_dir, parent = stack.pop()
        for fsobj in current_dir:
            parsed = _parse_fsobj(fsobj, parent)
            if not parsed:
                continue
            kind, path, payload = parsed
            if kind == C.KEY_DOT:
                stack.append((payload, path))
                continue
            output[path] = payload
    return output


def _parse_fsobj(fsobj: Any, parent: str) -> tuple[str, str, Any] | None:
    raw_name = fsobj.info.name.name
    name = raw_name.decode(C.ENCODING_UTF8, errors=C.ERRORS_IGNORE) if isinstance(raw_name, (bytes, bytearray)) else str(raw_name)
    if name in {C.KEY_DOT, C.KEY_DOTDOT}:
        return None

    path = f"{parent}{C.KEY_SLASH}{name}" if parent else name
    meta = fsobj.info.meta
    if meta is None:
        return C.KEY_EMPTY, path, _file_meta(name, C.UNKNOWN_TIME, C.UNKNOWN_TIME, C.UNKNOWN_TIME)

    if meta.type == cast(Any, pytsk3).TSK_FS_META_TYPE_DIR:
        return C.KEY_DOT, path, fsobj.as_directory()

    atime = _meta_time(meta.atime)
    ctime = _meta_time(getattr(meta, C.ATTR_CRTIME, 0))
    mtime = _meta_time(getattr(meta, C.ATTR_MTIME, 0))
    return C.KEY_EMPTY, path, _file_meta(name, atime, ctime, mtime)


def _meta_time(value: Any) -> str:
    if value:
        return datetime.datetime.fromtimestamp(value).isoformat()
    return C.UNKNOWN_TIME


def _file_meta(name: str, atime: str, ctime: str, mtime: str) -> dict[str, str | bool]:
    return {
        C.META_NAME: name,
        C.META_ATIME: atime,
        C.META_CREATED: ctime,
        C.META_MODIFIED: mtime,
        C.META_IS_EXECUTABLE: name.lower().endswith(C.EXT_EXE),
    }


def scan_files(indir: str) -> None:
    for fname in sorted(os.listdir(indir)):
        fpath = os.path.join(indir, fname)
        if not os.path.isfile(fpath):
            continue
        ext = fname.split(C.KEY_DOT)[-1].lower()
        try:
            _scan_by_extension(indir, fname, ext)
        except Exception:
            logger.exception(C.MSG_FILE_FAIL, fname)


def _scan_by_extension(indir: str, fname: str, ext: str) -> None:
    if ext in C.MEMORY_EXTENSIONS:
        for action in C.SCAN_ACTIONS:
            scan_memory(indir, fname, action)
        return
    if ext in C.PACKET_EXTENSIONS:
        scan_pcap(indir, fname)
        return
    if ext in C.DISK_EXTENSIONS:
        scan_disk(indir, fname)


def _base_name(value: str) -> str:
    return _path_basename(value).lower()


def _normalize_path(value: str) -> str:
    return _norm_join_path(value).strip()


def _split_ip_port(endpoint: str) -> tuple[str, int | None]:
    value = str(endpoint or C.KEY_EMPTY).strip()
    if not value:
        return C.KEY_EMPTY, None
    if C.KEY_COLON not in value:
        return value, None
    ip, port = value.rsplit(C.KEY_COLON, 1)
    parsed = _safe_int(port)
    if parsed is None:
        return value, None
    return ip, parsed


def _build_memory_artifacts() -> list[MemoryArtifact]:
    artifacts: list[MemoryArtifact] = []
    pattern = os.path.join(OUTDIR, C.WIN_PSSCAN + C.GLOB_ALL)
    for psscan_file in glob.glob(pattern):
        psscan_rows = _as_rows(load_json_file(psscan_file, []))
        netscan_rows = _as_rows(load_json_file(psscan_file.replace(C.WIN_PSSCAN, C.WIN_NETSCAN), []))
        evidence = normalize_output_evidence_name(psscan_file, C.SEP)
        processes, index = _normalize_processes(psscan_rows)
        sockets = _normalize_sockets(netscan_rows, index)
        artifacts.append({C.OUT_EVIDENCE: evidence, C.OUT_PROCESSES: processes, C.OUT_SOCKETS: sockets})
    return artifacts


def _as_rows(value: Any) -> list[JsonMap]:
    rows: list[JsonMap] = []
    for row in _as_any_list(value):
        if isinstance(row, dict):
            rows.append(cast(JsonMap, row))
    return rows


def _normalize_processes(rows: list[JsonMap]) -> tuple[list[ProcessRow], dict[str, ProcessRow]]:
    processes = [_normalize_process_row(row) for row in rows]
    index = {str(row.get(C.OUT_PID, C.KEY_EMPTY)): row for row in processes if str(row.get(C.OUT_PID, C.KEY_EMPTY))}
    for row in processes:
        ppid = _safe_str(row, C.OUT_PPID)
        parent = index.get(ppid)
        row[C.OUT_PARENT_NAME] = _safe_str(parent or {}, C.OUT_PROCESS_NAME)
    return processes, index


def _normalize_process_row(row: JsonMap) -> ProcessRow:
    return {
        C.OUT_PID: _safe_str(row, C.IN_PID),
        C.OUT_PPID: _first_present(row, (C.IN_PPID, C.IN_PARENT_PID)),
        C.OUT_PROCESS_NAME: _first_present(row, (C.IN_IMAGE_FILE_NAME, C.IN_NAME)),
        C.OUT_COMMAND_LINE: _first_present(row, (C.IN_COMMAND_LINE, C.IN_CMDLINE)),
        C.OUT_IMAGE_PATH: _first_present(row, (C.IN_PATH, C.IN_IMAGE_PATH)),
        C.OUT_START_TIME: _first_present(row, (C.IN_CREATE_TIME, C.IN_START_TIME)),
        C.OUT_PARENT_NAME: C.KEY_EMPTY,
    }


def _normalize_sockets(rows: list[JsonMap], process_index: dict[str, ProcessRow]) -> list[SocketRow]:
    sockets: list[SocketRow] = []
    for row in rows:
        pid = _first_present(row, (C.IN_PID, C.IN_OWNER_PID, C.IN_PID_ALT))
        remote = _first_present(row, (C.IN_FOREIGN_ADDR, C.IN_REMOTE_ADDR, C.IN_REMOTE_ADDR_ALT))
        remote_ip, remote_port = _split_ip_port(remote)
        sockets.append(
            {
                C.OUT_PID: pid,
                C.OUT_PROCESS_NAME: _safe_str(process_index.get(pid, {}), C.OUT_PROCESS_NAME) if pid else C.KEY_EMPTY,
                C.OUT_LOCAL_ENDPOINT: _first_present(row, (C.IN_LOCAL_ADDR, C.IN_LOCAL_ADDR_ALT)),
                C.OUT_REMOTE_ENDPOINT: remote,
                C.OUT_REMOTE_IP: remote_ip,
                C.OUT_REMOTE_PORT: remote_port,
                C.OUT_PROTOCOL: _first_present(row, (C.IN_PROTO, C.IN_PROTOCOL)),
                C.OUT_STATE: _safe_str(row, C.IN_STATE),
            }
        )
    return sockets


def _build_disk_artifacts() -> list[DiskArtifact]:
    artifacts: list[DiskArtifact] = []
    pattern = os.path.join(OUTDIR, C.FILES_PREFIX + C.SEP + C.GLOB_ALL)
    for fname in glob.glob(pattern):
        rows = _normalize_disk_rows(load_json_file(fname, {}))
        evidence = normalize_output_evidence_name(fname, C.SEP)
        artifacts.append({C.OUT_EVIDENCE: evidence, C.OUT_FILES: rows})
    return artifacts


def _normalize_disk_rows(value: Any) -> list[DiskFileRow]:
    value_map = _as_json_map(value)
    if not value_map:
        return []
    rows: list[DiskFileRow] = []
    for fpath, meta in value_map.items():
        if not isinstance(meta, dict):
            continue
        row = cast(JsonMap, meta)
        file_name = _safe_str(row, C.META_NAME, Path(str(fpath)).name)
        rows.append(
            {
                C.OUT_FILE_NAME: file_name,
                C.OUT_FILE_PATH: str(fpath),
                C.OUT_CREATED_TIME: _safe_str(row, C.META_CREATED),
                C.OUT_MODIFIED_TIME: _safe_str(row, C.META_MODIFIED),
                C.OUT_ACCESS_TIME: _safe_str(row, C.META_ATIME),
                C.OUT_EXECUTION_INDICATOR: bool(row.get(C.META_IS_EXECUTABLE, file_name.lower().endswith(C.EXT_EXE))),
            }
        )
    return rows


def _build_network_artifacts() -> list[NetworkArtifact]:
    artifacts: list[NetworkArtifact] = []
    patterns = [
        os.path.join(OUTDIR, f"*{C.KEY_DOT}{C.EXT_PCAP}{C.EXT_JSON}"),
        os.path.join(OUTDIR, f"*{C.KEY_DOT}{C.EXT_PCAPNG}{C.EXT_JSON}"),
    ]
    for fname in _expand_patterns(patterns):
        rows = _normalize_network_rows(load_json_file(fname, []))
        evidence = Path(fname).name.replace(C.EXT_JSON, C.KEY_EMPTY)
        artifacts.append({C.OUT_EVIDENCE: evidence, C.OUT_CONNECTIONS: rows})
    return artifacts


def _expand_patterns(patterns: list[str]) -> list[str]:
    files: list[str] = []
    for pattern in patterns:
        files.extend(glob.glob(pattern))
    return sorted(files)


def _normalize_network_rows(value: Any) -> list[NetworkConnRow]:
    rows = _as_rows(value)
    return [_normalize_network_row(row) for row in rows]


def _normalize_network_row(row: JsonMap) -> NetworkConnRow:
    src = _safe_str(row, C.IN_SRC)
    dst = _safe_str(row, C.IN_DST)
    src_port = row.get(C.IN_SRC_PORT)
    dst_port = row.get(C.IN_DST_PORT)
    return {
        C.OUT_SRC_IP: src,
        C.OUT_DST_IP: dst,
        C.IN_SRC_PORT: src_port,
        C.IN_DST_PORT: dst_port,
        C.IN_TIMESTAMP: _safe_str(row, C.IN_TIMESTAMP),
        C.OUT_REMOTE_CANDIDATES: [_endpoint_candidate(src, src_port), _endpoint_candidate(dst, dst_port)],
    }


def _endpoint_candidate(ip: str, port: Any) -> str:
    if ip and port is not None:
        return f"{ip}{C.KEY_COLON}{port}"
    return ip


def normalize_artifacts() -> None:
    write_json(os.path.join(OUTDIR, C.OUT_MEMORY_ARTIFACTS), _build_memory_artifacts())
    write_json(os.path.join(OUTDIR, C.OUT_DISK_ARTIFACTS), _build_disk_artifacts())
    write_json(os.path.join(OUTDIR, C.OUT_NETWORK_ARTIFACTS), _build_network_artifacts())


def _match_strength(path_or_proc_ok: bool, time_ok: bool) -> tuple[str, int]:
    if path_or_proc_ok and time_ok:
        return C.MATCH_STRONG, C.SCORE_STRONG
    if path_or_proc_ok or time_ok:
        return C.MATCH_MEDIUM, C.SCORE_MEDIUM
    return C.MATCH_SIMPLE, C.SCORE_SIMPLE


def _find_file_time(file_row: DiskFileRow) -> int | None:
    for key in C.FILE_TIME_KEYS:
        ts = parse_timestamp(_safe_str(file_row, key))
        if ts is not None:
            return ts
    return None


def _collect_process_records(memory_artifacts: list[Any]) -> list[ProcessRecord]:
    records: list[ProcessRecord] = []
    for artifact in memory_artifacts:
        if not isinstance(artifact, dict):
            continue
        art_map = cast(JsonMap, artifact)
        evidence = _safe_str(art_map, C.OUT_EVIDENCE)
        rows = _as_any_list(art_map.get(C.OUT_PROCESSES, []))
        for row in rows:
            if isinstance(row, dict):
                records.append((evidence, cast(ProcessRow, row)))
    return records


def _collect_socket_records(memory_artifacts: list[Any]) -> list[SocketRecord]:
    records: list[SocketRecord] = []
    for artifact in memory_artifacts:
        if not isinstance(artifact, dict):
            continue
        art_map = cast(JsonMap, artifact)
        evidence = _safe_str(art_map, C.OUT_EVIDENCE)
        rows = _as_any_list(art_map.get(C.OUT_SOCKETS, []))
        for row in rows:
            if isinstance(row, dict):
                records.append((evidence, cast(SocketRow, row)))
    return records


def _collect_disk_records(disk_artifacts: list[Any]) -> list[DiskRecord]:
    records: list[DiskRecord] = []
    for artifact in disk_artifacts:
        if not isinstance(artifact, dict):
            continue
        art_map = cast(JsonMap, artifact)
        evidence = _safe_str(art_map, C.OUT_EVIDENCE)
        rows = _as_any_list(art_map.get(C.OUT_FILES, []))
        for row in rows:
            if isinstance(row, dict):
                records.append((evidence, cast(DiskFileRow, row)))
    return records


def _collect_network_records(network_artifacts: list[Any]) -> list[NetworkRecord]:
    records: list[NetworkRecord] = []
    for artifact in network_artifacts:
        if not isinstance(artifact, dict):
            continue
        art_map = cast(JsonMap, artifact)
        evidence = _safe_str(art_map, C.OUT_EVIDENCE)
        rows = _as_any_list(art_map.get(C.OUT_CONNECTIONS, []))
        for row in rows:
            if isinstance(row, dict):
                records.append((evidence, cast(NetworkConnRow, row)))
    return records


def run_correlations(time_window_seconds: int = DEFAULT_TIME_WINDOW_SECONDS) -> None:
    memory_artifacts = load_json_file(os.path.join(OUTDIR, C.OUT_MEMORY_ARTIFACTS), [])
    disk_artifacts = load_json_file(os.path.join(OUTDIR, C.OUT_DISK_ARTIFACTS), [])
    network_artifacts = load_json_file(os.path.join(OUTDIR, C.OUT_NETWORK_ARTIFACTS), [])

    memory_list = _as_any_list(memory_artifacts)
    disk_list = _as_any_list(disk_artifacts)
    network_list = _as_any_list(network_artifacts)

    process_records = _collect_process_records(memory_list)
    socket_records = _collect_socket_records(memory_list)
    disk_records = _collect_disk_records(disk_list)
    net_records = _collect_network_records(network_list)

    correlations: list[CorrelationRow] = []
    correlations.extend(_build_process_correlations(process_records, disk_records, time_window_seconds))
    correlations.extend(_build_fileless_correlations(socket_records, net_records))
    write_json(os.path.join(OUTDIR, C.OUT_CORRELATIONS), correlations)


def _build_process_correlations(
    process_records: list[ProcessRecord],
    disk_records: list[DiskRecord],
    time_window_seconds: int,
) -> list[ProcessCorrelation]:
    output: list[ProcessCorrelation] = []
    for mem_evi, proc_row in process_records:
        proc_name = _safe_str(proc_row, C.OUT_PROCESS_NAME)
        if not proc_name:
            continue
        for disk_evi, file_row in disk_records:
            corr = _process_correlation_row(mem_evi, proc_row, disk_evi, file_row, time_window_seconds)
            if corr:
                output.append(corr)
    return output


def _process_correlation_row(
    mem_evi: str,
    proc_row: ProcessRow,
    disk_evi: str,
    file_row: DiskFileRow,
    time_window_seconds: int,
) -> ProcessCorrelation | None:
    proc_name = _safe_str(proc_row, C.OUT_PROCESS_NAME)
    file_name = _safe_str(file_row, C.OUT_FILE_NAME)
    if _base_name(file_name) != _base_name(proc_name):
        return None

    proc_start = parse_timestamp(_safe_str(proc_row, C.OUT_START_TIME))
    proc_image = _normalize_path(_safe_str(proc_row, C.OUT_IMAGE_PATH))
    proc_cmd = _normalize_path(_safe_str(proc_row, C.OUT_COMMAND_LINE))
    file_path = _normalize_path(_safe_str(file_row, C.OUT_FILE_PATH))

    path_ok = bool(file_path) and (file_path == proc_image or file_path in proc_cmd)
    file_time = _find_file_time(file_row)
    time_ok = bool(proc_start is not None and file_time is not None and abs(proc_start - file_time) <= time_window_seconds)
    strength, score = _match_strength(path_ok, time_ok)
    uncertainty = _process_uncertainty(path_ok, time_ok)

    process_evidence: ProcessEvidence = {C.OUT_MEMORY: mem_evi, C.OUT_DISK: disk_evi}
    process_notes: ProcessNotes = {
        C.OUT_PATH_MATCH: path_ok,
        C.OUT_TIME_ALIGNED: time_ok,
        C.OUT_UNCERTAINTY: uncertainty,
    }

    process_payload: ProcessRow = {
        C.OUT_PID: str(proc_row.get(C.OUT_PID, C.KEY_EMPTY)),
        C.OUT_PPID: str(proc_row.get(C.OUT_PPID, C.KEY_EMPTY)),
        C.OUT_PROCESS_NAME: proc_name,
        C.OUT_IMAGE_PATH: str(proc_row.get(C.OUT_IMAGE_PATH, C.KEY_EMPTY)),
        C.OUT_COMMAND_LINE: str(proc_row.get(C.OUT_COMMAND_LINE, C.KEY_EMPTY)),
        C.OUT_START_TIME: str(proc_row.get(C.OUT_START_TIME, C.KEY_EMPTY)),
        C.OUT_PARENT_NAME: str(proc_row.get(C.OUT_PARENT_NAME, C.KEY_EMPTY)),
    }

    correlation: ProcessCorrelation = {
        C.OUT_SCENARIO: C.SCENARIO_PROCESS,
        C.OUT_MATCH_STRENGTH: strength,
        C.OUT_CONFIDENCE_SCORE: score,
        C.OUT_JOIN_KEYS: [C.JOIN_PROCESS_NAME],
        C.OUT_EVIDENCE: process_evidence,
        C.OUT_PROCESS: process_payload,
        C.OUT_DISK_FILE: file_row,
        C.OUT_NOTES: process_notes,
        C.OUT_STATEMENT: C.STMT_PROCESS_TEMPLATE.format(proc=proc_name, path_ok=path_ok, time_ok=time_ok),
    }
    return correlation


def _process_uncertainty(path_ok: bool, time_ok: bool) -> list[str]:
    output: list[str] = []
    if not path_ok:
        output.append(C.NOTE_PATH_UNAVAILABLE)
    if not time_ok:
        output.append(C.NOTE_TIME_UNCONFIRMED)
    return output


def _build_fileless_correlations(
    socket_records: list[SocketRecord],
    net_records: list[NetworkRecord],
) -> list[FilelessCorrelation]:
    output: list[FilelessCorrelation] = []
    for mem_evi, socket_row in socket_records:
        mem_ip = _safe_str(socket_row, C.OUT_REMOTE_IP)
        if not mem_ip:
            continue
        for net_evi, conn_row in net_records:
            corr = _fileless_correlation_row(mem_evi, socket_row, net_evi, conn_row)
            if corr:
                output.append(corr)
    return output


def _fileless_correlation_row(
    mem_evi: str,
    socket_row: SocketRow,
    net_evi: str,
    conn_row: NetworkConnRow,
) -> FilelessCorrelation | None:
    mem_ip = _safe_str(socket_row, C.OUT_REMOTE_IP)
    src_ip = _safe_str(conn_row, C.OUT_SRC_IP)
    dst_ip = _safe_str(conn_row, C.OUT_DST_IP)
    if mem_ip not in {src_ip, dst_ip}:
        return None

    mem_port = socket_row.get(C.OUT_REMOTE_PORT)
    src_port = conn_row.get(C.IN_SRC_PORT)
    dst_port = conn_row.get(C.IN_DST_PORT)
    port_ok = mem_port is not None and mem_port in {src_port, dst_port}

    proc_name = _safe_str(socket_row, C.OUT_PROCESS_NAME)
    proc_ok = bool(proc_name)
    strength, score = _match_strength(port_ok or proc_ok, False)
    uncertainty = _fileless_uncertainty(port_ok, proc_ok)

    fileless_evidence: FilelessEvidence = {C.OUT_MEMORY: mem_evi, C.OUT_NETWORK: net_evi}
    fileless_notes: FilelessNotes = {
        C.OUT_PORT_MATCH: port_ok,
        C.OUT_PROCESS_ATTRIBUTED: proc_ok,
        C.OUT_UNCERTAINTY: uncertainty,
    }

    correlation: FilelessCorrelation = {
        C.OUT_SCENARIO: C.SCENARIO_FILELESS,
        C.OUT_MATCH_STRENGTH: strength,
        C.OUT_CONFIDENCE_SCORE: score,
        C.OUT_JOIN_KEYS: [C.JOIN_REMOTE_IP],
        C.OUT_EVIDENCE: fileless_evidence,
        C.OUT_SOCKET: socket_row,
        C.OUT_NETWORK_CONNECTION: conn_row,
        C.OUT_NOTES: fileless_notes,
        C.OUT_STATEMENT: C.STMT_FILELESS_TEMPLATE.format(
            ip=mem_ip,
            port_ok=port_ok,
            proc=(proc_name or C.UNKNOWN_PROCESS),
        ),
    }
    return correlation


def _fileless_uncertainty(port_ok: bool, proc_ok: bool) -> list[str]:
    output: list[str] = []
    if not port_ok:
        output.append(C.NOTE_IP_ONLY)
    if not proc_ok:
        output.append(C.NOTE_PROCESS_UNKNOWN)
    return output


def run(indir: str, include_correlations: bool = True) -> None:
    ensure_runtime_dirs(OUTDIR, ERRDIR)
    scan_files(indir)
    normalize_artifacts()
    if include_correlations:
        run_correlations()


def _parse_cli_args(argv: list[str]) -> tuple[str, bool] | None:
    triage = False
    inpaths: list[str] = []

    for arg in argv[1:]:
        if arg == C.CLI_TRIAGE:
            triage = True
            continue
        if arg in {C.CLI_HELP, C.KEY_DASH_H}:
            print(C.MSG_USAGE)
            return None
        if arg.startswith(C.KEY_DASH_DASH) or arg == C.KEY_DASH_H:
            print(C.MSG_UNKNOWN_OPTION.format(option=arg))
            print(C.MSG_USAGE)
            return None
        inpaths.append(arg)

    if len(inpaths) != 1:
        print(C.MSG_USAGE)
        return None

    return inpaths[0], triage


def main() -> None:
    ensure_runtime_dirs(OUTDIR, ERRDIR)
    parsed = _parse_cli_args(sys.argv)
    if parsed is None:
        return
    print(C.MSG_ANALYSING)
    inpath, triage = parsed
    if not os.path.exists(inpath):
        print(C.MSG_INPUT_NOT_FOUND.format(path=inpath))
        return
    if not triage:
        print(C.MSG_EXTRACT_ONLY)
    run(inpath, include_correlations=triage)


if __name__ == C.MAIN_GUARD:
    main()
