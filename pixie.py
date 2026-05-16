from thefuzz import fuzz
from typing import Any, cast
import datetime
import playbook
import psreport
from volatility_adapter import VolatilityAdapter
import pytsk3
import dpkt
import glob
import sys
import os
import re
import socket
import logging
from utilities import (
    ensure_runtime_dirs,
    is_playbook_path,
    load_evidence_map,
    load_json_file,
    normalize_output_evidence_name,
    parse_timestamp,
    skip_missing_or_empty_file,
    write_json,
)

WINDOWS = "windows."
WIN_FILESCAN = WINDOWS + "filescan"
WIN_PSSCAN = WINDOWS + "psscan"
WIN_NETSCAN = WINDOWS + "netscan"
WIN_DLLLIST = WINDOWS + "dlllist"
OUTDIR = "data"
ERRDIR = "err"
SEP = "_T_"
UNKNOWN_ATIME = "1970-01-01T01:01:01"

MEMORY_EXTENSIONS = {"mem", "bin", "lime"}
PACKET_EXTENSIONS = {"pcap", "pcapng"}
DISK_EXTENSIONS = {"dd", "001", "raw"}
SCAN_ACTIONS = [WIN_FILESCAN, WIN_PSSCAN, WIN_NETSCAN, WIN_DLLLIST]

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

JsonMap = dict[str, Any]
EvidenceMap = dict[str, list[Any]]
PathAtimeMap = dict[str, dict[str, str]]
ConnRecord = dict[str, str | int | None]

VOLATILITY_ADAPTER = VolatilityAdapter(prefer_library=True, enable_cli_fallback=True)


# Scanners ------------------------------------------------------------------


def get_conns(indir: str, fname: str) -> None:
    """Extract IPv4-like byte patterns from memory image and persist as json list."""
    inpath = os.path.join(indir, fname)
    ipat = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    with open(inpath, "rb") as fh:
        data = fh.read()

    ips = ipat.findall(data)
    ips = [ip.decode("utf-8") for ip in ips]

    outpath = os.path.join(OUTDIR, "conns" + SEP + fname + ".json")
    write_json(outpath, ips)


def scan_memory(indir: str, fname: str, action: str) -> None:
    """Best-effort memory plugin scan for one action."""
    try:
        scan_mem_subproc(indir, fname, action)
    except Exception as e:
        logger.exception("Error in %s for %s: %s", fname, action, e)


def scan_mem_subproc(indir: str, fname: str, action: str) -> None:
    inpath = os.path.join(indir, fname)
    errpath = os.path.join(ERRDIR, "err" + SEP + action + SEP + fname + ".log")
    outpath = os.path.join(OUTDIR, action + SEP + fname + ".json")

    VOLATILITY_ADAPTER.run_plugin(inpath, action, outpath, errpath)

    if os.path.exists(outpath):
        size = os.path.getsize(outpath)
        if size == 0:
            os.remove(outpath)


def scan_pcap(indir: str, fname: str) -> None:
    """Extract packet endpoint tuples from pcap/pcapng input."""
    iplist: list[ConnRecord] = []
    fpath = os.path.join(indir, fname)
    with open(fpath, "rb") as fh:
        dpkt_api = cast(Any, dpkt)
        packets = dpkt_api.pcapng.Reader(fh) if fname.lower().endswith("pcapng") else dpkt_api.pcap.Reader(fh)
        for _ts, buf in packets:
            try:
                eth = dpkt_api.ethernet.Ethernet(buf)
                ip = eth.data
                if not hasattr(ip, "src") or not hasattr(ip, "dst"):
                    continue

                src_ip = socket.inet_ntoa(cast(bytes, getattr(ip, "src")))
                dst_ip = socket.inet_ntoa(cast(bytes, getattr(ip, "dst")))
                src_port = getattr(ip.data, "sport", None)
                dst_port = getattr(ip.data, "dport", None)

                iplist.append({"src": src_ip, "dst": dst_ip, "src_port": src_port, "dst_port": dst_port})
            except (ValueError, AttributeError, dpkt_api.dpkt.NeedData):
                continue

    outpath = os.path.join(OUTDIR, fname + ".json")
    write_json(outpath, iplist)


def scan_disk(indir: str, fname: str) -> None:
    """Enumerate files from disk image and persist path/atime map."""
    inpath = os.path.join(indir, fname)
    tsk = cast(Any, pytsk3)
    img = tsk.Img_Info(inpath)
    fs = tsk.FS_Info(img)
    root = fs.open_dir(path="/")

    file_list = list_files(root)

    outpath = os.path.join(OUTDIR, "files" + SEP + fname + ".json")
    write_json(outpath, file_list)


def list_files(root: Any) -> PathAtimeMap:
    """Depth-first traversal of TSK filesystem directory objects."""
    stack: list[tuple[Any, str]] = [(root, "")]
    file_list: PathAtimeMap = {}

    while stack:
        current_dir, path = stack.pop()
        for fsobj in current_dir:
            raw_name = fsobj.info.name.name
            if isinstance(raw_name, (bytes, bytearray)):
                fname = raw_name.decode("utf-8", errors="ignore")
            else:
                fname = str(raw_name)

            if fname in [".", ".."]:
                continue

            fpath = f"{path}/{fname}" if path else fname

            if fsobj.info.meta is None:
                file_list[fpath] = {"name": fname, "atime": UNKNOWN_ATIME}
                continue

            if fsobj.info.meta.type == cast(Any, pytsk3).TSK_FS_META_TYPE_DIR:
                subdir = fsobj.as_directory()
                stack.append((subdir, fpath))
            else:
                atime = UNKNOWN_ATIME
                if fsobj.info.meta.atime:
                    atime = datetime.datetime.fromtimestamp(fsobj.info.meta.atime).isoformat()
                file_list[fpath] = {"name": fname, "atime": atime}

    return file_list


def scan_files(indir: str) -> None:
    """Dispatch each evidence file to scanner(s) based on extension."""
    fnames = sorted(os.listdir(indir))
    for fname in fnames:
        fpath = os.path.join(indir, fname)
        if not os.path.isfile(fpath):
            continue

        ext = fname.split(".")[-1].lower()
        try:
            if ext in MEMORY_EXTENSIONS:
                get_conns(indir, fname)
                for action in SCAN_ACTIONS:
                    scan_memory(indir, fname, action)
                continue

            if ext in PACKET_EXTENSIONS:
                scan_pcap(indir, fname)
                continue

            if ext in DISK_EXTENSIONS:
                scan_disk(indir, fname)
        except Exception:
            logger.exception("Failed processing %s", fname)


# Aggregation and reporting --------------------------------------------------

def common_files(fname: str, rname: str) -> None:
    """Aggregate disk file path evidence matches across inputs."""
    fpath = os.path.join(OUTDIR, fname)
    evidence_name = normalize_output_evidence_name(fname, SEP)

    if skip_missing_or_empty_file(fpath):
        return

    dd_fmap = load_json_file(fpath, {})
    if not isinstance(dd_fmap, dict):
        return
    dd_fmap = cast(JsonMap, dd_fmap)

    report_data = load_evidence_map(OUTDIR, rname)
    report_data = fuzz_match(dd_fmap, report_data, evidence_name, "")

    write_json(os.path.join(OUTDIR, rname), report_data)


def fuzz_match(srcmap: list[Any] | JsonMap, dstmap: EvidenceMap, fname: str, skey: str) -> EvidenceMap:
    """Merge artefact values into aggregate evidence map with fuzzy fallback matching."""
    if len(dstmap) == 0:
        for artefact in srcmap:
            artefact_val: Any = artefact
            if skey != "":
                if not isinstance(artefact_val, dict):
                    continue
                artefact_map = cast(dict[str, Any], artefact_val)
                if skey not in artefact_map:
                    continue
                artefact_val = artefact_map[skey]
            if artefact_val is None:
                continue
            dstmap[str(cast(object, artefact_val))] = [fname]
        return dstmap

    newfiles: dict[str, str] = {}
    for artefact in srcmap:
        artefact_val: Any = artefact
        if skey != "":
            if not isinstance(artefact_val, dict):
                continue
            artefact_map = cast(dict[str, Any], artefact_val)
            if skey not in artefact_map:
                continue
            artefact_val = artefact_map[skey]
        if artefact_val is None:
            continue

        artefact = str(cast(object, artefact_val))
        if artefact in dstmap:
            if fname not in dstmap[artefact]:
                dstmap[artefact].append(fname)
        else:
            for dst_map_file, file_list in dstmap.items():
                if fname in file_list:
                    continue

                dmf = dst_map_file.replace("\\", "/")
                smf = artefact.replace("\\", "/")

                conf = int(cast(Any, fuzz).ratio(dmf, smf))
                if {"evi": fname, "fpath": artefact, "conf": conf} in file_list:
                    continue

                if 85 <= conf < 100:
                    dmf = dmf.split("/")[-1]
                    smf = smf.split("/")[-1]

                    if dmf == smf:
                        file_list.append({"evi": fname, "fpath": artefact, "conf": conf})
                        dstmap[dst_map_file] = file_list
                        break

                if conf < 85:
                    newfiles[artefact] = fname

    for nkey in newfiles:
        dstmap[nkey] = [newfiles[nkey]]

    return dstmap


def common_conns(fname: str, rname: str) -> None:
    """Aggregate plain connection lists across evidence sources."""
    fpath = os.path.join(OUTDIR, fname)
    evidence_name = normalize_output_evidence_name(fname, SEP)

    if skip_missing_or_empty_file(fpath):
        return

    flist = load_json_file(fpath, [])
    if not isinstance(flist, list):
        return
    flist = cast(list[Any], flist)

    report_data = load_evidence_map(OUTDIR, rname)

    for file_name in flist:
        file_name = str(file_name)
        if file_name in report_data:
            if evidence_name in report_data[file_name]:
                continue
            report_data[file_name].append(evidence_name)
        else:
            report_data[file_name] = [evidence_name]

    write_json(os.path.join(OUTDIR, rname), report_data)


def common_report(fname: str, rname: str, skey: str) -> None:
    """Aggregate list-of-record scan outputs into a common report."""
    fpath = os.path.join(OUTDIR, fname)
    evidence_name = normalize_output_evidence_name(fname, SEP)

    if skip_missing_or_empty_file(fpath):
        return

    flmap = load_json_file(fpath, [])
    if not isinstance(flmap, list):
        return
    flmap = cast(list[Any], flmap)

    report_data = load_evidence_map(OUTDIR, rname)
    report_data = fuzz_match(flmap, report_data, evidence_name, skey)

    write_json(os.path.join(OUTDIR, rname), report_data)


def commonality() -> None:
    """Build aggregated cross-evidence reports from generated scan outputs."""
    fnames = os.listdir(OUTDIR)
    for fname in fnames:
        if WIN_FILESCAN in fname:
            common_report(fname, "files.json", "Name")
        if WIN_DLLLIST in fname:
            common_report(fname, "dlls.json", "Name")
        if WIN_PSSCAN in fname:
            common_report(fname, "processes.json", "ImageFileName")
        if WIN_NETSCAN in fname:
            common_report(fname, "conns.json", "LocalAddr")
            common_report(fname, "conns.json", "ForeignAddr")
        if "conns" + SEP in fname:
            common_conns(fname, "conns.json")
        if ".pcap." in fname:
            common_report(fname, "conns.json", "src")
        if any(ext in fname for ext in [".dd.", ".001.", ".raw."]):
            common_files(fname, "files.json")


def get_rels() -> list[psreport.Relation]:
    """Build process->DLL relationship records from psscan and dlllist outputs."""
    rels: list[psreport.Relation] = []
    jrels: list[dict[str, Any]] = []
    pattern = os.path.join(OUTDIR, WIN_PSSCAN + "*")

    for fname in glob.glob(pattern):
        ps_data = load_json_file(fname, [])
        if not isinstance(ps_data, list):
            continue
        ps_data = cast(list[Any], ps_data)

        dll_fname = fname.replace(WIN_PSSCAN, WIN_DLLLIST)
        dll_data = load_json_file(dll_fname, [])
        if not isinstance(dll_data, list):
            dll_data = []
        dll_data = cast(list[Any], dll_data)

        evidence_name = normalize_output_evidence_name(fname, SEP)

        for ps in ps_data:
            if not isinstance(ps, dict):
                continue
            ps = cast(JsonMap, ps)

            pid = str(ps.get("PID", ""))
            proc_name = str(ps.get("ImageFileName", ""))
            create_time = str(ps.get("CreateTime", ""))
            proc_path = ""
            dll_entries: list[psreport.DLLEntry] = []

            for dll in dll_data:
                if not isinstance(dll, dict):
                    continue
                dll = cast(JsonMap, dll)

                if ps.get("PID") == dll.get("PID"):
                    ppath = str(dll.get("Path", ""))
                    if ppath.lower().endswith(proc_name.lower()):
                        proc_path = ppath
                    dll_entries.append(
                        psreport.DLLEntry(
                            dll_path=ppath,
                            dll_name=str(dll.get("Name", "")),
                            load_time=str(dll.get("LoadTime", "")),
                        )
                    )

            if not proc_path:
                proc_path = proc_name

            rel = psreport.Relation(
                proc_path=proc_path,
                proc_name=proc_name,
                confidence=100,
                actual_deviation=0,
                create_time=create_time,
                evi=evidence_name,
                pid=pid,
                dll=dll_entries,
            )
            jrels.append(rel.model_dump())
            rels.append(rel)

    write_json(os.path.join(OUTDIR, "proc_dlls.json"), jrels)
    return rels


def ps_match(deviation: int) -> None:
    """Match executable disk access times against memory process creation events."""
    psmatches: list[dict[str, Any]] = []
    rels = get_rels()
    pattern = os.path.join(OUTDIR, "files_*")

    for fname in glob.glob(pattern):
        fdata = load_json_file(fname, {})
        if not isinstance(fdata, dict):
            continue
        fdata = cast(JsonMap, fdata)

        evidence_name = normalize_output_evidence_name(fname, SEP)

        for fitem, fmeta in fdata.items():
            fitem = str(fitem)
            if not fitem.lower().endswith(".exe"):
                continue

            if not isinstance(fmeta, dict):
                continue
            fmeta = cast(JsonMap, fmeta)

            atime = parse_timestamp(str(fmeta.get("atime", "")))
            if atime is None:
                continue

            psmatch_relations: list[psreport.Relation] = []
            access_time = str(fmeta.get("atime", ""))

            for rel in rels:
                if rel.create_time.startswith("1970"):
                    continue

                ctime = parse_timestamp(rel.create_time)
                if ctime is None:
                    continue

                diff = abs(atime - ctime)
                if diff > deviation:
                    continue

                proc_disk = fitem.replace("\\", "/")
                proc_mem = str(rel.proc_path).replace("\\", "/")
                confidence = int(cast(Any, fuzz).ratio(proc_disk, proc_mem))
                if confidence > 85:
                    if proc_disk.split("/")[-1] == proc_mem.split("/")[-1]:
                        rel_copy = rel.model_copy(deep=True)
                        rel_copy.actual_deviation = diff
                        rel_copy.confidence = confidence
                        psmatch_relations.append(rel_copy)

            if len(psmatch_relations) == 0:
                continue

            psmatches.append(
                psreport.PSMatch(
                    fpath=fitem,
                    access_time=access_time,
                    allowed_deviation=deviation,
                    evi=evidence_name,
                    relations=psmatch_relations,
                ).model_dump()
            )

    write_json(os.path.join(OUTDIR, "procmatches.json"), psmatches)


# Orchestration and CLI ------------------------------------------------------

def auto_triage(indir: str) -> None:
    """Default end-to-end triage pipeline."""
    scan_files(indir)
    commonality()
    ps_match(100)


def run_playbook(playbook_path: str) -> None:
    """Placeholder for playbook execution path."""
    _ = playbook.NewPlaybook(playbook_path)


def play(playbook_path: str) -> None:
    """Backward-compatible wrapper for older call sites."""
    run_playbook(playbook_path)


def main() -> None:
    """CLI entrypoint."""
    ensure_runtime_dirs(OUTDIR, ERRDIR)

    if len(sys.argv) < 2:
        print("Use: pixie <evidence_dir>")
        return

    print("Analysing....")

    inpath = sys.argv[1]
    if not os.path.exists(inpath):
        print(f"Input path does not exist: {inpath}")
        return

    if is_playbook_path(inpath):
        run_playbook(inpath)
        return

    auto_triage(inpath)


if __name__ == "__main__":
    main()
