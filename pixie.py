from volatility3.cli import CommandLine
from thefuzz import fuzz
from typing import List
from re import Pattern
import multiprocessing
import datetime
import playbook
import psreport
import datetime
import pyshark
import signal
import pytsk3
import glob
import json
import sys
import os
import re

WINDOWS = "windows."
WIN_FILESCAN = WINDOWS+"filescan"
WIN_PSSCAN = WINDOWS+"psscan"
WIN_NETSCAN = WINDOWS+"netscan"
WIN_DLLLIST = WINDOWS+"dlllist"
OUTDIR = "data"
ERRDIR = "err"
SEP = "_I_"

def scan_files(indir:str):
    actions = [
            WIN_FILESCAN,
            WIN_PSSCAN,
            WIN_NETSCAN,
            WIN_DLLLIST
        ]

    fnames = os.listdir(indir)
    for fname in fnames:
            ext = fname.split(".")[-1]
            match ext:
                case ram if ram in ["mem", "bin", "lime"]:
                    get_conns(indir, fname)
                    for action in actions:
                        scan_memory(indir, fname, action)
                case "pcap":
                    scan_pcap(indir, fname)
                case disk if disk in ["dd", "001", "raw"]:
                    scan_disk(indir, fname)

def set_cli(inpath:str, action:str):
    sys.argv[1] = "-f"

    if len(sys.argv) < 3:
        sys.argv.append(inpath)
        sys.argv.append("-r")
        sys.argv.append("json")
        sys.argv.append(action)
    else:
        sys.argv[2] = inpath
        sys.argv[3] = "-r"
        sys.argv[4] = "json"
        sys.argv[5] = action

def get_conns(indir:str, fname:str):
    inpath = os.path.join(indir, fname)
    ipat = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')

    fh = open(inpath, "rb")
    data = fh.read()
    fh.close()

    ips = ipat.findall(data)
    ips = [ip.decode('utf-8') for ip in ips]

    outpath = os.path.join(OUTDIR, "conns"+SEP+fname+".json")
    fh = open(outpath, "w")
    json.dump(ips, fh, indent=4)
    fh.close()

def signal_handler(pool):
    print("Ctrl+C pressed. Terminating all processes.")
    pool.terminate()
    pool.join()
def scan_memory(indir:str, fname:str, action:str):
    try:
        with multiprocessing.Pool(1) as pool:
            signal.signal(signal.SIGINT, signal_handler)
            pool.apply(scan_mem_subproc, (indir, fname, action))
    except Exception as e:
        print(f"Error in {fname} for {action}: {e}")

def scan_mem_subproc(indir:str, fname:str, action:str):
    inpath = os.path.join(indir, fname)
    set_cli(inpath, action)

    errpath = os.path.join(ERRDIR, "err"+SEP+action+SEP+fname+".log")
    errfile = open(errpath, "w")
    original_stderr = sys.stderr
    sys.stderr = errfile

    outpath = os.path.join(OUTDIR, action + SEP + fname + ".json")
    outfile = open(outpath, "w")
    original_stdout = sys.stdout
    sys.stdout = outfile

    cli = CommandLine()
    cli.run()

    sys.stderr = original_stderr
    errfile.close()
    sys.stdout = original_stdout
    outfile.close()

    if os.path.exists:
        size = os.path.getsize(outpath)
        if  size == 0:
            os.remove(outpath)

def scan_pcap(indir:str, fname:str):
    iplist = []
    fpath = os.path.join(indir, fname)
    packets = pyshark.FileCapture(fpath, only_summaries=False, keep_packets=False)
    for packet in packets:
        if 'IP' in packet:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst

            src_port, dst_port = None, None
            if 'TCP' in packet:
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
            elif 'UDP' in packet:
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport

            iplist.append({'src': src_ip, 'dst': dst_ip, 'src_port': src_port, 'dst_port': dst_port})

    outpath = os.path.join(OUTDIR, fname+".json")
    outfile = open(outpath, "w")
    json.dump(iplist, outfile, indent=4)
    outfile.close()

def scan_disk(indir:str, fname):
    pattern = r"'(.*?)'"
    pat = re.compile(pattern)

    inpath = os.path.join(indir, fname)
    img = pytsk3.Img_Info(inpath)
    fs = pytsk3.FS_Info(img)
    root = fs.open_dir(path="/")

    file_list = list_files(root, pat)

    outpath = os.path.join(OUTDIR, "files"+SEP+fname+".json")
    outfile = open(outpath, "w")
    json.dump(file_list, outfile, indent=4)
    outfile.close()
def list_files(root, pat:Pattern[str])->dict:
    stack = [(root, "")]
    file_list = {}

    while stack:
        current_dir, path = stack.pop()
        for fsobj in current_dir:
            fname = str(fsobj.info.name.name)
            match = pat.search(fname)
            if match:
                fname = match.group(1)

            if fname in [".", ".."]:
                continue

            fpath = f"{path}/{fname}" if path else fname

            if fsobj.info.meta is None:
                file_list[fpath] = {"name": fname, "atime": "1970-01-01T01:01:01"}
                continue
            if fsobj.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                subdir = fsobj.as_directory()
                stack.append((subdir, fpath))
            else:
                file_list[fpath] = {"name": fname, "atime": datetime.datetime.fromtimestamp(fsobj.info.meta.atime).isoformat()}

    return file_list

def commonality():
    fnames = os.listdir(OUTDIR)
    for fname in fnames:
        if WIN_FILESCAN in fname:
            common_report(fname, "files.json", "Name")
        if WIN_DLLLIST in fname:
            common_report(fname, "dlls.json", "Name")
        if WIN_PSSCAN in fname:
            common_report(fname, "processes.json", "ImageFileName")
        if WIN_NETSCAN in fname:
            common_conns(fname, "conns.json", "LocalAddr")
            common_conns(fname, "conns.json", "ForeignAddr")
        if "conns"+SEP in fname:
            common_conns(fname, "conns.json")
        if ".pcap." in fname:
            common_report(fname, "conns.json", "src")
        if any(ext in fname for ext in [".dd.", ".001.", ".raw."]):
            common_files(fname, "files.json")
def common_files(fname:str, rname:str):
    fpath = os.path.join(OUTDIR, fname)
    fname = fname.split(SEP)[-1]
    fname = fname.split(".json")[0]

    fh = open(fpath)
    dd_fmap = json.load(fh)
    fh.close()

    fmap = {}
    fpath = os.path.join(OUTDIR, rname)
    if os.path.exists(fpath):
        fh = open(fpath)
        fmap = json.load(fh)
        fh.close()

    fmap = fuzz_match(dd_fmap, fmap, fname, "")

    fh = open(fpath, "w")
    json.dump(fmap, fh, indent=4)
    fh.close()
def fuzz_match(srcmap, dstmap, fname:str, skey:str):
    if len(dstmap) == 0:
        for artefact in srcmap:
            if skey != "":
                artefact = artefact[skey]
            dstmap[artefact] = [fname]
        return dstmap

    newfiles = {}
    for artefact in srcmap:
        if skey != "":
            artefact = artefact[skey]
        if artefact is None:
                    continue
        if artefact in dstmap:
            if fname not in dstmap[artefact]:
                dstmap[artefact].append(fname)
        else:
            for dst_map_file, file_list in dstmap.items():
                if fname in file_list:
                    continue

                dmf = dst_map_file.replace("\\", "/")
                smf = artefact.replace("\\", "/")

                conf = fuzz.ratio(dmf, smf)
                if ({"evi": fname,"fpath": artefact,"conf": conf}) in file_list:
                    continue

                if 85 <= conf < 100:
                    dmf = dmf.split("/")[-1]
                    smf = smf.split("/")[-1]

                    if dmf == smf:
                        file_list.append(
                            {
                                "evi": fname,
                                "fpath": artefact,
                                "conf": conf
                            }
                        )
                        dstmap[dst_map_file] = file_list
                        break
                if conf < 85:
                    newfiles[artefact] = fname

    for nkey in newfiles:
        dstmap[nkey] = [newfiles[nkey]]

    return dstmap
def common_conns(fname:str, rname:str):
    fpath = os.path.join(OUTDIR, fname)
    fname = fname.split(SEP)[-1]
    fname = fname.split(".json")[0]

    fh = open(fpath)
    flist = json.load(fh)
    fh.close()

    fmap = {}
    fpath = os.path.join(OUTDIR, rname)
    if os.path.exists(fpath):
        fh = open(fpath)
        fmap = json.load(fh)
        fh.close()

    for file_name in flist:
        file_name = str(file_name)
        if file_name in fmap:
            if fname in fmap[file_name]:
                continue
            fmap[file_name].append(fname)
        else:
            fmap[file_name] = [fname]

    fh = open(fpath, "w")
    json.dump(fmap, fh, indent=4)
    fh.close()
def common_report(fname:str, rname:str, skey:str):
    fpath = os.path.join(OUTDIR, fname)
    fname = fname.split(SEP)[-1]
    fname = fname.split(".json")[0]

    fh = open(fpath)
    flmap = json.load(fh)
    fh.close()

    fmap = {}
    fpath = os.path.join(OUTDIR, rname)
    if os.path.exists(fpath):
        fh = open(fpath)
        fmap = json.load(fh)
        fh.close()

    fmap = fuzz_match(flmap, fmap, fname, skey)

    fh = open(fpath, "w")
    json.dump(fmap, fh, indent=4)
    fh.close()

def ps_match(deviation:int):
    psmatches = []
    rels = get_rels()
    pattern = os.path.join(OUTDIR, "files_*")

    for fname in glob.glob(pattern):
        fh = open(fname)
        fdata = json.load(fh)
        fh.close()

        fname = fname.split(SEP)[-1]
        fname = fname.split(".json")[0]

        for fitem in fdata:
            if not str(fitem).endswith("exe"):
                continue
            if str(fdata[fitem]["atime"]).startswith("1970"):
                continue

            psmatch = psreport.PSMatch
            psmatch.evi = fname
            psmatch.fpath = fitem
            psmatch.relations = []
            psmatch.allowed_deviation = deviation
            psmatch.access_time = fdata[fitem]["atime"]

            if psmatch.access_time.startswith("1970"):
                continue

            dt = datetime.datetime.strptime(psmatch.access_time, "%Y-%m-%dT%H:%M:%S")
            atime = int(dt.timestamp())

            for rel in rels:
                if rel.create_time.startswith("1970"):
                    continue

                dt = datetime.datetime.strptime(rel.create_time, "%Y-%m-%dT%H:%M:%S")
                ctime = int(dt.timestamp())

                diff = abs(atime-ctime)
                if diff > deviation:
                    continue

                proc_disk = str(fitem.replace("\\", "/"))
                proc_mem = rel.proc_path.replace("\\", "/")
                confidence = fuzz.ratio(proc_disk, proc_mem)
                if confidence > 85:
                    proc_disk = proc_disk.split("/")[-1]
                    proc_mem = proc_mem.split("/")[-1]
                    if proc_disk == proc_mem:
                        rel.actual_deviation = diff
                        rel.confidence = confidence
                        psmatch.relations.append(rel)

            if len(psmatch.relations) == 0:
                continue
            psmatch = psreport.PSMatch(
                fpath=psmatch.fpath,
                access_time=psmatch.access_time,
                allowed_deviation=psmatch.allowed_deviation,
                evi=psmatch.evi,
                relations=psmatch.relations
            )
            psmatch = psmatch.model_dump()
            psmatches.append(psmatch)

    psmatches = json.dumps(psmatches, indent=4)

    fpath = os.path.join(OUTDIR, "procmatches.json")
    fh = open(fpath, "w")
    fh.write(psmatches)
    fh.close()

def get_rels()-> list[psreport.Relation]:
    rels = []
    jrels = []
    pattern = os.path.join(OUTDIR, WIN_PSSCAN+"*")
    for fname in glob.glob(pattern):
        fh = open(fname)
        ps_data = json.load(fh)
        fh.close()

        fname = fname.replace(WIN_PSSCAN, WIN_DLLLIST)
        fh = open(fname)
        dll_data = json.load(fh)
        fh.close()

        fname = fname.split(SEP)[-1]
        fname = fname.split(".json")[0]

        for ps in ps_data:
            rel = psreport.Relation
            rel.pid = str(ps["PID"])
            rel.proc_name = str(ps["ImageFileName"])
            rel.create_time = str(ps["CreateTime"])
            rel.evi = fname
            rel.confidence = 0
            rel.actual_deviation = 0
            rel.dll = []

            for dll in dll_data:
                if ps["PID"] == dll["PID"]:
                    ppath = str(dll["Path"])
                    if ppath.endswith(rel.proc_name):
                        rel.proc_path = ppath
                    dll_entry = psreport.DLLEntry(
                        dll_path = ppath,
                        dll_name = str(dll["Name"]),
                        load_time = str(dll["LoadTime"])
                    )
                    rel.dll.append(dll_entry)

            rel = psreport.Relation(
                proc_path = rel.proc_path,
                proc_name = rel.proc_name,
                confidence = rel.confidence,
                actual_deviation = rel.actual_deviation,
                create_time = rel.create_time,
                evi = rel.evi,
                pid = rel.pid,
                dll = rel.dll
            )
            reldict = rel.model_dump()
            jrels.append(reldict)
            rels.append(rel)

    jrels = json.dumps(jrels, indent=4)
    fpath = os.path.join(OUTDIR, "proc_dlls.json")
    fh = open(fpath, "w")
    fh.write(jrels)
    fh.close()

    return rels

def auto_triage(indir:str):
    scan_files(indir)
    commonality()
    ps_match(100)

def play(playbook_path:str):
    book = playbook.NewPlaybook(playbook_path)
    pass

def main():
    if not os.path.exists(OUTDIR):
        os.mkdir(OUTDIR)
    if not os.path.exists(ERRDIR):
        os.mkdir(ERRDIR)

    if len(sys.argv) < 2:
        print("Use: pixie <evidence_dir>")
        return

    print("Analysing....")

    inpath = sys.argv[1]
    if "playbook" in inpath:
        play(inpath)
        return

    auto_triage(inpath)

if __name__ == '__main__':
    main()