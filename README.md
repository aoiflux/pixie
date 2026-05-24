# pixie

Pipeline for three evidence types:

- disk images
- memory images
- packet captures

The tool extracts structured artifacts and generates a correlation report for:

- process-centric activity (memory process <-> disk file)
- fileless/network-centric activity (memory socket <-> PCAP endpoint)

## Scope

Current behavior:

- parsing
- exact-key correlations
- JSON output only
- constants-driven configuration/keys in one place (`constants.py`)

## Supported Inputs

Drop files in one evidence directory and run pixie against that directory.

- memory: `.mem`, `.bin`, `.lime`
- disk: `.dd`, `.001`, `.raw`
- network: `.pcap`, `.pcapng`

## Processing Flow

1. Scan inputs by extension.
2. Produce per-source scan outputs.
3. Normalize into typed artifact files.
4. Run correlations.

Entrypoint flow in `pixie.py`:

- `auto_triage()`
- `scan_files()`
- `normalize_artifacts()`
- `run_correlations()`

## How It Works

1. `scan_files()` reads files from the input directory.
2. For memory files, `scan_memory()` runs Volatility plugins
   (`windows.filescan`, `windows.psscan`, `windows.netscan`, `windows.dlllist`).
3. For disk files, `scan_disk()` walks the filesystem and writes file metadata.
4. For PCAP files, `scan_pcap()` writes endpoint and timestamp records.
5. `normalize_artifacts()` builds:

- `memory_artifacts.json`
- `disk_artifacts.json`
- `network_artifacts.json`

6. `run_correlations()` loads normalized artifacts and writes
   `correlations.json`.
7. Process-centric correlation joins memory process name to disk file name, then
   checks path and time window.
8. Fileless correlation joins memory remote IP to network IP, then checks port
   and process attribution.

## Output Files

Generated under `data/`:

- `memory_artifacts.json`
- `disk_artifacts.json`
- `network_artifacts.json`
- `correlations.json`

### Normalized Artifacts

`memory_artifacts.json` contains:

- processes: `pid`, `ppid`, `process_name`, `command_line`, `image_path`,
  `start_time`, `parent_name`
- sockets: `pid`, `process_name`, `local_endpoint`, `remote_endpoint`,
  `remote_ip`, `remote_port`, `protocol`, `state`

`disk_artifacts.json` contains:

- `file_name`, `file_path`, `created_time`, `modified_time`, `access_time`,
  `execution_indicator`

`network_artifacts.json` contains:

- `src_ip`, `dst_ip`, `src_port`, `dst_port`, `timestamp`, `remote_candidates`

### Correlations

`correlations.json` emits two scenario types:

- `process-centric`
  - join: process name <-> file name
  - checks exact path and time-window alignment
- `fileless`
  - join: remote IP across memory socket and packet stream
  - checks port match and process attribution

Each record includes:

- `match_strength`
- `confidence_score`
- `join_keys`
- evidence references
- uncertainty notes
- statement

## Install

Create and activate a Python virtual environment:

```powershell
python -m venv .env
.\.env\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` includes:

- `pytsk3`
- `volatility3`
- `dpkt`
- `pytest`

## Run

From project root:

```powershell
python pixie.py <evidence_dir>
```

Example:

```powershell
python pixie.py .\samples
```

## Tests

```powershell
python -m pytest -q
```

## Development Notes

- All operational constants are centralized in `constants.py`.
- Core modules are type-annotated and checked via editor diagnostics.
- A guard test enforces constants usage:
  - `tests/test_constants_enforcement.py`

## Current Limitations

- No DNS/domain enrichment from PCAP yet.
- Correlations are for triage and require analyst review.
- Output schema may change.
