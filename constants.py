# Shared constants for the entire project.

# Core names and separators
WINDOWS = "windows."
WIN_FILESCAN = WINDOWS + "filescan"
WIN_PSSCAN = WINDOWS + "psscan"
WIN_NETSCAN = WINDOWS + "netscan"
WIN_DLLLIST = WINDOWS + "dlllist"
OUTDIR = "data"
ERRDIR = "err"
SEP = "_T_"

# File naming
EXT_JSON = ".json"
EXT_LOG = ".log"
EXT_EXE = ".exe"
EXT_PCAP = "pcap"
EXT_PCAPNG = "pcapng"
FILES_PREFIX = "files"
ERR_PREFIX = "err"
GLOB_ALL = "*"
UNKNOWN_TIME = "1970-01-01T01:01:01"

# Generic literals
ENCODING_UTF8 = "utf-8"
MAIN_GUARD = "__main__"
FILE_MODE_READ = "r"
FILE_MODE_WRITE = "w"
FILE_MODE_READ_BINARY = "rb"
ERRORS_IGNORE = "ignore"
JOIN_COMMA_SPACE = ", "
KEY_EMPTY = ""
KEY_DOT = "."
KEY_DOTDOT = ".."
KEY_SLASH = "/"
KEY_COLON = ":"
KEY_BACKSLASH = "\\"
KEY_DASH_F = "-f"
KEY_DASH_R = "-r"
KEY_DASH_H = "-h"
KEY_DASH_DASH = "--"
KEY_JSON = "json"
KEY_PIXIE = "pixie"
CLI_TRIAGE="--triage"
CLI_HELP = "--help"

# DPKT/IP attribute names
ATTR_SRC = "src"
ATTR_DST = "dst"
ATTR_SPORT = "sport"
ATTR_DPORT = "dport"
ATTR_CRTIME = "crtime"
ATTR_MTIME = "mtime"

# Runtime messages
MSG_USAGE = "Use: pixie [--extract-only] <evidence_dir>"
MSG_ANALYSING = "Analysing...."
MSG_INPUT_NOT_FOUND = "Input path does not exist: {path}"
MSG_UNKNOWN_OPTION = "Unknown option: {option}"
MSG_EXTRACT_ONLY = "Extraction-only mode: skipping auto-correlation."
MSG_SCAN_ERROR = "Error in %s for %s: %s"
MSG_FILE_FAIL = "Failed processing %s"
MSG_PLUGIN_FALLBACK = "Library mode failed for plugin %s, falling back to CLI"
MSG_PLUGIN_IMPORT_WARNINGS = "Plugin import warnings: %s"
MSG_UNKNOWN_PLUGIN = "Unknown volatility plugin: {plugin}"

# Correlation labels and confidence
SCENARIO_PROCESS = "process-centric"
SCENARIO_FILELESS = "fileless"
MATCH_STRONG = "strong"
MATCH_MEDIUM = "medium"
MATCH_SIMPLE = "simple"
JOIN_PROCESS_NAME = "process_name=file_name"
JOIN_REMOTE_IP = "remote_ip"
SCORE_STRONG = 95
SCORE_MEDIUM = 75
SCORE_SIMPLE = 55
DEFAULT_TIME_WINDOW_SECONDS = 600

# Notes and statements
NOTE_PATH_UNAVAILABLE = "Path match unavailable or not exact"
NOTE_TIME_UNCONFIRMED = "Time window not confirmed"
NOTE_IP_ONLY = "IP-only correlation without exact port match"
NOTE_PROCESS_UNKNOWN = "Socket owner process unavailable"
UNKNOWN_PROCESS = "unknown"
STMT_PROCESS_TEMPLATE = "{proc} appears in memory and on disk; path_match={path_ok}, time_aligned={time_ok}."
STMT_FILELESS_TEMPLATE = "Remote endpoint {ip} is present in memory sockets and packet data; port_match={port_ok}, process={proc}."

# Output filenames
OUT_MEMORY_ARTIFACTS = "memory_artifacts.json"
OUT_DISK_ARTIFACTS = "disk_artifacts.json"
OUT_NETWORK_ARTIFACTS = "network_artifacts.json"
OUT_CORRELATIONS = "correlations.json"

# Input extension dispatch
MEMORY_EXTENSIONS = {"mem", "bin", "lime"}
PACKET_EXTENSIONS = {EXT_PCAP, EXT_PCAPNG}
DISK_EXTENSIONS = {"dd", "001", "raw"}
SCAN_ACTIONS = [WIN_FILESCAN, WIN_PSSCAN, WIN_NETSCAN, WIN_DLLLIST]

# Logging
LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"

# Raw scan input keys
IN_PID = "PID"
IN_PPID = "PPID"
IN_PARENT_PID = "ParentPID"
IN_IMAGE_FILE_NAME = "ImageFileName"
IN_NAME = "Name"
IN_COMMAND_LINE = "CommandLine"
IN_CMDLINE = "CmdLine"
IN_PATH = "Path"
IN_IMAGE_PATH = "ImagePath"
IN_CREATE_TIME = "CreateTime"
IN_START_TIME = "StartTime"
IN_OWNER_PID = "OwnerPid"
IN_PID_ALT = "Pid"
IN_LOCAL_ADDR = "LocalAddr"
IN_LOCAL_ADDR_ALT = "LocalAddress"
IN_FOREIGN_ADDR = "ForeignAddr"
IN_REMOTE_ADDR = "RemoteAddr"
IN_REMOTE_ADDR_ALT = "RemoteAddress"
IN_PROTO = "Proto"
IN_PROTOCOL = "Protocol"
IN_STATE = "State"
IN_SRC = "src"
IN_DST = "dst"
IN_SRC_PORT = "src_port"
IN_DST_PORT = "dst_port"
IN_TIMESTAMP = "timestamp"

# Normalized output keys
OUT_EVIDENCE = "evidence"
OUT_PROCESSES = "processes"
OUT_SOCKETS = "sockets"
OUT_FILES = "files"
OUT_CONNECTIONS = "connections"
OUT_PID = "pid"
OUT_PPID = "ppid"
OUT_PROCESS_NAME = "process_name"
OUT_COMMAND_LINE = "command_line"
OUT_IMAGE_PATH = "image_path"
OUT_START_TIME = "start_time"
OUT_PARENT_NAME = "parent_name"
OUT_LOCAL_ENDPOINT = "local_endpoint"
OUT_REMOTE_ENDPOINT = "remote_endpoint"
OUT_REMOTE_IP = "remote_ip"
OUT_REMOTE_PORT = "remote_port"
OUT_PROTOCOL = "protocol"
OUT_STATE = "state"
OUT_FILE_NAME = "file_name"
OUT_FILE_PATH = "file_path"
OUT_CREATED_TIME = "created_time"
OUT_MODIFIED_TIME = "modified_time"
OUT_ACCESS_TIME = "access_time"
OUT_EXECUTION_INDICATOR = "execution_indicator"
OUT_SRC_IP = "src_ip"
OUT_DST_IP = "dst_ip"
OUT_REMOTE_CANDIDATES = "remote_candidates"
OUT_SCENARIO = "scenario"
OUT_MATCH_STRENGTH = "match_strength"
OUT_CONFIDENCE_SCORE = "confidence_score"
OUT_JOIN_KEYS = "join_keys"
OUT_PROCESS = "process"
OUT_DISK_FILE = "disk_file"
OUT_SOCKET = "socket"
OUT_NETWORK_CONNECTION = "network_connection"
OUT_NOTES = "notes"
OUT_STATEMENT = "statement"
OUT_PATH_MATCH = "path_match"
OUT_TIME_ALIGNED = "time_aligned"
OUT_UNCERTAINTY = "uncertainty"
OUT_PORT_MATCH = "port_match"
OUT_PROCESS_ATTRIBUTED = "process_attributed"
OUT_MEMORY = "memory"
OUT_DISK = "disk"
OUT_NETWORK = "network"

# Disk metadata keys
META_NAME = "name"
META_ATIME = "atime"
META_CREATED = "created"
META_MODIFIED = "modified"
META_IS_EXECUTABLE = "is_executable"
FILE_TIME_KEYS = (OUT_CREATED_TIME, OUT_MODIFIED_TIME, OUT_ACCESS_TIME)

# Utility timestamps
TIMESTAMP_INVALID_PREFIX = "1970"
TIMESTAMP_Z_SUFFIX = "Z"
TIMESTAMP_UTC_OFFSET = "+00:00"
TIMESTAMP_LAYOUTS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S.%f",
)
JSON_INDENT = 4

# Volatility adapter constants
LIBRARY_MODE_PLUGINS = {
    WIN_PSSCAN,
    WIN_DLLLIST,
    WIN_NETSCAN,
    WIN_FILESCAN,
}
VOLATILITY_IFACE_MAJOR = 2
VOLATILITY_IFACE_MINOR = 0
VOLATILITY_IFACE_PATCH = 0
VOLATILITY_BASE_CONFIG_PATH = "plugins"
VOLATILITY_AUTOMAGIC_SINGLE_LOCATION = "automagic.LayerStacker.single_location"
VOLATILITY_AUTOMAGIC_STACKERS = "automagic.LayerStacker.stackers"
MODE_LIBRARY = "library"
MODE_CLI = "cli"
