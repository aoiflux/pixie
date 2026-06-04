import importlib
import sys
import types
from typing import Any


def _install_dependency_stubs() -> None:
    if "volatility3" not in sys.modules:
        volatility3 = types.ModuleType("volatility3")
        cli = types.ModuleType("volatility3.cli")

        class CommandLine:
            def run(self) -> None:
                return None

        cli_any: Any = cli
        volatility3_any: Any = volatility3
        cli_any.CommandLine = CommandLine
        volatility3_any.cli = cli
        sys.modules["volatility3"] = volatility3
        sys.modules["volatility3.cli"] = cli

    if "pytsk3" not in sys.modules:
        pytsk3 = types.ModuleType("pytsk3")
        pytsk3_any: Any = pytsk3
        pytsk3_any.TSK_FS_META_TYPE_DIR = 1
        pytsk3_any.Img_Info = object
        pytsk3_any.FS_Info = object
        sys.modules["pytsk3"] = pytsk3

    if "dpkt" not in sys.modules:
        dpkt = types.ModuleType("dpkt")
        dpkt_any: Any = dpkt
        dpkt_any.dpkt = types.SimpleNamespace(NeedData=Exception)
        dpkt_any.pcap = types.SimpleNamespace(Reader=lambda _: [])
        dpkt_any.pcapng = types.SimpleNamespace(Reader=lambda _: [])
        dpkt_any.ethernet = types.SimpleNamespace(Ethernet=lambda _: types.SimpleNamespace(data=None))
        dpkt_any.ip = types.SimpleNamespace(IP=object)
        sys.modules["dpkt"] = dpkt


def import_pixie_module() -> types.ModuleType:
    _install_dependency_stubs()
    module = importlib.import_module("pixie")
    return importlib.reload(module)
