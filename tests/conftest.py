import importlib
import sys
import types


def _install_dependency_stubs() -> None:
    if "volatility3" not in sys.modules:
        volatility3 = types.ModuleType("volatility3")
        cli = types.ModuleType("volatility3.cli")

        class CommandLine:
            def run(self) -> None:
                return None

        cli.CommandLine = CommandLine
        volatility3.cli = cli
        sys.modules["volatility3"] = volatility3
        sys.modules["volatility3.cli"] = cli

    if "thefuzz" not in sys.modules:
        thefuzz = types.ModuleType("thefuzz")

        class _Fuzz:
            @staticmethod
            def ratio(a, b) -> int:
                return 100 if str(a).lower() == str(b).lower() else 0

        thefuzz.fuzz = _Fuzz()
        sys.modules["thefuzz"] = thefuzz

    if "pytsk3" not in sys.modules:
        pytsk3 = types.ModuleType("pytsk3")
        pytsk3.TSK_FS_META_TYPE_DIR = 1
        pytsk3.Img_Info = object
        pytsk3.FS_Info = object
        sys.modules["pytsk3"] = pytsk3

    if "dpkt" not in sys.modules:
        dpkt = types.ModuleType("dpkt")
        dpkt.dpkt = types.SimpleNamespace(NeedData=Exception)
        dpkt.pcap = types.SimpleNamespace(Reader=lambda _: [])
        dpkt.pcapng = types.SimpleNamespace(Reader=lambda _: [])
        dpkt.ethernet = types.SimpleNamespace(Ethernet=lambda _: types.SimpleNamespace(data=None))
        dpkt.ip = types.SimpleNamespace(IP=object)
        sys.modules["dpkt"] = dpkt


def import_pixie_module():
    _install_dependency_stubs()
    module = importlib.import_module("pixie")
    return importlib.reload(module)
