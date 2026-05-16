import logging
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, cast

from volatility3.cli import CommandLine

logger = logging.getLogger(__name__)

LIBRARY_MODE_PLUGINS = {
    "windows.psscan",
    "windows.dlllist",
    "windows.netscan",
    "windows.filescan",
}


class VolatilityAdapter:
    """Adapter boundary for memory-plugin execution.

    Current migration state:
    - Preferred path: library mode for plugins listed in LIBRARY_MODE_PLUGINS
    - Fallback path: CLI compatibility mode
    """

    def __init__(self, prefer_library: bool = True, enable_cli_fallback: bool = True):
        self.prefer_library = prefer_library
        self.enable_cli_fallback = enable_cli_fallback

    def run_plugin(self, image_path: str, plugin_name: str, out_path: str, err_path: str) -> str:
        """Run one volatility plugin and persist output/error streams."""
        if self.prefer_library and plugin_name in LIBRARY_MODE_PLUGINS:
            try:
                self._run_plugin_library(image_path, plugin_name, out_path, err_path)
                return "library"
            except Exception:
                logger.exception("Library mode failed for plugin %s, falling back to CLI", plugin_name)
                if not self.enable_cli_fallback:
                    raise

        self._run_plugin_cli(image_path, plugin_name, out_path, err_path)
        return "cli"

    def _run_plugin_library(self, image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        """Execute selected plugins via Volatility framework APIs directly."""
        import volatility3.plugins
        from volatility3 import framework
        from volatility3.cli import text_renderer
        from volatility3.framework import automagic, constants, contexts, plugins
        from volatility3.framework.automagic import stacker
        from volatility3.framework.configuration import requirements

        framework.require_interface_version(2, 0, 0)

        with open(out_path, "w", encoding="utf-8") as out_fh, open(err_path, "w", encoding="utf-8") as err_fh:
            with redirect_stdout(out_fh), redirect_stderr(err_fh):
                failures = framework.import_files(volatility3.plugins, True)
                if failures:
                    logger.debug("Plugin import warnings: %s", ", ".join(failures))

                ctx = contexts.Context()
                plugin_list = framework.list_plugins()
                if plugin_name not in plugin_list:
                    raise ValueError(f"Unknown volatility plugin: {plugin_name}")

                plugin = plugin_list[plugin_name]
                base_config_path = "plugins"

                single_location = requirements.URIRequirement.location_from_file(image_path)
                ctx.config["automagic.LayerStacker.single_location"] = single_location

                available_automagics = cast(Any, automagic).available(ctx)
                chosen_automagics = cast(Any, automagic).choose_automagic(available_automagics, plugin)
                if cast(Any, ctx.config).get("automagic.LayerStacker.stackers", None) is None:
                    ctx.config["automagic.LayerStacker.stackers"] = stacker.choose_os_stackers(plugin)

                # Reuse CLI file-handler implementation for any plugin side-file outputs.
                cli = CommandLine()
                cli.output_dir = os.path.dirname(os.path.abspath(out_path)) or constants.CACHE_PATH
                file_handler = cli.file_handler_class_factory()

                constructed = plugins.construct_plugin(
                    ctx,
                    chosen_automagics,
                    plugin,
                    base_config_path,
                    None,
                    file_handler,
                )

                grid = constructed.run()
                renderer = text_renderer.JsonRenderer()
                renderer.render(grid)

    def _run_plugin_cli(self, image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        original_argv = sys.argv[:]
        program = original_argv[0] if original_argv else "pixie"

        with open(out_path, "w", encoding="utf-8") as out_fh, open(err_path, "w", encoding="utf-8") as err_fh:
            try:
                sys.argv = [program, "-f", image_path, "-r", "json", plugin_name]
                with redirect_stdout(out_fh), redirect_stderr(err_fh):
                    cli = CommandLine()
                    cli.run()
            finally:
                sys.argv = original_argv
