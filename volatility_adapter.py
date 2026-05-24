import logging
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, cast

import constants as C
from volatility3.cli import CommandLine # type: ignore[import-untyped]
import volatility3.plugins # type: ignore[import-untyped]
from volatility3 import framework # type: ignore[import-untyped]
from volatility3.cli import text_renderer # type: ignore[import-untyped]
from volatility3.framework import automagic, constants, contexts, plugins # type: ignore[import-untyped]
from volatility3.framework.automagic import stacker # type: ignore[import-untyped]
from volatility3.framework.configuration import requirements # type: ignore[import-untyped]

logger = logging.getLogger(__name__)


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
        if self.prefer_library and plugin_name in C.LIBRARY_MODE_PLUGINS:
            try:
                self._run_plugin_library(image_path, plugin_name, out_path, err_path)
                return C.MODE_LIBRARY
            except Exception:
                logger.exception(C.MSG_PLUGIN_FALLBACK, plugin_name)
                if not self.enable_cli_fallback:
                    raise

        self._run_plugin_cli(image_path, plugin_name, out_path, err_path)
        return C.MODE_CLI

    def _run_plugin_library(self, image_path: str, plugin_name: str, out_path: str, err_path: str) -> None:
        """Execute selected plugins via Volatility framework APIs directly."""
        framework_api = cast(Any, framework)
        volatility_plugins = cast(Any, volatility3.plugins)
        framework_api.require_interface_version(C.VOLATILITY_IFACE_MAJOR, C.VOLATILITY_IFACE_MINOR, C.VOLATILITY_IFACE_PATCH)

        with open(out_path, C.FILE_MODE_WRITE, encoding=C.ENCODING_UTF8) as out_fh, open(err_path, C.FILE_MODE_WRITE, encoding=C.ENCODING_UTF8) as err_fh:
            with redirect_stdout(out_fh), redirect_stderr(err_fh):
                failures: list[str] = list(framework_api.import_files(volatility_plugins, True))
                if failures:
                    logger.debug(C.MSG_PLUGIN_IMPORT_WARNINGS, C.JOIN_COMMA_SPACE.join(failures))

                ctx = contexts.Context()
                plugin_list = cast(dict[str, Any], framework_api.list_plugins())
                if plugin_name not in plugin_list:
                    raise ValueError(C.MSG_UNKNOWN_PLUGIN.format(plugin=plugin_name))

                plugin = plugin_list[plugin_name]
                base_config_path = C.VOLATILITY_BASE_CONFIG_PATH

                single_location = requirements.URIRequirement.location_from_file(image_path)
                ctx.config[C.VOLATILITY_AUTOMAGIC_SINGLE_LOCATION] = single_location

                available_automagics = cast(Any, automagic).available(ctx)
                chosen_automagics = cast(Any, automagic).choose_automagic(available_automagics, plugin)
                if cast(Any, ctx.config).get(C.VOLATILITY_AUTOMAGIC_STACKERS, None) is None:
                    ctx.config[C.VOLATILITY_AUTOMAGIC_STACKERS] = stacker.choose_os_stackers(plugin)

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
        program = original_argv[0] if original_argv else C.KEY_PIXIE

        with open(out_path, C.FILE_MODE_WRITE, encoding=C.ENCODING_UTF8) as out_fh, open(err_path, C.FILE_MODE_WRITE, encoding=C.ENCODING_UTF8) as err_fh:
            try:
                sys.argv = [program, C.KEY_DASH_F, image_path, C.KEY_DASH_R, C.KEY_JSON, plugin_name]
                with redirect_stdout(out_fh), redirect_stderr(err_fh):
                    cli = CommandLine()
                    cli.run()
            finally:
                sys.argv = original_argv
