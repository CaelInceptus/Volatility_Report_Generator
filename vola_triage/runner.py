"""
VolatilityRunner — executes Volatility3 plugins via the Python API.

Supported memory dump formats:
  Raw:       .raw, .dd, .mem, .img, .bin
  Windows:   .dmp (crash dump / WinPmem), hiberfil.sys (hibernation)
  VMware:    .vmem, .vmsn (snapshot), .vmss (suspend state)
  VirtualBox:.sav
  LiME:      .lime (Linux Memory Extractor)
  EWF:       .E01, .e01 (Expert Witness Format, requires libewf)
"""

import os
import logging
import importlib
from typing import Dict, List, Optional, Any
from pathlib import Path

logger = logging.getLogger(__name__)

WINDOWS_PLUGINS: Dict[str, str] = {
    "pslist":     "volatility3.plugins.windows.pslist.PsList",
    "psscan":     "volatility3.plugins.windows.psscan.PsScan",
    "pstree":     "volatility3.plugins.windows.pstree.PsTree",
    "cmdline":    "volatility3.plugins.windows.cmdline.CmdLine",
    "dlllist":    "volatility3.plugins.windows.dlllist.DllList",
    "netscan":    "volatility3.plugins.windows.netscan.NetScan",
    "netstat":    "volatility3.plugins.windows.netstat.NetStat",
    "malfind":    "volatility3.plugins.windows.malfind.Malfind",
    "ldrmodules": "volatility3.plugins.windows.ldrmodules.LdrModules",
    "handles":    "volatility3.plugins.windows.handles.Handles",
    "svcscan":    "volatility3.plugins.windows.svcscan.SvcScan",
    "modules":    "volatility3.plugins.windows.modules.Modules",
    "modscan":    "volatility3.plugins.windows.modscan.ModScan",
    "privileges": "volatility3.plugins.windows.privileges.Privs",
    "getsids":    "volatility3.plugins.windows.getsids.GetSIDs",
    "envars":     "volatility3.plugins.windows.envars.Envars",
    "filescan":   "volatility3.plugins.windows.filescan.FileScan",
    "callbacks":  "volatility3.plugins.windows.callbacks.Callbacks",
    "ssdt":       "volatility3.plugins.windows.ssdt.SSDT",
    "driverirp":  "volatility3.plugins.windows.driverirp.DriverIrp",
}

LINUX_PLUGINS: Dict[str, str] = {
    "linux.pslist":        "volatility3.plugins.linux.pslist.PsList",
    "linux.pstree":        "volatility3.plugins.linux.pstree.PsTree",
    "linux.netstat":       "volatility3.plugins.linux.netstat.Netstat",
    "linux.lsof":          "volatility3.plugins.linux.lsof.Lsof",
    "linux.bash":          "volatility3.plugins.linux.bash.Bash",
    "linux.check_modules": "volatility3.plugins.linux.check_modules.Check_modules",
    "linux.check_creds":   "volatility3.plugins.linux.check_creds.Check_creds",
}

MAC_PLUGINS: Dict[str, str] = {
    "mac.pslist": "volatility3.plugins.mac.pslist.PsList",
    "mac.pstree": "volatility3.plugins.mac.pstree.PsTree",
    "mac.netstat": "volatility3.plugins.mac.netstat.Netstat",
    "mac.lsof":   "volatility3.plugins.mac.lsof.Lsof",
}

OS_PLUGIN_MAP: Dict[str, Dict[str, str]] = {
    "windows": WINDOWS_PLUGINS,
    "linux":   LINUX_PLUGINS,
    "mac":     MAC_PLUGINS,
}


class VolatilityRunner:
    def __init__(self, dump_path: str, os_hint: Optional[str] = None):
        self.dump_path = os.path.abspath(dump_path)
        self.os_hint = os_hint
        self._context = None
        self._detected_os = None
        self._init_framework()

    def _init_framework(self):
        from volatility3.framework import contexts, automagic, constants
        import volatility3.framework
        volatility3.framework.require_interface_version(2, 0, 0)
        self._context = contexts.Context()
        self._context.config['automagic.LayerStacker.single_location'] = f"file://{self.dump_path}"
        # Suppress framework verbosity
        constants.LOGLEVEL_VVVV = 9

    def detect_os(self) -> str:
        if self.os_hint:
            self._detected_os = self.os_hint.lower()
            return self._detected_os
        if self._detected_os:
            return self._detected_os
        # Try each OS by attempting to run a lightweight plugin
        for os_name, plugins in OS_PLUGIN_MAP.items():
            first_plugin_path = list(plugins.values())[0]
            try:
                plugin_class = self._import_plugin(first_plugin_path)
                self._run_plugin_class(plugin_class)
                self._detected_os = os_name
                logger.info(f"Detected OS: {os_name}")
                return os_name
            except Exception as e:
                logger.debug(f"OS detection attempt {os_name} failed: {e}")
                continue
        self._detected_os = "windows"  # fallback
        logger.warning("OS detection failed, defaulting to windows")
        return self._detected_os

    def _import_plugin(self, dotted_path: str):
        module_path, class_name = dotted_path.rsplit(".", 1)
        module = importlib.import_module(module_path)
        return getattr(module, class_name)

    @staticmethod
    def _convert_value(val) -> Any:
        try:
            from volatility3.framework import renderers
            if isinstance(val, renderers.NotApplicableValue):
                return "N/A"
            if isinstance(val, renderers.NotAvailableValue):
                return "N/A"
            if isinstance(val, renderers.UnparsableValue):
                return "<unparsable>"
            if hasattr(renderers, 'MultiTypeData') and isinstance(val, renderers.MultiTypeData):
                return str(val)
        except ImportError:
            pass
        if isinstance(val, bytes):
            return val.hex()
        if isinstance(val, (int, float, bool, type(None))):
            return val
        return str(val)

    def _run_plugin_class(self, plugin_class) -> List[Dict]:
        from volatility3.framework import contexts, automagic
        from volatility3 import plugins as vol_plugins

        # Try to suppress output from Volatility3
        try:
            from volatility3.cli import MuteProgress
            progress = MuteProgress()
        except ImportError:
            progress = None

        ctx = self._context.clone()
        available_automagics = automagic.available(ctx)
        plugin_automagics = automagic.choose_automagic(available_automagics, plugin_class)
        constructed = vol_plugins.construct_plugin(
            ctx, plugin_automagics, plugin_class, "plugins", progress, None
        )
        treegrid = constructed.run()
        columns = [col.name for col in treegrid.columns]
        rows: List[Dict] = []

        def visitor(node, accumulator):
            row = {}
            for col, val in zip(columns, node.values):
                row[col] = self._convert_value(val)
            accumulator.append(row)
            return accumulator

        treegrid.populate(visitor, rows)
        return rows

    def run_plugin(self, plugin_name: str) -> List[Dict]:
        os_name = self.detect_os()
        plugin_map = OS_PLUGIN_MAP.get(os_name, WINDOWS_PLUGINS)
        dotted_path = plugin_map.get(plugin_name)
        if not dotted_path:
            raise ValueError(f"Unknown plugin: {plugin_name} for OS {os_name}")
        plugin_class = self._import_plugin(dotted_path)
        return self._run_plugin_class(plugin_class)

    def run_all(self, plugin_names: Optional[List[str]] = None) -> Dict[str, List[Dict]]:
        os_name = self.detect_os()
        plugin_map = OS_PLUGIN_MAP.get(os_name, WINDOWS_PLUGINS)
        names_to_run = plugin_names if plugin_names else list(plugin_map.keys())
        results: Dict[str, List[Dict]] = {}
        for name in names_to_run:
            try:
                logger.info(f"Running plugin: {name}")
                results[name] = self.run_plugin(name)
                logger.info(f"  OK {name}: {len(results[name])} rows")
            except Exception as e:
                logger.warning(f"  FAIL {name}: {e}")
                results[name] = []
        return results
