"""
ArtifactCorrelator — cross-correlates Volatility3 plugin results to identify
suspicious patterns, hidden processes, injections, and other indicators.
"""

import re
import logging
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)

SUSPICIOUS_PARENT_CHILD: Dict[str, List[str]] = {
    "cmd.exe": [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
        "acrord32.exe", "foxit reader.exe", "mspaint.exe",
    ],
    "powershell.exe": [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe",
        "svchost.exe", "acrord32.exe", "mspaint.exe",
    ],
    "wscript.exe": [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msedge.exe", "chrome.exe", "firefox.exe",
    ],
    "cscript.exe": [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    ],
    "mshta.exe": [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msedge.exe", "chrome.exe", "firefox.exe", "svchost.exe",
    ],
    "regsvr32.exe": [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
        "msedge.exe", "chrome.exe", "firefox.exe", "svchost.exe",
    ],
    "rundll32.exe": [
        "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    ],
}

SUSPICIOUS_DLL_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\local\\temp\\",
    r"\\appdata\\roaming\\", r"\\users\\public\\",
    r"\\programdata\\", r"\\downloads\\", r"\\desktop\\",
]

SUSPICIOUS_CMDLINE_PATTERNS = [
    (r"-[Ee][Nn][Cc][Oo][Dd][Ee][Dd][Cc][Oo][Mm][Mm][Aa][Nn][Dd]", "PowerShell EncodedCommand"),
    (r"-[Ee][Nn][Cc]\s+[A-Za-z0-9+/=]{20,}", "PowerShell Base64 encoded command"),
    (r"[Cc]ert[Uu]til.*-[Uu][Rr][Ll][Cc]ache", "CertUtil download cradle"),
    (r"[Bb]its[Aa]dmin.*[Tt]ransfer", "BITSAdmin transfer"),
    (r"[Mm]shta\s+http", "MSHTA remote script"),
    (r"[Rr]egsvr32.*http", "Regsvr32 remote script"),
    (r"[Ww][Gg][Ee][Tt]\s+http", "WGet download"),
    (r"[Ii][Nn][Vv][Oo][Kk][Ee]-[Ee][Xx][Pp][Rr][Ee][Ss][Ss][Ii][Oo][Nn]", "IEX invocation"),
    (r"[Ii][Nn][Vv][Oo][Kk][Ee]-[Ww][Ee][Bb][Rr][Ee][Qq][Uu][Ee][Ss][Tt]", "IWR download"),
    (r"[Nn][Ee][Tt]\.[Ww][Ee][Bb][Cc][Ll][Ii][Ee][Nn][Tt]", "Net.WebClient download"),
    (r"[Ff]rom[Bb]ase64[Ss]tring", "Base64 decode"),
    (r"\-[Ee][Xx][Ee][Cc][Uu][Tt][Ii][Oo][Nn][Pp][Oo][Ll][Ii][Cc][Yy]\s+[Bb]ypass", "ExecutionPolicy Bypass"),
    (r"[Ww][Ii][Nn][Dd][Oo][Ww][Ss][Tt][Yy][Ll][Ee]\s+[Hh]idden", "Hidden window style"),
    (r"[Ss][Cc]\.exe.*create", "Service creation via sc.exe"),
    (r"schtasks.*\/create", "Scheduled task creation"),
    (r"vssadmin.*delete.*shadows", "Shadow copy deletion"),
    (r"wmic.*shadowcopy.*delete", "Shadow copy deletion via WMIC"),
    (r"net\s+user.*\/add", "User account creation"),
    (r"net\s+localgroup.*administrators.*\/add", "Adding user to admins"),
]

SUSPICIOUS_SERVICE_PATHS = [
    r"\\temp\\", r"\\tmp\\", r"\\appdata\\",
    r"\\users\\public\\", r"\\programdata\\(?!microsoft)",
    r"\\downloads\\", r"\\desktop\\",
]

PRIVILEGED_SUSPICIOUS = {
    "SeDebugPrivilege",
    "SeLoadDriverPrivilege",
    "SeCreateTokenPrivilege",
    "SeTcbPrivilege",
}

LEGITIMATE_SYSTEM_PROCESSES = {
    "system", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "svchost.exe", "lsm.exe",
    "spoolsv.exe", "dwm.exe",
}


class ArtifactCorrelator:
    def __init__(self, results: Dict[str, List[Dict]]):
        """
        :param results: dict mapping plugin name -> list of row dicts from VolatilityRunner.run_all()
        """
        self.results = results

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, plugin: str) -> List[Dict]:
        """Return plugin result rows, empty list if not present."""
        return self.results.get(plugin, [])

    def _pid_from_row(self, row: Dict) -> Optional[int]:
        """Try common PID column names and return int or None."""
        for key in ("PID", "pid", "Pid"):
            val = row.get(key)
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass
        return None

    def _name_from_row(self, row: Dict) -> str:
        """Try common process name column names."""
        for key in ("ImageFileName", "Name", "Process", "name", "process"):
            val = row.get(key)
            if val and str(val) not in ("N/A", "<unparsable>", ""):
                return str(val)
        return "<unknown>"

    # ------------------------------------------------------------------
    # Finding methods
    # ------------------------------------------------------------------

    def find_hidden_processes(self) -> List[Dict]:
        """
        Compare PIDs in psscan vs pslist.
        PIDs present in psscan but absent in pslist are considered hidden.
        """
        findings = []
        try:
            pslist_rows = self._get("pslist")
            psscan_rows = self._get("psscan")

            pslist_pids: Set[int] = set()
            for row in pslist_rows:
                pid = self._pid_from_row(row)
                if pid is not None:
                    pslist_pids.add(pid)

            seen_scan: Set[int] = set()
            for row in psscan_rows:
                pid = self._pid_from_row(row)
                if pid is None:
                    continue
                if pid in seen_scan:
                    continue
                seen_scan.add(pid)
                if pid not in pslist_pids:
                    findings.append({
                        "type": "hidden_process",
                        "severity": "CRITICAL",
                        "pid": pid,
                        "name": self._name_from_row(row),
                        "description": (
                            f"Process PID {pid} ({self._name_from_row(row)}) "
                            f"found in psscan but not in pslist — likely DKOM-hidden"
                        ),
                        "raw": row,
                    })
        except Exception as e:
            logger.warning(f"find_hidden_processes error: {e}")
        return findings

    def find_ghost_processes(self) -> List[Dict]:
        """
        Compare PIDs in pslist vs psscan.
        PIDs in pslist not in psscan may indicate process list manipulation.
        """
        findings = []
        try:
            pslist_rows = self._get("pslist")
            psscan_rows = self._get("psscan")

            psscan_pids: Set[int] = set()
            for row in psscan_rows:
                pid = self._pid_from_row(row)
                if pid is not None:
                    psscan_pids.add(pid)

            seen_list: Set[int] = set()
            for row in pslist_rows:
                pid = self._pid_from_row(row)
                if pid is None:
                    continue
                if pid in seen_list:
                    continue
                seen_list.add(pid)
                if pid not in psscan_pids:
                    findings.append({
                        "type": "ghost_process",
                        "severity": "LOW",
                        "pid": pid,
                        "name": self._name_from_row(row),
                        "description": (
                            f"Process PID {pid} ({self._name_from_row(row)}) "
                            f"in pslist but not in psscan — possible ghost/hollow process"
                        ),
                        "raw": row,
                    })
        except Exception as e:
            logger.warning(f"find_ghost_processes error: {e}")
        return findings

    def find_injected_processes(self) -> List[Dict]:
        """
        Identify processes with injected code regions from malfind output.
        """
        findings = []
        try:
            malfind_rows = self._get("malfind")
            seen: Set[int] = set()
            for row in malfind_rows:
                pid = self._pid_from_row(row)
                if pid is None:
                    continue
                name = self._name_from_row(row)
                va = row.get("Start VPN", row.get("StartVPN", row.get("Address", "N/A")))
                protection = row.get("Protection", row.get("Tag", "N/A"))
                hex_data = row.get("Hexdump", row.get("Bytes", row.get("Disassembly", "")))

                findings.append({
                    "type": "code_injection",
                    "severity": "HIGH",
                    "pid": pid,
                    "name": name,
                    "virtual_address": str(va),
                    "protection": str(protection),
                    "hex_preview": str(hex_data)[:200] if hex_data else "",
                    "description": (
                        f"Malfind flagged PID {pid} ({name}) at VA {va} "
                        f"with protection {protection}"
                    ),
                    "raw": row,
                })
        except Exception as e:
            logger.warning(f"find_injected_processes error: {e}")
        return findings

    def find_network_plus_injection(self) -> List[Dict]:
        """
        Find processes that have both injected code AND active network connections.
        """
        findings = []
        try:
            injections = self.find_injected_processes()
            injected_pids: Set[int] = {f["pid"] for f in injections if f.get("pid") is not None}

            net_pids: Set[int] = set()
            for plugin in ("netscan", "netstat"):
                for row in self._get(plugin):
                    pid = self._pid_from_row(row)
                    if pid is not None:
                        net_pids.add(pid)

            both = injected_pids & net_pids
            for pid in both:
                # Find process name from injections
                name = "<unknown>"
                for inj in injections:
                    if inj.get("pid") == pid:
                        name = inj.get("name", "<unknown>")
                        break
                findings.append({
                    "type": "network_injection",
                    "severity": "CRITICAL",
                    "pid": pid,
                    "name": name,
                    "description": (
                        f"PID {pid} ({name}) has both injected code (malfind) "
                        f"and active network connections — high-confidence C2 indicator"
                    ),
                })
        except Exception as e:
            logger.warning(f"find_network_plus_injection error: {e}")
        return findings

    def find_suspicious_parents(self) -> List[Dict]:
        """
        Identify suspicious parent-child process relationships using pstree/pslist.
        """
        findings = []
        try:
            pslist_rows = self._get("pslist")

            # Build PID -> {name, ppid} map
            pid_info: Dict[int, Dict] = {}
            for row in pslist_rows:
                pid = self._pid_from_row(row)
                if pid is None:
                    continue
                ppid = None
                for key in ("PPID", "ppid", "ParentPID", "InheritedFromUniqueProcessId"):
                    val = row.get(key)
                    if val is not None:
                        try:
                            ppid = int(val)
                            break
                        except (ValueError, TypeError):
                            pass
                pid_info[pid] = {
                    "name": self._name_from_row(row).lower(),
                    "ppid": ppid,
                    "raw": row,
                }

            # Now check each process against suspicious parent-child rules
            for pid, info in pid_info.items():
                child_name = info["name"]
                ppid = info.get("ppid")
                if ppid is None:
                    continue
                parent_info = pid_info.get(ppid)
                if not parent_info:
                    continue
                parent_name = parent_info["name"]

                # Check if this child spawned a suspicious child
                for suspicious_child, suspicious_parents in SUSPICIOUS_PARENT_CHILD.items():
                    if child_name == suspicious_child.lower():
                        if parent_name in [p.lower() for p in suspicious_parents]:
                            findings.append({
                                "type": "suspicious_parent_child",
                                "severity": "HIGH",
                                "pid": pid,
                                "name": child_name,
                                "ppid": ppid,
                                "parent_name": parent_name,
                                "description": (
                                    f"Suspicious parent-child: {parent_name} (PID {ppid}) "
                                    f"spawned {child_name} (PID {pid})"
                                ),
                                "raw": info["raw"],
                            })
        except Exception as e:
            logger.warning(f"find_suspicious_parents error: {e}")
        return findings

    def find_suspicious_dlls(self) -> List[Dict]:
        """
        Identify DLLs loaded from suspicious paths using dlllist output.
        """
        findings = []
        try:
            dlllist_rows = self._get("dlllist")
            for row in dlllist_rows:
                dll_path = str(row.get("Path", row.get("FullDllName", row.get("Base", ""))))
                if not dll_path or dll_path in ("N/A", "<unparsable>", ""):
                    continue
                dll_path_lower = dll_path.lower().replace("/", "\\")
                for pattern in SUSPICIOUS_DLL_PATHS:
                    if re.search(pattern, dll_path_lower):
                        pid = self._pid_from_row(row)
                        findings.append({
                            "type": "suspicious_dll",
                            "severity": "MEDIUM",
                            "pid": pid,
                            "name": self._name_from_row(row),
                            "dll_path": dll_path,
                            "matched_pattern": pattern,
                            "description": (
                                f"DLL loaded from suspicious path: {dll_path} "
                                f"(pattern: {pattern})"
                            ),
                            "raw": row,
                        })
                        break  # one match per DLL is enough
        except Exception as e:
            logger.warning(f"find_suspicious_dlls error: {e}")
        return findings

    def find_hidden_modules(self) -> List[Dict]:
        """
        Identify modules not present in all three loader lists (InLoad, InInit, InMem).
        """
        findings = []
        try:
            ldrmodules_rows = self._get("ldrmodules")
            for row in ldrmodules_rows:
                in_load = row.get("InLoad", row.get("InLdr", True))
                in_init = row.get("InInit", True)
                in_mem = row.get("InMem", True)

                # Normalize boolean-like values
                def to_bool(val) -> bool:
                    if isinstance(val, bool):
                        return val
                    if isinstance(val, int):
                        return bool(val)
                    if isinstance(val, str):
                        return val.strip().lower() not in ("false", "0", "no", "n/a", "")
                    return True

                missing = []
                if not to_bool(in_load):
                    missing.append("InLoad")
                if not to_bool(in_init):
                    missing.append("InInit")
                if not to_bool(in_mem):
                    missing.append("InMem")

                if missing:
                    pid = self._pid_from_row(row)
                    module_path = str(row.get("MappedPath", row.get("FullPath", row.get("Name", "unknown"))))
                    findings.append({
                        "type": "hidden_module",
                        "severity": "HIGH",
                        "pid": pid,
                        "name": self._name_from_row(row),
                        "module_path": module_path,
                        "missing_lists": missing,
                        "description": (
                            f"Module {module_path} not in loader lists: {', '.join(missing)} "
                            f"— possible rootkit DLL hiding"
                        ),
                        "raw": row,
                    })
        except Exception as e:
            logger.warning(f"find_hidden_modules error: {e}")
        return findings

    def find_suspicious_services(self) -> List[Dict]:
        """
        Identify services with binaries in suspicious paths.
        """
        findings = []
        try:
            svcscan_rows = self._get("svcscan")
            for row in svcscan_rows:
                binary = str(row.get("Binary", row.get("BinaryPath", row.get("PathName", ""))))
                if not binary or binary in ("N/A", "<unparsable>", ""):
                    continue
                binary_lower = binary.lower().replace("/", "\\")
                for pattern in SUSPICIOUS_SERVICE_PATHS:
                    if re.search(pattern, binary_lower):
                        svc_name = str(row.get("Name", row.get("ServiceName", "<unknown>")))
                        pid = self._pid_from_row(row)
                        findings.append({
                            "type": "suspicious_service",
                            "severity": "HIGH",
                            "pid": pid,
                            "service_name": svc_name,
                            "binary_path": binary,
                            "matched_pattern": pattern,
                            "description": (
                                f"Service '{svc_name}' binary in suspicious path: {binary}"
                            ),
                            "raw": row,
                        })
                        break
        except Exception as e:
            logger.warning(f"find_suspicious_services error: {e}")
        return findings

    def find_privileged_processes(self) -> List[Dict]:
        """
        Find non-system processes with dangerous privileges enabled.
        """
        findings = []
        try:
            priv_rows = self._get("privileges")
            for row in priv_rows:
                priv_name = str(row.get("Privilege", row.get("Name", "")))
                if priv_name not in PRIVILEGED_SUSPICIOUS:
                    continue
                attributes = str(row.get("Attributes", row.get("Present", "")))
                if "Present" not in attributes and "Enabled" not in attributes:
                    continue
                proc_name = self._name_from_row(row).lower()
                if proc_name in LEGITIMATE_SYSTEM_PROCESSES:
                    continue
                pid = self._pid_from_row(row)
                findings.append({
                    "type": "suspicious_privilege",
                    "severity": "MEDIUM",
                    "pid": pid,
                    "name": self._name_from_row(row),
                    "privilege": priv_name,
                    "attributes": attributes,
                    "description": (
                        f"Non-system process {self._name_from_row(row)} (PID {pid}) "
                        f"has {priv_name} [{attributes}]"
                    ),
                    "raw": row,
                })
        except Exception as e:
            logger.warning(f"find_privileged_processes error: {e}")
        return findings

    def find_suspicious_cmdlines(self) -> List[Dict]:
        """
        Scan command lines for known malicious patterns.
        """
        findings = []
        try:
            cmdline_rows = self._get("cmdline")
            for row in cmdline_rows:
                cmdline = str(row.get("Args", row.get("CommandLine", row.get("Cmdline", ""))))
                if not cmdline or cmdline in ("N/A", "<unparsable>", ""):
                    continue
                for pattern, description in SUSPICIOUS_CMDLINE_PATTERNS:
                    if re.search(pattern, cmdline):
                        pid = self._pid_from_row(row)
                        findings.append({
                            "type": "suspicious_cmdline",
                            "severity": "HIGH",
                            "pid": pid,
                            "name": self._name_from_row(row),
                            "cmdline": cmdline[:500],
                            "matched_pattern": pattern,
                            "match_description": description,
                            "description": (
                                f"Suspicious cmdline in {self._name_from_row(row)} "
                                f"(PID {pid}): {description}"
                            ),
                            "raw": row,
                        })
                        # Report each unique pattern match separately
        except Exception as e:
            logger.warning(f"find_suspicious_cmdlines error: {e}")
        return findings

    def find_network_connections(self) -> List[Dict]:
        """
        Collect all unique network connections, filtering out empty/loopback addresses.
        """
        findings = []
        try:
            LOOPBACK = {"127.0.0.1", "::1", "0.0.0.0", "::", "*", "-", ""}
            seen: Set[str] = set()

            for plugin in ("netscan", "netstat"):
                for row in self._get(plugin):
                    local_addr = str(row.get("LocalAddr", row.get("Local", row.get("LocalAddress", ""))))
                    foreign_addr = str(row.get("ForeignAddr", row.get("Foreign", row.get("RemoteAddress", ""))))
                    local_port = str(row.get("LocalPort", row.get("Port", "")))
                    foreign_port = str(row.get("ForeignPort", row.get("RemotePort", "")))
                    state = str(row.get("State", row.get("Status", "")))
                    proto = str(row.get("Proto", row.get("Protocol", row.get("Owner", ""))))
                    pid = self._pid_from_row(row)
                    name = self._name_from_row(row)

                    # Skip loopback/empty
                    foreign_ip = foreign_addr.split(":")[0] if ":" in foreign_addr else foreign_addr
                    if foreign_ip in LOOPBACK:
                        continue
                    local_ip = local_addr.split(":")[0] if ":" in local_addr else local_addr
                    if local_ip in LOOPBACK and foreign_ip in LOOPBACK:
                        continue

                    conn_key = f"{local_addr}:{local_port}->{foreign_addr}:{foreign_port}-{pid}"
                    if conn_key in seen:
                        continue
                    seen.add(conn_key)

                    findings.append({
                        "type": "network_connection",
                        "severity": "INFO",
                        "pid": pid,
                        "name": name,
                        "local_addr": local_addr,
                        "local_port": local_port,
                        "foreign_addr": foreign_addr,
                        "foreign_port": foreign_port,
                        "protocol": proto,
                        "state": state,
                        "description": (
                            f"Network connection: {local_addr}:{local_port} -> "
                            f"{foreign_addr}:{foreign_port} [{state}] PID={pid} ({name})"
                        ),
                        "raw": row,
                    })
        except Exception as e:
            logger.warning(f"find_network_connections error: {e}")
        return findings

    # ------------------------------------------------------------------
    # Main correlation entry point
    # ------------------------------------------------------------------

    def correlate_all(self) -> Dict[str, Any]:
        """
        Run all correlation checks and return a structured dict.
        """
        logger.info("Running artifact correlation...")

        hidden_processes = self.find_hidden_processes()
        ghost_processes = self.find_ghost_processes()
        injections = self.find_injected_processes()
        network_injections = self.find_network_plus_injection()
        suspicious_parents = self.find_suspicious_parents()
        suspicious_dlls = self.find_suspicious_dlls()
        hidden_modules = self.find_hidden_modules()
        suspicious_services = self.find_suspicious_services()
        privileged_processes = self.find_privileged_processes()
        suspicious_cmdlines = self.find_suspicious_cmdlines()
        network_connections = self.find_network_connections()

        summary_stats = {
            "hidden_processes":      len(hidden_processes),
            "ghost_processes":       len(ghost_processes),
            "injections":            len(injections),
            "network_injections":    len(network_injections),
            "suspicious_parents":    len(suspicious_parents),
            "suspicious_dlls":       len(suspicious_dlls),
            "hidden_modules":        len(hidden_modules),
            "suspicious_services":   len(suspicious_services),
            "privileged_processes":  len(privileged_processes),
            "suspicious_cmdlines":   len(suspicious_cmdlines),
            "network_connections":   len(network_connections),
            "total_findings": (
                len(hidden_processes) + len(injections) + len(network_injections)
                + len(suspicious_parents) + len(suspicious_dlls) + len(hidden_modules)
                + len(suspicious_services) + len(suspicious_cmdlines)
            ),
        }

        logger.info(f"Correlation complete: {summary_stats['total_findings']} total findings")

        return {
            "hidden_processes":     hidden_processes,
            "ghost_processes":      ghost_processes,
            "injections":           injections,
            "network_injections":   network_injections,
            "suspicious_parents":   suspicious_parents,
            "suspicious_dlls":      suspicious_dlls,
            "hidden_modules":       hidden_modules,
            "suspicious_services":  suspicious_services,
            "privileged_processes": privileged_processes,
            "suspicious_cmdlines":  suspicious_cmdlines,
            "network_connections":  network_connections,
            "summary_stats":        summary_stats,
        }
