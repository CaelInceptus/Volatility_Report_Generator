"""
IOCExporter — extracts Indicators of Compromise from analysis results
and exports them to a structured JSON file.
"""

import json
import re
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Set

PRIVATE_IP_PATTERNS = [
    r'^10\.',
    r'^172\.(1[6-9]|2[0-9]|3[01])\.',
    r'^192\.168\.',
    r'^127\.',
    r'^::1$',
    r'^0\.0\.0\.0$',
    r'^\*$',
    r'^-$',
]


class IOCExporter:
    def __init__(
        self,
        dump_path: str,
        results: Dict[str, List[Dict]],
        correlations: Dict[str, Any],
        scores: Dict[int, Dict],
    ):
        """
        :param dump_path:    path to the memory dump file
        :param results:      raw plugin results from VolatilityRunner.run_all()
        :param correlations: output from ArtifactCorrelator.correlate_all()
        :param scores:       output from SuspicionScorer.score_all()
        """
        self.dump_path = dump_path
        self.results = results
        self.correlations = correlations
        self.scores = scores

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _is_private_or_empty(self, ip: str) -> bool:
        """Return True if the IP is private, loopback, empty, or a placeholder."""
        if not ip or not ip.strip():
            return True
        ip = ip.strip()
        for pattern in PRIVATE_IP_PATTERNS:
            if re.match(pattern, ip):
                return True
        return False

    def _get_plugin(self, name: str) -> List[Dict]:
        return self.results.get(name, [])

    # ------------------------------------------------------------------
    # Extraction methods
    # ------------------------------------------------------------------

    def _extract_ips(self) -> List[str]:
        """Extract unique external IP addresses from netscan/netstat ForeignAddr fields."""
        ips: Set[str] = set()
        for plugin in ("netscan", "netstat"):
            for row in self._get_plugin(plugin):
                for key in ("ForeignAddr", "Foreign", "RemoteAddress", "RemoteAddr"):
                    val = str(row.get(key, ""))
                    if not val or val in ("N/A", "<unparsable>", "-", "*", ""):
                        continue
                    # Strip port if present (e.g. "1.2.3.4:443" or "[::1]:80")
                    val = val.strip()
                    if val.startswith("["):
                        # IPv6 bracket notation
                        m = re.match(r'^\[([^\]]+)\]', val)
                        ip = m.group(1) if m else val
                    elif ":" in val:
                        # Could be IPv4:port or bare IPv6
                        parts = val.rsplit(":", 1)
                        # If last part is a port number
                        if parts[-1].isdigit():
                            ip = parts[0]
                        else:
                            ip = val
                    else:
                        ip = val
                    if not self._is_private_or_empty(ip):
                        ips.add(ip)
                    break  # only first matching key per row
        return sorted(ips)

    def _extract_file_paths(self) -> List[str]:
        """Collect suspicious file paths from malfind, DLL findings, and service findings."""
        paths: Set[str] = set()

        # From malfind: virtual addresses aren't file paths, but process names can hint
        # at injected binaries — skip VA, but collect process names with injection
        for finding in self.correlations.get("injections", []):
            name = finding.get("name", "")
            if name and name not in ("<unknown>", "N/A"):
                # Not a file path per se; skip
                pass

        # From suspicious DLLs
        for finding in self.correlations.get("suspicious_dlls", []):
            path = finding.get("dll_path", "")
            if path and path not in ("N/A", "<unparsable>", ""):
                paths.add(path)

        # From suspicious services
        for finding in self.correlations.get("suspicious_services", []):
            binary = finding.get("binary_path", "")
            if binary and binary not in ("N/A", "<unparsable>", ""):
                paths.add(binary)

        # From hidden modules
        for finding in self.correlations.get("hidden_modules", []):
            module = finding.get("module_path", "")
            if module and module not in ("N/A", "<unparsable>", "unknown"):
                paths.add(module)

        # From filescan (if available) — pick any suspicious-looking paths
        for row in self._get_plugin("filescan"):
            file_name = str(row.get("Name", row.get("FileName", row.get("File", ""))))
            if not file_name or file_name in ("N/A", "<unparsable>"):
                continue
            lower = file_name.lower()
            suspicious_keywords = [
                "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
                "\\users\\public\\", "\\programdata\\",
            ]
            for kw in suspicious_keywords:
                if kw in lower:
                    paths.add(file_name)
                    break

        return sorted(paths)

    def _extract_suspicious_processes(self) -> List[Dict]:
        """Return processes with score > 30."""
        procs = []
        for pid, data in self.scores.items():
            if data.get("score", 0) > 30:
                procs.append({
                    "pid": data.get("pid"),
                    "name": data.get("name", "<unknown>"),
                    "score": data.get("score", 0),
                    "level": data.get("level", "UNKNOWN"),
                    "indicators": data.get("indicators", []),
                })
        procs.sort(key=lambda x: x["score"], reverse=True)
        return procs

    def _extract_network_connections(self) -> List[Dict]:
        """Deduplicate and return network connection records."""
        connections: List[Dict] = []
        seen: Set[str] = set()
        for conn in self.correlations.get("network_connections", []):
            key = (
                f"{conn.get('local_addr')}:{conn.get('local_port')}"
                f"->{conn.get('foreign_addr')}:{conn.get('foreign_port')}"
                f"-{conn.get('pid')}"
            )
            if key in seen:
                continue
            seen.add(key)
            connections.append({
                "pid": conn.get("pid"),
                "process": conn.get("name"),
                "protocol": conn.get("protocol"),
                "local_addr": conn.get("local_addr"),
                "local_port": conn.get("local_port"),
                "foreign_addr": conn.get("foreign_addr"),
                "foreign_port": conn.get("foreign_port"),
                "state": conn.get("state"),
            })
        return connections

    def _extract_injections(self) -> List[Dict]:
        """Extract injection details from malfind findings."""
        injections: List[Dict] = []
        for finding in self.correlations.get("injections", []):
            injections.append({
                "pid": finding.get("pid"),
                "name": finding.get("name", "<unknown>"),
                "va": finding.get("virtual_address", ""),
                "protection": finding.get("protection", ""),
                "hex_preview": finding.get("hex_preview", "")[:200],
            })
        return injections

    def _extract_hidden_processes(self) -> List[Dict]:
        """Return hidden process records from correlation."""
        hidden: List[Dict] = []
        for finding in self.correlations.get("hidden_processes", []):
            hidden.append({
                "pid": finding.get("pid"),
                "name": finding.get("name", "<unknown>"),
                "description": finding.get("description", ""),
            })
        return hidden

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export(self, output_dir: str) -> str:
        """
        Write IOC JSON file to output_dir.
        Returns the path to the written file.
        """
        os.makedirs(output_dir, exist_ok=True)

        ips = self._extract_ips()
        file_paths = self._extract_file_paths()
        suspicious_processes = self._extract_suspicious_processes()
        network_connections = self._extract_network_connections()
        injections = self._extract_injections()
        hidden_processes = self._extract_hidden_processes()

        # Build process_names IOC list (unique names from suspicious procs)
        process_names = sorted(
            set(p["name"] for p in suspicious_processes if p.get("name") and p["name"] != "<unknown>")
        )

        total_iocs = len(ips) + len(file_paths) + len(process_names)

        payload = {
            "metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "tool": "VolaTriage v1.0.0",
                "dump_path": self.dump_path,
                "total_iocs": total_iocs,
            },
            "iocs": {
                "ip_addresses": ips,
                "file_paths": file_paths,
                "process_names": process_names,
                "registry_keys": [],
                "hashes": [],
                "mutexes": [],
            },
            "suspicious_processes": suspicious_processes,
            "network_connections": network_connections,
            "injections": injections,
            "hidden_processes": hidden_processes,
        }

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"volatriage_iocs_{timestamp}.json"
        output_path = os.path.join(output_dir, filename)

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)

        return output_path
