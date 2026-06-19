"""
SuspicionScorer — assigns a numeric suspicion score to each process
based on correlation findings, then classifies processes by severity level.
"""

from typing import Dict, List, Any, Optional, Tuple

SCORE_WEIGHTS = {
    "hidden_process":        80,
    "code_injection":        70,
    "network_injection":     40,   # added on top of injection score
    "suspicious_parent":     40,
    "suspicious_privilege":  30,
    "suspicious_dll":        25,   # per DLL, max 60
    "hidden_module":         50,
    "suspicious_service":    60,
    "suspicious_cmdline":    35,
    "system_sid_non_system": 45,
}

SCORE_LEVELS = [
    (0,   10,  "CLEAN",    "#28a745"),
    (11,  30,  "LOW",      "#ffc107"),
    (31,  60,  "MEDIUM",   "#fd7e14"),
    (61,  100, "HIGH",     "#dc3545"),
    (101, 999, "CRITICAL", "#6f0000"),
]


class SuspicionScorer:
    def __init__(self, pslist_results: List[Dict], correlations: Dict[str, Any]):
        """
        :param pslist_results: raw rows from the pslist plugin
        :param correlations:   output of ArtifactCorrelator.correlate_all()
        """
        self.pslist_results = pslist_results
        self.correlations = correlations
        self._scores: Dict[int, Dict] = {}

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_score_level(self, score: int) -> Tuple[str, str]:
        """Return (level_string, hex_color) for a numeric score."""
        for low, high, label, color in SCORE_LEVELS:
            if low <= score <= high:
                return label, color
        return "CRITICAL", "#6f0000"

    def _pid_from_row(self, row: Dict) -> Optional[int]:
        for key in ("PID", "pid", "Pid"):
            val = row.get(key)
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass
        return None

    def _name_from_row(self, row: Dict) -> str:
        for key in ("ImageFileName", "Name", "Process", "name", "process"):
            val = row.get(key)
            if val and str(val) not in ("N/A", "<unparsable>", ""):
                return str(val)
        return "<unknown>"

    def _add_score(self, pid: int, delta: int, indicator: str):
        """Add delta points to a PID's score and record the indicator."""
        if pid not in self._scores:
            return  # only score known processes
        self._scores[pid]["score"] += delta
        self._scores[pid]["indicators"].append(indicator)

    # ------------------------------------------------------------------
    # Main scoring
    # ------------------------------------------------------------------

    def score_all(self) -> Dict[int, Dict]:
        """
        Score every process discovered in pslist.
        Returns a dict mapping PID -> scoring info dict.
        """
        # Initialize all known processes at score 0
        self._scores = {}
        for row in self.pslist_results:
            pid = self._pid_from_row(row)
            if pid is None:
                continue
            name = self._name_from_row(row)
            if pid not in self._scores:
                self._scores[pid] = {
                    "pid": pid,
                    "name": name,
                    "score": 0,
                    "level": "CLEAN",
                    "color": "#28a745",
                    "indicators": [],
                }

        # --- Hidden processes (+80) ---
        for finding in self.correlations.get("hidden_processes", []):
            pid = finding.get("pid")
            name = finding.get("name", "<hidden>")
            # Hidden processes may not be in pslist — add them
            if pid is not None and pid not in self._scores:
                self._scores[pid] = {
                    "pid": pid,
                    "name": name,
                    "score": 0,
                    "level": "CLEAN",
                    "color": "#28a745",
                    "indicators": [],
                }
            if pid is not None:
                self._add_score(pid, SCORE_WEIGHTS["hidden_process"],
                                f"Hidden process (DKOM): +{SCORE_WEIGHTS['hidden_process']}")

        # --- Code injection / malfind (+70 per finding) ---
        for finding in self.correlations.get("injections", []):
            pid = finding.get("pid")
            va = finding.get("virtual_address", "")
            prot = finding.get("protection", "")
            if pid is not None:
                if pid not in self._scores:
                    self._scores[pid] = {
                        "pid": pid,
                        "name": finding.get("name", "<unknown>"),
                        "score": 0, "level": "CLEAN", "color": "#28a745",
                        "indicators": [],
                    }
                self._add_score(pid, SCORE_WEIGHTS["code_injection"],
                                f"Code injection at {va} [{prot}]: +{SCORE_WEIGHTS['code_injection']}")

        # --- Network injection (+40 on top) ---
        for finding in self.correlations.get("network_injections", []):
            pid = finding.get("pid")
            if pid is not None:
                if pid not in self._scores:
                    self._scores[pid] = {
                        "pid": pid,
                        "name": finding.get("name", "<unknown>"),
                        "score": 0, "level": "CLEAN", "color": "#28a745",
                        "indicators": [],
                    }
                self._add_score(pid, SCORE_WEIGHTS["network_injection"],
                                f"Active network connection + injection: +{SCORE_WEIGHTS['network_injection']}")

        # --- Suspicious parent-child (+40) ---
        for finding in self.correlations.get("suspicious_parents", []):
            pid = finding.get("pid")
            parent = finding.get("parent_name", "?")
            child = finding.get("name", "?")
            if pid is not None:
                self._add_score(pid, SCORE_WEIGHTS["suspicious_parent"],
                                f"Spawned by {parent}: +{SCORE_WEIGHTS['suspicious_parent']}")

        # --- Suspicious DLLs (+25 each, capped at 60 per PID) ---
        dll_contribution: Dict[int, int] = {}
        for finding in self.correlations.get("suspicious_dlls", []):
            pid = finding.get("pid")
            dll_path = finding.get("dll_path", "")
            if pid is None:
                continue
            current = dll_contribution.get(pid, 0)
            if current >= 60:
                continue
            delta = min(SCORE_WEIGHTS["suspicious_dll"], 60 - current)
            dll_contribution[pid] = current + delta
            self._add_score(pid, delta,
                            f"Suspicious DLL path [{dll_path}]: +{delta}")

        # --- Hidden modules (+50) ---
        for finding in self.correlations.get("hidden_modules", []):
            pid = finding.get("pid")
            module = finding.get("module_path", "")
            missing = finding.get("missing_lists", [])
            if pid is not None:
                self._add_score(pid, SCORE_WEIGHTS["hidden_module"],
                                f"Hidden module {module} (missing: {missing}): +{SCORE_WEIGHTS['hidden_module']}")

        # --- Suspicious services (+60) ---
        # Services don't always have a clear PID in the findings; try to match
        for finding in self.correlations.get("suspicious_services", []):
            pid = finding.get("pid")
            svc_name = finding.get("service_name", "")
            binary = finding.get("binary_path", "")
            if pid is not None and pid in self._scores:
                self._add_score(pid, SCORE_WEIGHTS["suspicious_service"],
                                f"Service binary in suspicious path [{binary}]: +{SCORE_WEIGHTS['suspicious_service']}")
            else:
                # Can't tie to a PID; create a synthetic entry
                if pid is not None:
                    if pid not in self._scores:
                        self._scores[pid] = {
                            "pid": pid,
                            "name": svc_name,
                            "score": 0, "level": "CLEAN", "color": "#28a745",
                            "indicators": [],
                        }
                    self._add_score(pid, SCORE_WEIGHTS["suspicious_service"],
                                    f"Service binary in suspicious path [{binary}]: +{SCORE_WEIGHTS['suspicious_service']}")

        # --- Suspicious cmdlines (+35) ---
        for finding in self.correlations.get("suspicious_cmdlines", []):
            pid = finding.get("pid")
            match_desc = finding.get("match_description", "")
            if pid is not None:
                if pid not in self._scores:
                    self._scores[pid] = {
                        "pid": pid,
                        "name": finding.get("name", "<unknown>"),
                        "score": 0, "level": "CLEAN", "color": "#28a745",
                        "indicators": [],
                    }
                self._add_score(pid, SCORE_WEIGHTS["suspicious_cmdline"],
                                f"Suspicious cmdline [{match_desc}]: +{SCORE_WEIGHTS['suspicious_cmdline']}")

        # --- Privileged processes (+30) ---
        for finding in self.correlations.get("privileged_processes", []):
            pid = finding.get("pid")
            priv = finding.get("privilege", "")
            if pid is not None:
                self._add_score(pid, SCORE_WEIGHTS["suspicious_privilege"],
                                f"Dangerous privilege {priv}: +{SCORE_WEIGHTS['suspicious_privilege']}")

        # --- Finalize: assign level and color based on score ---
        for pid, data in self._scores.items():
            level, color = self._get_score_level(data["score"])
            data["level"] = level
            data["color"] = color

        return self._scores

    def get_top_suspects(self, n: int = 10) -> List[Dict]:
        """
        Return the top n processes by score (descending), excluding score == 0.
        """
        if not self._scores:
            self.score_all()
        suspects = [data for data in self._scores.values() if data["score"] > 0]
        suspects.sort(key=lambda x: x["score"], reverse=True)
        return suspects[:n]

    def get_summary_stats(self) -> Dict[str, int]:
        """
        Return aggregate statistics across all scored processes.
        """
        if not self._scores:
            self.score_all()
        total = len(self._scores)
        suspicious = sum(1 for d in self._scores.values() if d["score"] > 10)
        critical = sum(1 for d in self._scores.values() if d["level"] == "CRITICAL")
        high = sum(1 for d in self._scores.values() if d["level"] == "HIGH")
        medium = sum(1 for d in self._scores.values() if d["level"] == "MEDIUM")
        low = sum(1 for d in self._scores.values() if d["level"] == "LOW")
        return {
            "total_processes": total,
            "suspicious_count": suspicious,
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
        }
