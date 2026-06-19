#!/usr/bin/env python3
"""
VolaTriage — Automated Memory Forensics Triage Tool
Wraps Volatility3 to automate plugin execution, artifact correlation,
suspicion scoring, and structured HTML/JSON report generation.

Usage:
    python main.py -d /path/to/memory.dmp [options]

Supported dump formats:
    .raw .dd .mem .img .bin .dmp .vmem .vmsn .vmss .sav .lime .E01 .e01 hiberfil.sys
"""

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# ANSI color codes
# ---------------------------------------------------------------------------
RED    = "\033[91m"
ORANGE = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
DIM    = "\033[2m"

BANNER = f"""{CYAN}{BOLD}
 __   __    _       _____      _
 \\ \\ / /__ | | __ _|_   _| __(_) __ _  __ _  ___
  \\ V / _ \\| |/ _` | | || '__| |/ _` |/ _` |/ _ \\
   | | (_) | | (_| | | || |  | | (_| | (_| |  __/
   |_|\\___/|_|\\__,_| |_||_|  |_|\\__,_|\\__, |\\___|
                                        |___/
  Automated Memory Forensics Triage — Powered by Volatility3
{RESET}"""

LEVEL_COLORS = {
    "CRITICAL": RED,
    "HIGH":     ORANGE,
    "MEDIUM":   "\033[33m",   # yellow
    "LOW":      GREEN,
    "CLEAN":    DIM,
    "INFO":     BLUE,
}

SUPPORTED_EXTENSIONS = {
    ".raw", ".dd", ".mem", ".img", ".bin",
    ".dmp", ".vmem", ".vmsn", ".vmss", ".sav",
    ".lime", ".e01", ".E01",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _color(text: str, code: str, no_color: bool = False) -> str:
    return text if no_color else f"{code}{text}{RESET}"


def _step(n: int, total: int, msg: str, no_color: bool = False) -> None:
    tag = _color(f"[ {n}/{total} ]", CYAN + BOLD, no_color)
    print(f"\n{tag} {msg}")


def _ok(msg: str, no_color: bool = False) -> None:
    mark = _color("  ✓", GREEN, no_color)
    print(f"{mark} {msg}")


def _fail(msg: str, no_color: bool = False) -> None:
    mark = _color("  ✗", RED, no_color)
    print(f"{mark} {msg}")


def _box_line(no_color: bool = False) -> str:
    return _color("═" * 55, CYAN, no_color)


def _print_suspects_table(suspects, no_color: bool = False) -> None:
    """Print the top suspects in a formatted ASCII table."""
    if not suspects:
        print(_color("  No suspects found.", DIM, no_color))
        return

    header_line = _color("  ┌────┬──────────┬──────────────────────┬───────┬──────────┐", CYAN, no_color)
    header      = _color("  │ #  │   PID    │      Process         │ Score │  Level   │", CYAN + BOLD, no_color)
    divider     = _color("  ├────┼──────────┼──────────────────────┼───────┼──────────┤", CYAN, no_color)
    footer      = _color("  └────┴──────────┴──────────────────────┴───────┴──────────┘", CYAN, no_color)

    print(header_line)
    print(header)
    print(divider)

    for i, proc in enumerate(suspects, start=1):
        pid   = str(proc.get("pid", "?")).center(8)
        name  = str(proc.get("name", "?"))[:20].ljust(20)
        score = str(proc.get("score", 0)).center(5)
        level = str(proc.get("level", "?")).center(8)
        level_color = LEVEL_COLORS.get(proc.get("level", ""), "")

        row = (
            f"  │ {str(i).center(2)} │ {pid} │ {name} │ {score} │ "
            f"{_color(level, level_color, no_color)} │"
        )
        print(row)

    print(footer)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # ---- Argument parsing ----
    parser = argparse.ArgumentParser(
        prog="volatriage",
        description="VolaTriage — Automated Memory Forensics Triage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py -d memdump.dmp\n"
            "  python main.py -d memdump.raw --os windows --output /tmp/reports\n"
            "  python main.py -d memory.lime --os linux --plugins linux.pslist,linux.netstat\n"
        ),
    )
    parser.add_argument(
        "-d", "--dump", required=True,
        metavar="DUMP",
        help="Path to memory dump file",
    )
    parser.add_argument(
        "-o", "--output", default="./reports",
        metavar="DIR",
        help="Output directory for reports (default: ./reports)",
    )
    parser.add_argument(
        "--os", choices=["windows", "linux", "mac"],
        default=None,
        dest="os_hint",
        help="OS hint for plugin selection (auto-detected if omitted)",
    )
    parser.add_argument(
        "--plugins",
        metavar="PLUGINS",
        default=None,
        help="Comma-separated list of plugins to run (default: all for detected OS)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable ANSI color output",
    )

    args = parser.parse_args()
    no_color = args.no_color

    # ---- Banner ----
    if not no_color:
        print(BANNER)
    else:
        print("=== VolaTriage — Automated Memory Forensics Triage ===\n")

    # ---- Logging ----
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logger = logging.getLogger("volatriage")

    # ---- Validate dump file ----
    dump_path = os.path.abspath(args.dump)
    if not os.path.isfile(dump_path):
        print(_color(f"[ERROR] Dump file not found: {dump_path}", RED, no_color))
        return 1

    dump_size_mb = os.path.getsize(dump_path) / (1024 * 1024)
    dump_ext = Path(dump_path).suffix.lower()
    dump_name = Path(dump_path).name

    if dump_ext not in SUPPORTED_EXTENSIONS and dump_name.lower() != "hiberfil.sys":
        print(_color(
            f"[WARNING] Unrecognized dump extension '{dump_ext}'. "
            f"Proceeding anyway — Volatility3 may auto-detect format.",
            ORANGE, no_color,
        ))

    print(f"  {_color('Dump file:', BOLD, no_color)} {dump_path}")
    print(f"  {_color('Size:     ', BOLD, no_color)} {dump_size_mb:.1f} MB")
    if args.os_hint:
        print(f"  {_color('OS hint:  ', BOLD, no_color)} {args.os_hint}")

    # ---- Output directory ----
    output_dir = os.path.abspath(args.output)
    os.makedirs(output_dir, exist_ok=True)

    # ---- Plugin list ----
    plugin_names = None
    if args.plugins:
        plugin_names = [p.strip() for p in args.plugins.split(",") if p.strip()]

    start_time = datetime.now()

    # ====================================================================
    # STEP 1 — Initialize Volatility3
    # ====================================================================
    _step(1, 5, "Initializing Volatility3...", no_color)
    try:
        from vola_triage import VolatilityRunner
        runner = VolatilityRunner(dump_path=dump_path, os_hint=args.os_hint)
        _ok("Volatility3 framework initialized", no_color)
    except Exception as exc:
        print(_color(f"[FATAL] Failed to initialize Volatility3: {exc}", RED, no_color))
        logger.exception("Volatility3 init failed")
        return 1

    # ====================================================================
    # STEP 2 — Run plugins
    # ====================================================================
    _step(2, 5, "Running plugins...", no_color)
    try:
        os_detected = runner.detect_os()
        _ok(f"Detected OS: {os_detected.upper()}", no_color)
    except Exception as exc:
        os_detected = args.os_hint or "windows"
        _fail(f"OS detection failed ({exc}), defaulting to {os_detected}", no_color)

    try:
        results = runner.run_all(plugin_names=plugin_names)
    except Exception as exc:
        print(_color(f"[FATAL] Plugin execution failed: {exc}", RED, no_color))
        logger.exception("run_all failed")
        return 1

    for plugin_name, rows in results.items():
        if rows:
            _ok(f"{plugin_name}: {len(rows)} rows", no_color)
        else:
            _fail(f"{plugin_name}: 0 rows (plugin failed or no data)", no_color)

    # ====================================================================
    # STEP 3 — Correlate artifacts
    # ====================================================================
    _step(3, 5, "Correlating artifacts...", no_color)
    try:
        from vola_triage import ArtifactCorrelator
        correlator = ArtifactCorrelator(results)
        correlations = correlator.correlate_all()

        stats = correlations.get("summary_stats", {})
        _ok(f"Hidden processes:    {stats.get('hidden_processes', 0)}", no_color)
        _ok(f"Code injections:     {stats.get('injections', 0)}", no_color)
        _ok(f"Network injections:  {stats.get('network_injections', 0)}", no_color)
        _ok(f"Suspicious cmdlines: {stats.get('suspicious_cmdlines', 0)}", no_color)
        _ok(f"Suspicious services: {stats.get('suspicious_services', 0)}", no_color)
        _ok(f"Hidden modules:      {stats.get('hidden_modules', 0)}", no_color)
        _ok(f"Network connections: {stats.get('network_connections', 0)}", no_color)
    except Exception as exc:
        print(_color(f"[FATAL] Correlation failed: {exc}", RED, no_color))
        logger.exception("correlate_all failed")
        return 1

    # ====================================================================
    # STEP 4 — Score processes
    # ====================================================================
    _step(4, 5, "Scoring processes...", no_color)
    try:
        from vola_triage import SuspicionScorer
        pslist_rows = results.get("pslist", [])
        scorer = SuspicionScorer(pslist_results=pslist_rows, correlations=correlations)
        scores = scorer.score_all()
        score_stats = scorer.get_summary_stats()
        top_suspects = scorer.get_top_suspects(n=10)

        _ok(f"Total processes:   {score_stats.get('total_processes', 0)}", no_color)
        _ok(f"Suspicious:        {score_stats.get('suspicious_count', 0)}", no_color)
        _ok(
            _color(f"Critical:          {score_stats.get('critical_count', 0)}", RED, no_color),
            no_color,
        )
        _ok(
            _color(f"High:              {score_stats.get('high_count', 0)}", ORANGE, no_color),
            no_color,
        )
    except Exception as exc:
        print(_color(f"[FATAL] Scoring failed: {exc}", RED, no_color))
        logger.exception("score_all failed")
        return 1

    # ====================================================================
    # STEP 5 — Generate reports
    # ====================================================================
    _step(5, 5, "Generating reports...", no_color)

    # IOC JSON
    try:
        from vola_triage import IOCExporter
        ioc_exporter = IOCExporter(
            dump_path=dump_path,
            results=results,
            correlations=correlations,
            scores=scores,
        )
        ioc_path = ioc_exporter.export(output_dir)
        _ok(f"IOC JSON: {ioc_path}", no_color)
    except Exception as exc:
        ioc_path = ""
        _fail(f"IOC export failed: {exc}", no_color)
        logger.exception("IOC export failed")

    # HTML Report
    try:
        from vola_triage import ReportGenerator
        reporter = ReportGenerator(
            dump_path=dump_path,
            results=results,
            correlations=correlations,
            scores=scores,
            os_detected=os_detected,
            dump_size_mb=dump_size_mb,
            tool_version="1.0.0",
            ioc_path=ioc_path,
        )
        report_path = reporter.generate(output_dir)
        _ok(f"HTML report: {report_path}", no_color)
    except Exception as exc:
        report_path = ""
        _fail(f"HTML report failed: {exc}", no_color)
        logger.exception("Report generation failed")

    # ====================================================================
    # FINAL SUMMARY
    # ====================================================================
    elapsed = (datetime.now() - start_time).total_seconds()

    print(f"\n{_box_line(no_color)}")
    print(_color("  TRIAGE COMPLETE", BOLD + GREEN, no_color))
    print(_box_line(no_color))
    print(f"  {_color('Report: ', BOLD, no_color)} {report_path}")
    print(f"  {_color('IOCs:   ', BOLD, no_color)} {ioc_path}")
    print(f"  {_color('Time:   ', BOLD, no_color)} {elapsed:.1f}s")
    print(_box_line(no_color))

    if top_suspects:
        print(f"\n{_color('  TOP SUSPECTS:', BOLD, no_color)}")
        _print_suspects_table(top_suspects, no_color=no_color)

    critical_count = score_stats.get("critical_count", 0)
    if critical_count > 0:
        print()
        print(_color(
            f"  ⚠  {critical_count} CRITICAL process(es) detected — immediate investigation recommended.",
            RED + BOLD, no_color,
        ))

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
