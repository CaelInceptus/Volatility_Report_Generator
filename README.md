# VolaTriage

Automated memory forensics triage tool built on top of the **Volatility3 Python API**.  
Runs a full plugin suite against a memory dump, correlates artifacts, scores suspicious processes and generates a self-contained HTML report + IOC JSON export.

---

## Features

- Automatic plugin execution (20 Windows / 7 Linux / 4 macOS plugins)
- Artifact correlation engine (DKOM, process injection, suspicious parents, hidden modules, etc.)
- Heuristic suspicion scoring per process (CLEAN → LOW → MEDIUM → HIGH → CRITICAL)
- Self-contained dark-theme HTML report (no CDN, embedded CSS + JS)
- IOC JSON export (IPs, file paths, injections, hidden processes)

---

## Requirements

```
Python 3.9+
volatility3 >= 2.4.0
jinja2 >= 3.1.0
```

```bash
pip install volatility3 jinja2
```

> **Symbols** : Volatility3 requires ISF symbol tables to analyze Windows/Linux dumps.  
> Download them from the [Volatility3 symbols repository](https://downloads.volatilityfoundation.org/volatility3/symbols/) and place them in `~/.local/lib/python3.x/site-packages/volatility3/symbols/`.

---

## Supported dump formats

| Format | Extensions |
|--------|-----------|
| Raw physical memory | `.raw` `.dd` `.mem` `.img` `.bin` |
| Windows crash dump / WinPmem | `.dmp` |
| Windows hibernation | `hiberfil.sys` |
| VMware snapshot / suspend | `.vmem` `.vmsn` `.vmss` |
| VirtualBox saved state | `.sav` |
| LiME (Linux Memory Extractor) | `.lime` |
| Expert Witness Format | `.E01` `.e01` *(requires libewf)* |

---

## Usage

```bash
python main.py -d <dump_file> [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-d`, `--dump` | Path to memory dump *(required)* | — |
| `-o`, `--output` | Output directory for reports | `./reports/` |
| `--os` | Force OS selection: `windows` / `linux` / `mac` | auto-detect |
| `--plugins` | Comma-separated plugin list to override defaults | all |
| `-v`, `--verbose` | Enable debug logging | off |
| `--no-color` | Disable ANSI colors | off |

### Examples

```bash
# Basic Windows dump analysis
python main.py -d MemoryDump.mem

# Specify OS and custom output directory
python main.py -d memdump.dmp --os windows -o /tmp/forensics/

# Linux LiME dump, specific plugins only
python main.py -d memory.lime --os linux --plugins linux.pslist,linux.netstat

# Verbose mode (shows per-plugin debug output)
python main.py -d dump.vmem -v
```

---

## Output

```
reports/
├── volatriage_report_YYYYMMDD_HHMMSS.html   # Full HTML report
└── volatriage_iocs_YYYYMMDD_HHMMSS.json     # IOC export
```

### HTML Report sections

1. **Executive Summary** — process counts, injections, hidden processes, network connections
2. **Top Suspects** — processes ranked by suspicion score with key indicators
3. **Critical & High Findings** — grouped correlation findings by severity
4. **Network Activity** — all external connections with associated processes
5. **Code Injections** — malfind results with hex preview
6. **All Processes** — full sortable process table
7. **Raw Plugin Data** — collapsible sections (pslist, psscan, modules, svcscan, netscan, cmdline)

### IOC JSON structure

```json
{
  "metadata": { "generated_at": "...", "tool": "VolaTriage v1.0.0" },
  "iocs": {
    "ip_addresses": [...],
    "file_paths": [...],
    "process_names": [...]
  },
  "suspicious_processes": [...],
  "network_connections": [...],
  "injections": [...],
  "hidden_processes": [...]
}
```

---

## Scoring

Each process starts at 0 and accumulates points from correlated findings:

| Indicator | Score |
|-----------|-------|
| Hidden process (DKOM — in psscan, not pslist) | +80 |
| Code injection (malfind) | +70 |
| Network connection on injected process | +40 *(bonus)* |
| Suspicious parent-child relationship | +40 |
| Hidden module (ldrmodules InLoad/InInit/InMem = False) | +50 |
| Suspicious service binary path | +60 |
| Suspicious DLL path (Temp, AppData…) | +25 *(max +60)* |
| Suspicious cmdline (Base64, IEX, certutil…) | +35 |
| Dangerous privilege enabled (SeDebugPrivilege…) | +30 |

| Score | Level |
|-------|-------|
| 0 – 10 | CLEAN |
| 11 – 30 | LOW |
| 31 – 60 | MEDIUM |
| 61 – 100 | HIGH |
| > 100 | CRITICAL |

---

## Project structure

```
├── main.py                  # CLI entry point
└── vola_triage/
    ├── runner.py            # Volatility3 Python API — plugin execution
    ├── correlator.py        # Artifact correlation (DKOM, injection, parents…)
    ├── scorer.py            # Heuristic suspicion scoring
    ├── report.py            # HTML report generation (Jinja2)
    └── ioc_exporter.py      # IOC JSON export
```

---

## TO-DO

- [ ] **Process whitelist** — exclude known-legitimate processes (FTK Imager, vmtoolsd, system processes running in VM environments) from scoring to reduce false positives
- [ ] **Scorer refinement for false positives** — adjust ldrmodules weight (currently over-represented at 81 hidden modules for legitimate DLLs), add per-indicator confidence levels, and tune thresholds based on process context (system vs user-land)
