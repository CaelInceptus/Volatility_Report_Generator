"""
ReportGenerator — renders a self-contained dark-theme HTML triage report
using an embedded Jinja2 template.
"""

import os
from datetime import datetime
from typing import Dict, List, Any, Optional

from jinja2 import Environment, BaseLoader

# ---------------------------------------------------------------------------
# Embedded HTML/Jinja2 template
# ---------------------------------------------------------------------------

REPORT_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>VolaTriage Report — {{ metadata.dump_path | basename }}</title>
<style>
/* ===== RESET & BASE ===== */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { font-size: 14px; }
body {
  background: #0d1117;
  color: #c9d1d9;
  font-family: 'Segoe UI', 'Liberation Sans', Arial, sans-serif;
  line-height: 1.6;
  min-height: 100vh;
}
a { color: #58a6ff; text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre, .mono {
  font-family: 'Consolas', 'Cascadia Code', 'Fira Code', monospace;
  font-size: 0.85rem;
}

/* ===== LAYOUT ===== */
.container { max-width: 1600px; margin: 0 auto; padding: 0 1.5rem 3rem; }

/* ===== HEADER ===== */
.header {
  background: linear-gradient(135deg, #161b22 0%, #0d1117 60%, #1a1f2e 100%);
  border-bottom: 1px solid #30363d;
  padding: 1.5rem 2rem;
  position: sticky;
  top: 0;
  z-index: 100;
  box-shadow: 0 2px 16px rgba(0,0,0,0.5);
}
.header-inner {
  max-width: 1600px;
  margin: 0 auto;
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 1rem;
}
.header-title {
  font-size: 1.6rem;
  font-weight: 700;
  color: #58a6ff;
  letter-spacing: -0.5px;
}
.header-title span { color: #c9d1d9; }
.header-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 1.5rem;
  font-size: 0.8rem;
  color: #8b949e;
}
.header-meta .meta-item strong { color: #c9d1d9; }

/* ===== SECTION HEADINGS ===== */
.section { margin-top: 2.5rem; }
.section-title {
  font-size: 1.15rem;
  font-weight: 600;
  color: #c9d1d9;
  padding-bottom: 0.5rem;
  border-bottom: 2px solid #30363d;
  margin-bottom: 1.25rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}
.section-title .icon { font-size: 1.1rem; }

/* ===== SUMMARY CARDS ===== */
.cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
}
.card {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  padding: 1.2rem 1.4rem;
  transition: border-color 0.2s, transform 0.15s;
}
.card:hover { border-color: #58a6ff; transform: translateY(-2px); }
.card-label {
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: #8b949e;
  margin-bottom: 0.4rem;
}
.card-value {
  font-size: 2rem;
  font-weight: 700;
  line-height: 1;
}
.card-sub { font-size: 0.75rem; color: #8b949e; margin-top: 0.3rem; }

/* Card severity colors */
.card-critical  { border-left: 4px solid #ff6b6b; }
.card-high      { border-left: 4px solid #ff8c42; }
.card-medium    { border-left: 4px solid #ffd700; }
.card-low       { border-left: 4px solid #90ee90; }
.card-info      { border-left: 4px solid #58a6ff; }
.card-neutral   { border-left: 4px solid #30363d; }

.val-critical { color: #ff6b6b; }
.val-high     { color: #ff8c42; }
.val-medium   { color: #ffd700; }
.val-low      { color: #90ee90; }
.val-info     { color: #58a6ff; }
.val-clean    { color: #6b7280; }

/* ===== BADGES ===== */
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.5px;
  white-space: nowrap;
}
.badge-CRITICAL { background: #6f0000; color: #ff6b6b; }
.badge-HIGH     { background: #3d1a00; color: #ff8c42; }
.badge-MEDIUM   { background: #2d2000; color: #ffd700; }
.badge-LOW      { background: #1a2800; color: #90ee90; }
.badge-CLEAN    { background: #161b22; color: #6b7280; border: 1px solid #30363d; }
.badge-INFO     { background: #0d2137; color: #58a6ff; }

/* ===== TABLES ===== */
.table-wrap {
  overflow-x: auto;
  border: 1px solid #30363d;
  border-radius: 8px;
}
table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.82rem;
}
thead th {
  background: #161b22;
  color: #8b949e;
  font-weight: 600;
  font-size: 0.72rem;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  padding: 0.6rem 0.9rem;
  text-align: left;
  white-space: nowrap;
  border-bottom: 1px solid #30363d;
  cursor: pointer;
  user-select: none;
  position: relative;
}
thead th:hover { color: #58a6ff; }
thead th.sort-asc::after  { content: " ▲"; color: #58a6ff; }
thead th.sort-desc::after { content: " ▼"; color: #58a6ff; }
tbody tr {
  border-bottom: 1px solid #1c2128;
  transition: background 0.15s;
}
tbody tr:last-child { border-bottom: none; }
tbody tr:hover { background: #1c2128; }
td { padding: 0.55rem 0.9rem; vertical-align: top; }
td.mono { font-family: 'Consolas', monospace; font-size: 0.78rem; }

/* Row severity coloring */
tr.row-CRITICAL { background: rgba(111,0,0,0.15); }
tr.row-HIGH     { background: rgba(61,26,0,0.2); }
tr.row-MEDIUM   { background: rgba(45,32,0,0.2); }
tr.row-LOW      { background: rgba(26,40,0,0.15); }

/* Expandable details */
.expand-row { display: none; }
.expand-row td {
  background: #0d1117;
  padding: 1rem 1.5rem;
  font-size: 0.8rem;
  border-top: 1px dashed #30363d;
}
.expand-row.open { display: table-row; }
.indicator-list { margin: 0; padding-left: 1.2rem; }
.indicator-list li { margin-bottom: 0.2rem; color: #c9d1d9; }

/* ===== FINDINGS ===== */
.finding-group { margin-bottom: 1.2rem; }
.finding-group-title {
  font-size: 0.85rem;
  font-weight: 600;
  color: #8b949e;
  text-transform: uppercase;
  letter-spacing: 0.8px;
  margin-bottom: 0.5rem;
}
.finding-item {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 6px;
  padding: 0.7rem 1rem;
  margin-bottom: 0.5rem;
  font-size: 0.83rem;
  display: flex;
  align-items: flex-start;
  gap: 0.7rem;
}
.finding-item .fi-icon { font-size: 1rem; flex-shrink: 0; margin-top: 0.05rem; }
.finding-item .fi-body { flex: 1; }
.finding-item .fi-desc { color: #c9d1d9; }
.finding-item .fi-meta { color: #8b949e; font-size: 0.75rem; margin-top: 0.2rem; }

.finding-CRITICAL { border-left: 3px solid #ff6b6b; }
.finding-HIGH     { border-left: 3px solid #ff8c42; }
.finding-MEDIUM   { border-left: 3px solid #ffd700; }
.finding-LOW      { border-left: 3px solid #90ee90; }

/* ===== COLLAPSIBLE (details/summary) ===== */
details {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 8px;
  margin-bottom: 0.8rem;
  overflow: hidden;
}
summary {
  padding: 0.8rem 1.2rem;
  cursor: pointer;
  font-weight: 600;
  font-size: 0.88rem;
  color: #c9d1d9;
  list-style: none;
  display: flex;
  align-items: center;
  justify-content: space-between;
  user-select: none;
  border-bottom: 1px solid transparent;
  transition: border-color 0.2s, background 0.2s;
}
summary::-webkit-details-marker { display: none; }
summary::after { content: "▶"; color: #8b949e; font-size: 0.7rem; transition: transform 0.2s; }
details[open] summary { border-bottom-color: #30363d; background: #1c2128; }
details[open] summary::after { transform: rotate(90deg); }
.details-body { padding: 1rem; overflow-x: auto; }

/* ===== NETWORK TABLE ===== */
.external-ip { color: #ff8c42; font-weight: 600; }
.internal-ip { color: #c9d1d9; }

/* ===== SCORE BAR ===== */
.score-bar-wrap { display: flex; align-items: center; gap: 0.6rem; }
.score-bar {
  flex: 1;
  height: 6px;
  background: #1c2128;
  border-radius: 3px;
  overflow: hidden;
  min-width: 60px;
}
.score-fill {
  height: 100%;
  border-radius: 3px;
  transition: width 0.4s ease;
}
.score-num { font-weight: 700; font-size: 0.88rem; min-width: 2.5rem; text-align: right; }

/* ===== TOP SUSPECTS ===== */
.rank-cell { font-weight: 700; color: #8b949e; text-align: center; width: 2.5rem; }
.rank-1 { color: #ffd700; }
.rank-2 { color: #c0c0c0; }
.rank-3 { color: #cd7f32; }

/* ===== EMPTY STATE ===== */
.empty-state {
  text-align: center;
  padding: 2.5rem;
  color: #6b7280;
  font-size: 0.9rem;
}

/* ===== FOOTER ===== */
.footer {
  margin-top: 3rem;
  padding: 1.5rem 2rem;
  border-top: 1px solid #30363d;
  text-align: center;
  font-size: 0.77rem;
  color: #6b7280;
}
.footer a { color: #8b949e; }

/* ===== PREFORMATTED HEX ===== */
.hex-block {
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 4px;
  padding: 0.5rem 0.8rem;
  font-family: monospace;
  font-size: 0.75rem;
  color: #8b949e;
  white-space: pre-wrap;
  word-break: break-all;
  max-height: 120px;
  overflow-y: auto;
}

/* ===== SCROLL HELPER ===== */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d1117; }
::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #8b949e; }

/* ===== UTILITY ===== */
.text-muted { color: #8b949e; }
.text-small { font-size: 0.78rem; }
.mt-1 { margin-top: 0.5rem; }
.mb-1 { margin-bottom: 0.5rem; }
.tag {
  display: inline-block;
  background: #1c2128;
  border: 1px solid #30363d;
  border-radius: 3px;
  padding: 1px 5px;
  font-size: 0.72rem;
  color: #8b949e;
  font-family: monospace;
}
</style>
</head>
<body>

<!-- ===== HEADER ===== -->
<header class="header">
  <div class="header-inner">
    <div class="header-title">🧠 Vola<span>Triage</span></div>
    <div class="header-meta">
      <div class="meta-item">
        <strong>Dump:</strong> {{ metadata.dump_path | basename }}
      </div>
      <div class="meta-item">
        <strong>OS:</strong> {{ metadata.os_detected | upper }}
      </div>
      <div class="meta-item">
        <strong>Size:</strong> {{ metadata.dump_size_mb }} MB
      </div>
      <div class="meta-item">
        <strong>Analyzed:</strong> {{ metadata.analysis_time }}
      </div>
      <div class="meta-item">
        <strong>Version:</strong> {{ metadata.tool_version }}
      </div>
    </div>
  </div>
</header>

<div class="container">

<!-- ===== EXECUTIVE SUMMARY ===== -->
<div class="section">
  <div class="section-title"><span class="icon">📊</span> Executive Summary</div>
  <div class="cards-grid">
    <div class="card card-neutral">
      <div class="card-label">Total Processes</div>
      <div class="card-value val-info">{{ summary.total_processes }}</div>
      <div class="card-sub">From pslist</div>
    </div>
    <div class="card {% if summary.suspicious_count > 0 %}card-high{% else %}card-neutral{% endif %}">
      <div class="card-label">Suspicious</div>
      <div class="card-value {% if summary.suspicious_count > 0 %}val-high{% else %}val-clean{% endif %}">
        {{ summary.suspicious_count }}
      </div>
      <div class="card-sub">Score &gt; 10</div>
    </div>
    <div class="card {% if summary.critical_count > 0 %}card-critical{% else %}card-neutral{% endif %}">
      <div class="card-label">Critical</div>
      <div class="card-value {% if summary.critical_count > 0 %}val-critical{% else %}val-clean{% endif %}">
        {{ summary.critical_count }}
      </div>
      <div class="card-sub">Score &gt; 100</div>
    </div>
    <div class="card {% if summary.network_connections_count > 0 %}card-info{% else %}card-neutral{% endif %}">
      <div class="card-label">Network Connections</div>
      <div class="card-value val-info">{{ summary.network_connections_count }}</div>
      <div class="card-sub">External only</div>
    </div>
    <div class="card {% if summary.injections_count > 0 %}card-critical{% else %}card-neutral{% endif %}">
      <div class="card-label">Code Injections</div>
      <div class="card-value {% if summary.injections_count > 0 %}val-critical{% else %}val-clean{% endif %}">
        {{ summary.injections_count }}
      </div>
      <div class="card-sub">Malfind hits</div>
    </div>
    <div class="card {% if summary.hidden_processes_count > 0 %}card-critical{% else %}card-neutral{% endif %}">
      <div class="card-label">Hidden Processes</div>
      <div class="card-value {% if summary.hidden_processes_count > 0 %}val-critical{% else %}val-clean{% endif %}">
        {{ summary.hidden_processes_count }}
      </div>
      <div class="card-sub">DKOM detected</div>
    </div>
  </div>
</div>

<!-- ===== TOP SUSPECTS ===== -->
<div class="section">
  <div class="section-title"><span class="icon">🎯</span> Top Suspects</div>
  {% if top_suspects %}
  <div class="table-wrap">
    <table id="suspects-table">
      <thead>
        <tr>
          <th class="rank-cell" onclick="sortTable('suspects-table',0)">#</th>
          <th onclick="sortTable('suspects-table',1)">PID</th>
          <th onclick="sortTable('suspects-table',2)">Process Name</th>
          <th onclick="sortTable('suspects-table',3)">Score</th>
          <th onclick="sortTable('suspects-table',4)">Level</th>
          <th>Key Indicators</th>
        </tr>
      </thead>
      <tbody>
        {% for proc in top_suspects %}
        <tr class="row-{{ proc.level }}" onclick="toggleExpand('expand-{{ loop.index }}')" style="cursor:pointer;">
          <td class="rank-cell rank-{{ loop.index }}">{{ loop.index }}</td>
          <td class="mono">{{ proc.pid }}</td>
          <td><strong>{{ proc.name }}</strong></td>
          <td>
            <div class="score-bar-wrap">
              <div class="score-bar">
                <div class="score-fill" style="width:{{ [proc.score, 150] | min / 1.5 | round | int }}%; background:{{ proc.color }};"></div>
              </div>
              <span class="score-num" style="color:{{ proc.color }};">{{ proc.score }}</span>
            </div>
          </td>
          <td><span class="badge badge-{{ proc.level }}">{{ proc.level }}</span></td>
          <td class="text-small text-muted">
            {% if proc.indicators %}
              {{ proc.indicators[0] }}{% if proc.indicators | length > 1 %} <span class="tag">+{{ proc.indicators | length - 1 }} more</span>{% endif %}
            {% else %}
              —
            {% endif %}
          </td>
        </tr>
        <tr class="expand-row" id="expand-{{ loop.index }}">
          <td colspan="6">
            <strong style="color:#58a6ff;">PID {{ proc.pid }} — {{ proc.name }}</strong>
            &nbsp;<span class="badge badge-{{ proc.level }}">{{ proc.level }}</span>
            &nbsp;<span class="text-muted text-small">Score: {{ proc.score }}</span>
            {% if proc.indicators %}
            <ul class="indicator-list mt-1">
              {% for ind in proc.indicators %}
              <li>{{ ind }}</li>
              {% endfor %}
            </ul>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="empty-state">No suspicious processes identified.</div>
  {% endif %}
</div>

<!-- ===== CRITICAL & HIGH FINDINGS ===== -->
<div class="section">
  <div class="section-title"><span class="icon">🔍</span> Critical &amp; High Findings</div>

  {% set finding_groups = [
    ("hidden_processes",    "🔴", "CRITICAL", "Hidden Processes (DKOM)"),
    ("network_injections",  "🔴", "CRITICAL", "Network + Code Injection"),
    ("injections",          "🟠", "HIGH",     "Code Injections (Malfind)"),
    ("suspicious_cmdlines", "🟠", "HIGH",     "Suspicious Command Lines"),
    ("suspicious_services", "🟠", "HIGH",     "Suspicious Services"),
    ("hidden_modules",      "🟠", "HIGH",     "Hidden Modules (LdrModules)"),
    ("suspicious_parents",  "🟠", "HIGH",     "Suspicious Parent–Child"),
    ("suspicious_dlls",     "🟡", "MEDIUM",   "Suspicious DLL Paths"),
    ("privileged_processes","🟡", "MEDIUM",   "Dangerous Privileges"),
  ] %}

  {% set found_any = namespace(value=false) %}
  {% for key, icon, sev, label in finding_groups %}
    {% if correlations[key] %}
      {% set found_any.value = true %}
      <div class="finding-group">
        <div class="finding-group-title">{{ icon }} {{ label }} ({{ correlations[key] | length }})</div>
        {% for f in correlations[key] %}
        <div class="finding-item finding-{{ sev }}">
          <span class="fi-icon">{{ icon }}</span>
          <div class="fi-body">
            <div class="fi-desc">{{ f.description }}</div>
            <div class="fi-meta">
              {% if f.pid is not none %}PID {{ f.pid }}{% endif %}
              {% if f.name %}&nbsp;·&nbsp;{{ f.name }}{% endif %}
              &nbsp;·&nbsp;<span class="badge badge-{{ sev }}">{{ sev }}</span>
            </div>
          </div>
        </div>
        {% endfor %}
      </div>
    {% endif %}
  {% endfor %}

  {% if not found_any.value %}
  <div class="empty-state">✅ No critical or high severity findings.</div>
  {% endif %}
</div>

<!-- ===== NETWORK CONNECTIONS ===== -->
<div class="section">
  <div class="section-title"><span class="icon">🌐</span> Network Connections
    <span class="text-muted text-small" style="font-weight:400;">(external only)</span>
  </div>
  {% if correlations.network_connections %}
  <div class="table-wrap">
    <table id="net-table">
      <thead>
        <tr>
          <th onclick="sortTable('net-table',0)">PID</th>
          <th onclick="sortTable('net-table',1)">Process</th>
          <th onclick="sortTable('net-table',2)">Protocol</th>
          <th onclick="sortTable('net-table',3)">Local Address</th>
          <th onclick="sortTable('net-table',4)">Local Port</th>
          <th onclick="sortTable('net-table',5)">Foreign Address</th>
          <th onclick="sortTable('net-table',6)">Foreign Port</th>
          <th onclick="sortTable('net-table',7)">State</th>
        </tr>
      </thead>
      <tbody>
        {% for conn in correlations.network_connections %}
        <tr>
          <td class="mono">{{ conn.pid }}</td>
          <td>{{ conn.name }}</td>
          <td><span class="tag">{{ conn.protocol }}</span></td>
          <td class="mono internal-ip">{{ conn.local_addr }}</td>
          <td class="mono">{{ conn.local_port }}</td>
          <td class="mono external-ip">{{ conn.foreign_addr }}</td>
          <td class="mono">{{ conn.foreign_port }}</td>
          <td><span class="tag">{{ conn.state }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="empty-state">No external network connections found.</div>
  {% endif %}
</div>

<!-- ===== CODE INJECTIONS ===== -->
<div class="section">
  <div class="section-title"><span class="icon">💉</span> Code Injections (Malfind)</div>
  {% if correlations.injections %}
  <div class="table-wrap">
    <table id="inj-table">
      <thead>
        <tr>
          <th onclick="sortTable('inj-table',0)">PID</th>
          <th onclick="sortTable('inj-table',1)">Process</th>
          <th onclick="sortTable('inj-table',2)">Virtual Address</th>
          <th onclick="sortTable('inj-table',3)">Protection</th>
          <th>Hex / Disasm Preview</th>
        </tr>
      </thead>
      <tbody>
        {% for inj in correlations.injections %}
        <tr class="row-HIGH">
          <td class="mono">{{ inj.pid }}</td>
          <td><strong>{{ inj.name }}</strong></td>
          <td class="mono">{{ inj.virtual_address }}</td>
          <td><span class="tag">{{ inj.protection }}</span></td>
          <td>
            {% if inj.hex_preview %}
            <div class="hex-block">{{ inj.hex_preview }}</div>
            {% else %}
            <span class="text-muted">—</span>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="empty-state">No malfind injections detected.</div>
  {% endif %}
</div>

<!-- ===== ALL PROCESSES ===== -->
<div class="section">
  <div class="section-title"><span class="icon">⚙️</span> All Processes</div>
  {% set sorted_procs = all_processes | sort(attribute='score', reverse=True) %}
  {% if sorted_procs %}
  <div class="table-wrap">
    <table id="all-procs-table">
      <thead>
        <tr>
          <th onclick="sortTable('all-procs-table',0)">PID</th>
          <th onclick="sortTable('all-procs-table',1)">Name</th>
          <th onclick="sortTable('all-procs-table',2)">Score</th>
          <th onclick="sortTable('all-procs-table',3)">Level</th>
          <th>Indicators</th>
        </tr>
      </thead>
      <tbody>
        {% for proc in sorted_procs %}
        <tr class="row-{{ proc.level }}">
          <td class="mono">{{ proc.pid }}</td>
          <td>{{ proc.name }}</td>
          <td>
            <div class="score-bar-wrap">
              <div class="score-bar">
                <div class="score-fill" style="width:{{ [proc.score, 150] | min / 1.5 | round | int }}%; background:{{ proc.color }};"></div>
              </div>
              <span class="score-num" style="color:{{ proc.color }};">{{ proc.score }}</span>
            </div>
          </td>
          <td><span class="badge badge-{{ proc.level }}">{{ proc.level }}</span></td>
          <td class="text-small text-muted">
            {% if proc.indicators %}
              {{ proc.indicators | join(' · ') | truncate(120) }}
            {% else %}—{% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="empty-state">No process data available.</div>
  {% endif %}
</div>

<!-- ===== RAW PLUGIN DATA ===== -->
<div class="section">
  <div class="section-title"><span class="icon">🗂️</span> Raw Plugin Data</div>

  {% for plugin_name, plugin_label in [
      ("pslist",  "Process List (pslist)"),
      ("psscan",  "Process Scan (psscan)"),
      ("modules", "Kernel Modules (modules)"),
      ("svcscan", "Services (svcscan)"),
      ("netscan", "Network Scan (netscan)"),
      ("cmdline", "Command Lines (cmdline)"),
  ] %}
  {% if results.get(plugin_name) %}
  <details>
    <summary>
      {{ plugin_label }}
      <span class="text-muted text-small" style="font-weight:400;">{{ results[plugin_name] | length }} rows</span>
    </summary>
    <div class="details-body">
      {% set plugin_rows = results[plugin_name] %}
      {% if plugin_rows %}
        {% set cols = plugin_rows[0].keys() | list %}
        <div class="table-wrap">
          <table id="raw-{{ plugin_name }}">
            <thead>
              <tr>
                {% for col in cols %}
                <th onclick="sortTable('raw-{{ plugin_name }}', {{ loop.index0 }})">{{ col }}</th>
                {% endfor %}
              </tr>
            </thead>
            <tbody>
              {% for row in plugin_rows %}
              <tr>
                {% for col in cols %}
                <td class="mono">{{ row.get(col, '') }}</td>
                {% endfor %}
              </tr>
              {% endfor %}
            </tbody>
          </table>
        </div>
      {% else %}
        <div class="empty-state">No data.</div>
      {% endif %}
    </div>
  </details>
  {% endif %}
  {% endfor %}
</div>

<!-- ===== FOOTER ===== -->
<div class="footer">
  Generated by <strong>VolaTriage {{ metadata.tool_version }}</strong>
  on {{ metadata.analysis_time }}
  &nbsp;·&nbsp;
  IOC file: <code>{{ ioc_path }}</code>
  &nbsp;·&nbsp;
  Dump: <code>{{ metadata.dump_path }}</code>
</div>

</div><!-- /container -->

<!-- ===== JAVASCRIPT ===== -->
<script>
// ---- Table sorting ----
var sortState = {};
function sortTable(tableId, colIdx) {
  var tbl = document.getElementById(tableId);
  if (!tbl) return;
  var key = tableId + ':' + colIdx;
  var asc = sortState[key] !== true;
  sortState[key] = asc;

  // Update header classes
  var ths = tbl.querySelectorAll('thead th');
  ths.forEach(function(th, i) {
    th.classList.remove('sort-asc', 'sort-desc');
    if (i === colIdx) th.classList.add(asc ? 'sort-asc' : 'sort-desc');
  });

  var tbody = tbl.querySelector('tbody');
  var rows = Array.from(tbody.querySelectorAll('tr:not(.expand-row)'));
  rows.sort(function(a, b) {
    var aCell = a.querySelectorAll('td')[colIdx];
    var bCell = b.querySelectorAll('td')[colIdx];
    if (!aCell || !bCell) return 0;
    var aVal = aCell.textContent.trim();
    var bVal = bCell.textContent.trim();
    var aNum = parseFloat(aVal);
    var bNum = parseFloat(bVal);
    if (!isNaN(aNum) && !isNaN(bNum)) {
      return asc ? aNum - bNum : bNum - aNum;
    }
    return asc ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
  });
  rows.forEach(function(row) { tbody.appendChild(row); });
}

// ---- Expandable rows ----
function toggleExpand(id) {
  var el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle('open');
}

// ---- Animate score bars on load ----
document.addEventListener('DOMContentLoaded', function() {
  var fills = document.querySelectorAll('.score-fill');
  fills.forEach(function(el) {
    var target = el.style.width;
    el.style.width = '0%';
    setTimeout(function() { el.style.width = target; }, 50);
  });
});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Jinja2 filter: basename
# ---------------------------------------------------------------------------

def _basename_filter(path: str) -> str:
    return os.path.basename(str(path)) if path else ""


class ReportGenerator:
    def __init__(
        self,
        dump_path: str,
        results: Dict[str, List[Dict]],
        correlations: Dict[str, Any],
        scores: Dict[int, Dict],
        os_detected: str = "unknown",
        dump_size_mb: float = 0.0,
        tool_version: str = "1.0.0",
        ioc_path: str = "",
    ):
        self.dump_path = dump_path
        self.results = results
        self.correlations = correlations
        self.scores = scores
        self.os_detected = os_detected
        self.dump_size_mb = dump_size_mb
        self.tool_version = tool_version
        self.ioc_path = ioc_path

        # Set up Jinja2 environment with the embedded template string
        self._env = Environment(loader=BaseLoader(), autoescape=False)
        self._env.filters["basename"] = _basename_filter
        self._env.globals["min"] = min
        # Allow dict .get() in templates
        self._env.globals["results"] = results
        self._template = self._env.from_string(REPORT_TEMPLATE)

    def _build_summary(self) -> Dict[str, Any]:
        """Build the summary dict passed to the template."""
        total = len(self.scores)
        suspicious = sum(1 for d in self.scores.values() if d.get("score", 0) > 10)
        critical = sum(1 for d in self.scores.values() if d.get("level") == "CRITICAL")
        high = sum(1 for d in self.scores.values() if d.get("level") == "HIGH")
        medium = sum(1 for d in self.scores.values() if d.get("level") == "MEDIUM")
        low = sum(1 for d in self.scores.values() if d.get("level") == "LOW")

        net_conns = len(self.correlations.get("network_connections", []))
        injections = len(self.correlations.get("injections", []))
        hidden = len(self.correlations.get("hidden_processes", []))

        return {
            "total_processes": total,
            "suspicious_count": suspicious,
            "critical_count": critical,
            "high_count": high,
            "medium_count": medium,
            "low_count": low,
            "network_connections_count": net_conns,
            "injections_count": injections,
            "hidden_processes_count": hidden,
        }

    def _build_top_suspects(self, n: int = 15) -> List[Dict]:
        suspects = [d for d in self.scores.values() if d.get("score", 0) > 0]
        suspects.sort(key=lambda x: x.get("score", 0), reverse=True)
        return suspects[:n]

    def _build_all_processes(self) -> List[Dict]:
        procs = list(self.scores.values())
        procs.sort(key=lambda x: x.get("score", 0), reverse=True)
        return procs

    def generate(self, output_dir: str) -> str:
        """
        Render the report and write it to output_dir.
        Returns the path to the generated HTML file.
        """
        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"volatriage_report_{timestamp}.html"
        output_path = os.path.join(output_dir, filename)

        metadata = {
            "dump_path": self.dump_path,
            "os_detected": self.os_detected,
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "dump_size_mb": f"{self.dump_size_mb:.1f}",
            "tool_version": self.tool_version,
        }

        context = {
            "metadata": metadata,
            "summary": self._build_summary(),
            "top_suspects": self._build_top_suspects(),
            "all_processes": self._build_all_processes(),
            "correlations": self.correlations,
            "results": self.results,
            "ioc_path": self.ioc_path,
        }

        rendered = self._template.render(**context)

        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(rendered)

        return output_path
