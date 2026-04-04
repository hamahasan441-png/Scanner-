#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v8.0 - ULTIMATE EDITION
Report generation module
"""

import os
import json
import re
from datetime import datetime, timezone


from config import Config, Colors


class ReportGenerator:
    """Report generator for scan results"""

    # Only allow safe characters in scan IDs used for filenames
    _SAFE_ID = re.compile(r'^[a-zA-Z0-9_-]+$')

    def __init__(self, scan_id, findings=None, target=None, start_time=None, end_time=None, total_requests=0, output_dir=None,
                 exploit_chains=None, shield_profile=None, origin_result=None, agent_result=None):
        # Sanitize scan_id to prevent path traversal in report filenames
        if not self._SAFE_ID.match(scan_id or ''):
            scan_id = re.sub(r'[^a-zA-Z0-9_-]', '_', scan_id or 'unknown')
        self.scan_id = scan_id
        self.findings = findings or []
        self.target = target or ''
        self.start_time = start_time
        self.end_time = end_time
        self.total_requests = total_requests
        self.output_dir = output_dir or Config.REPORTS_DIR
        os.makedirs(self.output_dir, exist_ok=True)

        # Phase 10 enrichment data
        self.exploit_chains = exploit_chains or []
        self.shield_profile = shield_profile or {}
        self.origin_result = origin_result or {}
        self.agent_result = agent_result or {}

        # If no findings provided, try to load from database
        if not self.findings:
            self._load_from_db()

    def _load_from_db(self):
        """Load scan data from database"""
        try:
            from utils.database import Database, ScanModel, FindingModel, SQLALCHEMY_AVAILABLE
            if not SQLALCHEMY_AVAILABLE:
                return

            from sqlalchemy import create_engine
            from sqlalchemy.orm import sessionmaker

            engine = create_engine(Config.DB_URL)
            Session = sessionmaker(bind=engine)
            session = Session()

            scan = session.query(ScanModel).filter_by(scan_id=self.scan_id).first()
            if scan:
                self.target = scan.target
                self.start_time = scan.start_time
                self.end_time = scan.end_time

            db_findings = session.query(FindingModel).filter_by(scan_id=self.scan_id).all()
            for f in db_findings:
                self.findings.append({
                    'technique': f.technique,
                    'url': f.url,
                    'param': f.param,
                    'payload': f.payload,
                    'evidence': f.evidence,
                    'severity': f.severity,
                    'confidence': f.confidence,
                    'mitre_id': f.mitre_id,
                    'cwe_id': f.cwe_id,
                    'cvss': f.cvss,
                })

            session.close()
        except Exception as e:
            print(f"{Colors.error(f'Could not load scan data: {e}')}")

    def generate(self, fmt='html'):
        """Generate report in specified format. Returns the filepath or None."""
        generators = {
            'html': self._generate_html,
            'json': self._generate_json,
            'csv': self._generate_csv,
            'txt': self._generate_txt,
            'pdf': self._generate_pdf,
            'xml': self._generate_xml,
            'sarif': self._generate_sarif,
        }

        generator = generators.get(fmt)
        if generator:
            filepath = generator()
            if filepath:
                print(f"{Colors.success(f'Report generated: {filepath}')}")
            return filepath
        else:
            print(f"{Colors.error(f'Unsupported format: {fmt}')}")
            return None

    def generate_all(self):
        """Generate reports in all formats"""
        for fmt in ['html', 'json', 'csv', 'txt', 'pdf', 'xml', 'sarif']:
            self.generate(fmt)

    def _get_findings_data(self):
        """Get findings as list of dicts"""
        data = []
        for f in self.findings:
            if isinstance(f, dict):
                data.append(f)
            else:
                data.append({
                    'technique': getattr(f, 'technique', ''),
                    'url': getattr(f, 'url', ''),
                    'param': getattr(f, 'param', ''),
                    'payload': getattr(f, 'payload', ''),
                    'evidence': getattr(f, 'evidence', ''),
                    'severity': getattr(f, 'severity', 'INFO'),
                    'confidence': getattr(f, 'confidence', 0.0),
                    'mitre_id': getattr(f, 'mitre_id', ''),
                    'cwe_id': getattr(f, 'cwe_id', ''),
                    'cvss': getattr(f, 'cvss', 0.0),
                    'signals': getattr(f, 'signals', {}),
                    'priority': getattr(f, 'priority', 0.0),
                    'remediation': getattr(f, 'remediation', ''),
                })
        return data

    @staticmethod
    def _format_signals(signals):
        """Format a signals dict as a compact string."""
        if not signals:
            return ''
        return '; '.join(f'{k}={v}' for k, v in signals.items())

    @staticmethod
    def _pdf_safe(text):
        """Replace Unicode characters that Helvetica can't render."""
        return str(text).replace('\u2192', '->').replace('\u2190', '<-').replace('\u2194', '<->')

    # ------------------------------------------------------------------
    # Phase 10 enrichment helpers
    # ------------------------------------------------------------------

    def _severity_counts(self):
        """Return {severity: count} from findings."""
        counts = {}
        for f in self._get_findings_data():
            sev = f.get('severity', 'INFO')
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _top_critical_risks(self, n=3):
        """Return top-N findings sorted by CVSS DESC."""
        data = self._get_findings_data()
        data.sort(key=lambda f: f.get('cvss', 0), reverse=True)
        return data[:n]

    def _get_chains_data(self):
        """Get exploit chains as list of dicts."""
        result = []
        for chain in self.exploit_chains:
            if isinstance(chain, dict):
                result.append(chain)
            else:
                result.append({
                    'id': getattr(chain, 'id', ''),
                    'name': getattr(chain, 'name', ''),
                    'steps': getattr(chain, 'steps', []),
                    'combined_cvss': getattr(chain, 'combined_cvss', 0.0),
                    'combined_severity': getattr(chain, 'combined_severity', ''),
                    'finding_count': len(getattr(chain, 'findings', [])),
                })
        return result

    def _waf_bypass_info(self):
        """Extract WAF bypass disclosure from shield profile and findings."""
        info = {}
        waf = self.shield_profile.get('waf', {})
        if waf.get('detected'):
            info['waf_detected'] = True
            info['waf_provider'] = waf.get('provider', 'Unknown')
        bypasses = []
        for f in self._get_findings_data():
            signals = f.get('signals', {})
            waf_flag = signals.get('waf_flag', '')
            if waf_flag == 'WAF_BYPASSED_CONFIRMED':
                bypasses.append({
                    'technique': f.get('technique', ''),
                    'url': f.get('url', ''),
                    'payload': f.get('payload', '')[:120],
                })
        info['bypasses'] = bypasses
        return info

    def _origin_exposure_info(self):
        """Extract origin exposure from origin result."""
        info = {}
        if self.origin_result:
            info['origin_ip'] = self.origin_result.get('origin_ip')
            info['confidence'] = self.origin_result.get('confidence', 0)
            info['method'] = self.origin_result.get('method', '')
        cdn = self.shield_profile.get('cdn', {})
        if cdn.get('detected'):
            info['cdn_provider'] = cdn.get('provider', 'Unknown')
            info['cdn_misconfigured'] = self.shield_profile.get('needs_origin_discovery', False)
        return info

    def _agent_reasoning_log(self):
        """Extract agent reasoning log from agent result."""
        if not self.agent_result:
            return []
        log = []
        for goal in self.agent_result.get('goals_completed', []):
            log.append({
                'type': 'goal_completed',
                'description': goal if isinstance(goal, str) else str(goal),
            })
        for pivot in self.agent_result.get('pivots_found', []):
            log.append({
                'type': 'pivot',
                'description': pivot if isinstance(pivot, str) else str(pivot),
            })
        return log

    def _remediation_plan(self):
        """Build prioritized remediation plan from findings."""
        data = self._get_findings_data()
        data.sort(key=lambda f: f.get('cvss', 0), reverse=True)
        plan = []
        seen = set()
        for f in data:
            rem = f.get('remediation', '')
            if not rem:
                continue
            key = f"{f.get('technique', '')}:{rem[:40]}"
            if key in seen:
                continue
            seen.add(key)
            plan.append({
                'technique': f.get('technique', ''),
                'severity': f.get('severity', 'INFO'),
                'cvss': f.get('cvss', 0),
                'remediation': rem,
            })
        return plan

    def _generate_json(self):
        """Generate JSON report with Phase 10 enrichment."""
        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.json')

        report = {
            'scan_id': self.scan_id,
            'target': self.target,
            'start_time': str(self.start_time) if self.start_time else None,
            'end_time': str(self.end_time) if self.end_time else None,
            'total_requests': self.total_requests,
            'total_findings': len(self.findings),
            'executive_summary': {
                'severity_counts': self._severity_counts(),
                'top_critical_risks': [
                    {'technique': r.get('technique', ''), 'cvss': r.get('cvss', 0), 'url': r.get('url', '')}
                    for r in self._top_critical_risks()
                ],
                'origin_exposure': self._origin_exposure_info(),
            },
            'findings': self._get_findings_data(),
            'exploit_chains': self._get_chains_data(),
            'waf_bypass_disclosure': self._waf_bypass_info(),
            'origin_exposure_note': self._origin_exposure_info(),
            'remediation_plan': self._remediation_plan(),
            'agent_reasoning_log': self._agent_reasoning_log(),
        }

        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath

    def _generate_html(self):
        """Generate HTML report with Phase 10 enrichment sections."""
        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.html')
        findings_data = self._get_findings_data()

        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#e74c3c',
            'MEDIUM': '#f39c12',
            'LOW': '#3498db',
            'INFO': '#6c757d',
        }

        # ── Executive summary cards ──
        sev_counts = self._severity_counts()
        sev_cards = ''
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            cnt = sev_counts.get(sev, 0)
            if cnt:
                color = severity_colors.get(sev, '#6c757d')
                sev_cards += f'<div class="summary-card"><h3 style="color:{color}">{cnt}</h3><p>{sev}</p></div>'

        top_risks_html = ''
        for r in self._top_critical_risks():
            top_risks_html += f"<li><strong>{r.get('technique','')}</strong> (CVSS {r.get('cvss',0)}) — {r.get('url','')[:80]}</li>"

        origin_info = self._origin_exposure_info()
        origin_html = ''
        if origin_info.get('origin_ip'):
            origin_html = f"""<p><span style="color:#e94560">⚠ Origin IP exposed:</span> {origin_info['origin_ip']}
            (confidence: {origin_info.get('confidence', 0):.0%}, method: {origin_info.get('method', '')})</p>"""
        if origin_info.get('cdn_provider'):
            origin_html += f"<p>CDN provider: {origin_info['cdn_provider']}"
            if origin_info.get('cdn_misconfigured'):
                origin_html += ' <span style="color:#f39c12">(misconfigured)</span>'
            origin_html += '</p>'

        # ── Findings table rows ──
        findings_html = ''
        for f in findings_data:
            color = severity_colors.get(f.get('severity', 'INFO'), '#6c757d')
            signals = f.get('signals', {})
            signals_html = ''
            if signals:
                signals_html = (
                    f"T:{signals.get('timing', 0):.1f} "
                    f"E:{signals.get('error', 0):.1f} "
                    f"R:{signals.get('reflection', 0):.1f} "
                    f"D:{signals.get('diff', 0):.1f}"
                )
            remediation = f.get('remediation', '')
            findings_html += f"""
            <tr>
                <td><span style="color:{color};font-weight:bold">{f.get('severity', 'INFO')}</span></td>
                <td>{f.get('technique', '')}</td>
                <td style="word-break:break-all">{f.get('url', '')}</td>
                <td>{f.get('param', '')}</td>
                <td><code>{f.get('payload', '')[:80]}</code></td>
                <td>{f.get('evidence', '')[:100]}</td>
                <td>{f.get('confidence', 0):.0%}</td>
                <td style="font-size:11px">{signals_html}</td>
                <td style="font-size:11px">{remediation[:120]}</td>
            </tr>"""

        # ── Exploit chains section ──
        chains_html = ''
        chains_data = self._get_chains_data()
        if chains_data:
            chains_html = '<h2>Exploit Chains</h2>'
            for ch in chains_data:
                ch_color = severity_colors.get(ch.get('combined_severity', 'HIGH'), '#e74c3c')
                steps = ' → '.join(ch.get('steps', []))
                chains_html += f"""
                <div style="background:#16213e;padding:12px;border-radius:6px;margin:8px 0;border-left:4px solid {ch_color}">
                    <strong style="color:{ch_color}">[{ch.get('id','')}] {ch.get('name','')}</strong>
                    <span style="color:#aaa;margin-left:10px">CVSS {ch.get('combined_cvss',0)}</span>
                    <p style="margin:4px 0 0;color:#ccc">Steps: {steps}</p>
                </div>"""

        # ── WAF bypass disclosure ──
        waf_html = ''
        waf_info = self._waf_bypass_info()
        if waf_info.get('waf_detected'):
            waf_html = f'<h2>WAF Bypass Disclosure</h2><p>WAF detected: <strong>{waf_info.get("waf_provider", "Unknown")}</strong></p>'
            if waf_info.get('bypasses'):
                waf_html += '<ul>'
                for bp in waf_info['bypasses']:
                    waf_html += f"<li>{bp.get('technique','')} — <code>{bp.get('payload','')[:80]}</code></li>"
                waf_html += '</ul>'
            else:
                waf_html += '<p style="color:#aaa">No confirmed WAF bypasses.</p>'

        # ── Remediation plan ──
        rem_html = ''
        rem_plan = self._remediation_plan()
        if rem_plan:
            rem_html = '<h2>Remediation Plan</h2><ol>'
            for item in rem_plan:
                color = severity_colors.get(item.get('severity', 'INFO'), '#6c757d')
                rem_html += f'<li><span style="color:{color}">[{item["severity"]}]</span> <strong>{item["technique"]}</strong> — {item["remediation"]}</li>'
            rem_html += '</ol>'

        # ── Agent reasoning log ──
        agent_html = ''
        agent_log = self._agent_reasoning_log()
        if agent_log:
            agent_html = '<h2>Agent Reasoning Log</h2><ul>'
            for entry in agent_log:
                icon = '✓' if entry['type'] == 'goal_completed' else '↗'
                agent_html += f'<li>{icon} [{entry["type"]}] {entry["description"]}</li>'
            agent_html += '</ul>'

        duration = ''
        if self.start_time and self.end_time:
            duration = f"{(self.end_time - self.start_time).total_seconds():.1f}s"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>ATOMIC Framework - Scan Report {self.scan_id}</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #e94560; }}
        h2 {{ color: #0f3460; background: #16213e; padding: 10px; border-radius: 5px; color: #eee; }}
        table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
        th {{ background: #16213e; color: #eee; padding: 10px; text-align: left; }}
        td {{ padding: 8px; border-bottom: 1px solid #333; }}
        tr:hover {{ background: #16213e; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; flex-wrap: wrap; }}
        .summary-card {{ background: #16213e; padding: 15px; border-radius: 8px; flex: 1; text-align: center; min-width: 100px; }}
        .summary-card h3 {{ margin: 0; color: #e94560; font-size: 24px; }}
        .summary-card p {{ margin: 5px 0 0; color: #aaa; }}
        code {{ background: #333; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
        ol, ul {{ color: #ccc; }}
    </style>
</head>
<body>
    <h1>ATOMIC Framework v{Config.VERSION} - Scan Report</h1>

    <h2>Executive Summary</h2>
    <div class="summary">
        <div class="summary-card"><h3>{self.scan_id}</h3><p>Scan ID</p></div>
        <div class="summary-card"><h3>{len(self.findings)}</h3><p>Findings</p></div>
        <div class="summary-card"><h3>{self.total_requests}</h3><p>Requests</p></div>
        <div class="summary-card"><h3>{duration}</h3><p>Duration</p></div>
        {sev_cards}
    </div>

    <p><strong>Target:</strong> {self.target}</p>
    <p><strong>Start:</strong> {self.start_time}</p>
    <p><strong>End:</strong> {self.end_time}</p>

    {f'<h3>Top Critical Risks</h3><ol>{top_risks_html}</ol>' if top_risks_html else ''}
    {origin_html}

    <h2>Finding Table ({len(self.findings)})</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Technique</th>
            <th>URL</th>
            <th>Parameter</th>
            <th>Payload</th>
            <th>Evidence</th>
            <th>Confidence</th>
            <th>Signals</th>
            <th>Remediation</th>
        </tr>
        {findings_html}
    </table>

    {chains_html}
    {waf_html}
    {rem_html}
    {agent_html}

    <p style="color:#666;margin-top:30px;text-align:center">
        Generated by ATOMIC Framework v{Config.VERSION} | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}
    </p>
</body>
</html>"""

        try:
            with open(filepath, 'w') as f:
                f.write(html)
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath

    def _generate_csv(self):
        """Generate CSV report"""
        import csv

        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.csv')
        findings_data = self._get_findings_data()

        try:
            with open(filepath, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'Severity', 'Technique', 'URL', 'Parameter', 'Payload',
                    'Evidence', 'MITRE ID', 'CWE ID', 'CVSS', 'Confidence',
                    'Signals', 'Priority', 'Remediation',
                ])

                for finding in findings_data:
                    signals_str = self._format_signals(finding.get('signals', {}))
                    writer.writerow([
                        finding.get('severity', ''),
                        finding.get('technique', ''),
                        finding.get('url', ''),
                        finding.get('param', ''),
                        finding.get('payload', ''),
                        finding.get('evidence', ''),
                        finding.get('mitre_id', ''),
                        finding.get('cwe_id', ''),
                        finding.get('cvss', ''),
                        finding.get('confidence', ''),
                        signals_str,
                        finding.get('priority', ''),
                        finding.get('remediation', ''),
                    ])
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath

    def _generate_txt(self):
        """Generate text report with Phase 10 enrichment."""
        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.txt')
        findings_data = self._get_findings_data()

        duration = ''
        if self.start_time and self.end_time:
            duration = f"{(self.end_time - self.start_time).total_seconds():.1f}s"

        lines = [
            f"ATOMIC Framework v{Config.VERSION} - Scan Report",
            "=" * 60,
            f"Scan ID:    {self.scan_id}",
            f"Target:     {self.target}",
            f"Start:      {self.start_time}",
            f"End:        {self.end_time}",
            f"Duration:   {duration}",
            f"Requests:   {self.total_requests}",
            f"Findings:   {len(self.findings)}",
            "",
            "EXECUTIVE SUMMARY",
            "=" * 60,
        ]

        sev_counts = self._severity_counts()
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            cnt = sev_counts.get(sev, 0)
            if cnt:
                lines.append(f"  {sev}: {cnt}")

        top_risks = self._top_critical_risks()
        if top_risks:
            lines.append("")
            lines.append("Top Critical Risks:")
            for i, r in enumerate(top_risks, 1):
                lines.append(f"  {i}. {r.get('technique','')} (CVSS {r.get('cvss',0)}) — {r.get('url','')[:60]}")

        origin = self._origin_exposure_info()
        if origin.get('origin_ip'):
            lines.append("")
            lines.append(f"Origin Exposure: IP {origin['origin_ip']} (confidence: {origin.get('confidence',0):.0%})")

        lines.extend(["", "FINDINGS", "=" * 60])

        for i, f in enumerate(findings_data, 1):
            lines.append(f"\n[{i}] {f.get('severity', 'INFO')} - {f.get('technique', '')}")
            lines.append(f"    URL:      {f.get('url', '')}")
            if f.get('param'):
                lines.append(f"    Param:    {f.get('param', '')}")
            if f.get('payload'):
                lines.append(f"    Payload:  {f.get('payload', '')[:80]}")
            if f.get('evidence'):
                lines.append(f"    Evidence: {f.get('evidence', '')[:100]}")
            if f.get('confidence'):
                lines.append(f"    Confidence: {f.get('confidence', 0):.0%}")
            signals = f.get('signals', {})
            if signals:
                lines.append(f"    Signals:  {self._format_signals(signals)}")
            if f.get('mitre_id'):
                lines.append(f"    MITRE:    {f.get('mitre_id', '')}")
            if f.get('cwe_id'):
                lines.append(f"    CWE:      {f.get('cwe_id', '')}")
            if f.get('remediation'):
                lines.append(f"    Fix:      {f.get('remediation', '')}")

        # Exploit chains
        chains_data = self._get_chains_data()
        if chains_data:
            lines.extend(["", "EXPLOIT CHAINS", "=" * 60])
            for ch in chains_data:
                steps = ' -> '.join(ch.get('steps', []))
                lines.append(f"  [{ch.get('id','')}] {ch.get('name','')} (CVSS {ch.get('combined_cvss',0)})")
                lines.append(f"    Steps: {steps}")

        # WAF bypass
        waf_info = self._waf_bypass_info()
        if waf_info.get('waf_detected'):
            lines.extend(["", "WAF BYPASS DISCLOSURE", "=" * 60])
            lines.append(f"  WAF: {waf_info.get('waf_provider', 'Unknown')}")
            for bp in waf_info.get('bypasses', []):
                lines.append(f"  Bypass: {bp.get('technique','')} — {bp.get('payload','')[:60]}")

        # Remediation plan
        rem_plan = self._remediation_plan()
        if rem_plan:
            lines.extend(["", "REMEDIATION PLAN", "=" * 60])
            for i, item in enumerate(rem_plan, 1):
                lines.append(f"  {i}. [{item['severity']}] {item['technique']}: {item['remediation']}")

        # Agent reasoning
        agent_log = self._agent_reasoning_log()
        if agent_log:
            lines.extend(["", "AGENT REASONING LOG", "=" * 60])
            for entry in agent_log:
                lines.append(f"  [{entry['type']}] {entry['description']}")

        try:
            with open(filepath, 'w') as f:
                f.write('\n'.join(lines))
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath

    def _generate_pdf(self):
        """Generate PDF report with Phase 10 sections using fpdf2."""
        try:
            from fpdf import FPDF
        except ImportError:
            print(f"{Colors.error('fpdf2 not installed — cannot generate PDF report')}")
            return None

        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.pdf')
        findings_data = self._get_findings_data()

        duration = ''
        if self.start_time and self.end_time:
            duration = f"{(self.end_time - self.start_time).total_seconds():.1f}s"

        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        pdf.add_page()

        NL = dict(new_x='LMARGIN', new_y='NEXT')

        # Title
        pdf.set_font('Helvetica', 'B', 16)
        pdf.cell(0, 10, f'ATOMIC Framework v{Config.VERSION} - Scan Report', **NL)
        pdf.ln(5)

        # Executive Summary
        pdf.set_font('Helvetica', 'B', 13)
        pdf.cell(0, 10, 'Executive Summary', **NL)
        pdf.set_font('Helvetica', '', 11)
        pdf.cell(0, 7, f'Scan ID: {self.scan_id}', **NL)
        pdf.cell(0, 7, f'Target: {self.target}', **NL)
        pdf.cell(0, 7, f'Duration: {duration} | Requests: {self.total_requests}', **NL)

        sev_counts = self._severity_counts()
        sev_line = ', '.join(f'{s}: {c}' for s, c in sev_counts.items() if c)
        if sev_line:
            pdf.cell(0, 7, f'Findings by severity: {sev_line}', **NL)

        origin = self._origin_exposure_info()
        if origin.get('origin_ip'):
            pdf.cell(0, 7, f'Origin IP: {origin["origin_ip"]} (confidence: {origin.get("confidence",0):.0%})', **NL)
        pdf.ln(5)

        # Findings
        pdf.set_font('Helvetica', 'B', 13)
        pdf.cell(0, 10, f'Findings ({len(findings_data)})', **NL)
        pdf.set_font('Helvetica', '', 10)

        for i, f in enumerate(findings_data, 1):
            pdf.set_font('Helvetica', 'B', 10)
            pdf.cell(0, 7, f"[{i}] {f.get('severity', 'INFO')} - {f.get('technique', '')}", **NL)
            pdf.set_font('Helvetica', '', 9)
            pdf.cell(0, 6, f"  URL: {f.get('url', '')[:120]}", **NL)
            if f.get('param'):
                pdf.cell(0, 6, f"  Param: {f.get('param', '')}", **NL)
            if f.get('payload'):
                pdf.cell(0, 6, f"  Payload: {f.get('payload', '')[:100]}", **NL)
            if f.get('evidence'):
                pdf.cell(0, 6, f"  Evidence: {f.get('evidence', '')[:100]}", **NL)
            if f.get('remediation'):
                pdf.cell(0, 6, f"  Fix: {f.get('remediation', '')[:120]}", **NL)
            pdf.ln(2)

        # Exploit chains
        chains_data = self._get_chains_data()
        if chains_data:
            pdf.set_font('Helvetica', 'B', 13)
            pdf.cell(0, 10, 'Exploit Chains', **NL)
            pdf.set_font('Helvetica', '', 10)
            for chain in chains_data:
                steps = ' -> '.join(chain.get('steps', []))
                pdf.cell(0, 7, self._pdf_safe(f"[{chain.get('id','')}] {chain.get('name','')} (CVSS {chain.get('combined_cvss',0)})"), **NL)
                pdf.cell(0, 6, f"  Steps: {steps}", **NL)
                pdf.ln(2)

        # Remediation plan
        rem_plan = self._remediation_plan()
        if rem_plan:
            pdf.set_font('Helvetica', 'B', 13)
            pdf.cell(0, 10, 'Remediation Plan', **NL)
            pdf.set_font('Helvetica', '', 9)
            for i, item in enumerate(rem_plan, 1):
                pdf.cell(0, 6, f"{i}. [{item['severity']}] {item['technique']}: {item['remediation'][:100]}", **NL)

        try:
            pdf.output(filepath)
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath

    def _generate_xml(self):
        """Generate XML report."""
        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.xml')
        findings_data = self._get_findings_data()

        duration = ''
        if self.start_time and self.end_time:
            duration = f"{(self.end_time - self.start_time).total_seconds():.1f}s"

        from xml.sax.saxutils import escape as xml_escape

        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            '<atomic-report>',
            '  <scan>',
            f'    <scan-id>{xml_escape(str(self.scan_id))}</scan-id>',
            f'    <target>{xml_escape(str(self.target))}</target>',
            f'    <start-time>{xml_escape(str(self.start_time))}</start-time>',
            f'    <end-time>{xml_escape(str(self.end_time))}</end-time>',
            f'    <duration>{xml_escape(duration)}</duration>',
            f'    <total-requests>{self.total_requests}</total-requests>',
            f'    <total-findings>{len(findings_data)}</total-findings>',
            '  </scan>',
            '  <findings>',
        ]

        for f in findings_data:
            lines.append('    <finding>')
            lines.append(f'      <severity>{xml_escape(str(f.get("severity", "INFO")))}</severity>')
            lines.append(f'      <technique>{xml_escape(str(f.get("technique", "")))}</technique>')
            lines.append(f'      <url>{xml_escape(str(f.get("url", "")))}</url>')
            lines.append(f'      <param>{xml_escape(str(f.get("param", "")))}</param>')
            lines.append(f'      <payload>{xml_escape(str(f.get("payload", "")))}</payload>')
            lines.append(f'      <evidence>{xml_escape(str(f.get("evidence", "")))}</evidence>')
            lines.append(f'      <confidence>{f.get("confidence", 0)}</confidence>')
            lines.append(f'      <mitre-id>{xml_escape(str(f.get("mitre_id", "")))}</mitre-id>')
            lines.append(f'      <cwe-id>{xml_escape(str(f.get("cwe_id", "")))}</cwe-id>')
            lines.append(f'      <cvss>{f.get("cvss", 0)}</cvss>')
            if f.get('remediation'):
                lines.append(f'      <remediation>{xml_escape(str(f.get("remediation", "")))}</remediation>')
            lines.append('    </finding>')

        lines.append('  </findings>')

        # Exploit chains
        chains_data = self._get_chains_data()
        if chains_data:
            lines.append('  <exploit-chains>')
            for ch in chains_data:
                lines.append('    <chain>')
                lines.append(f'      <chain-id>{xml_escape(str(ch.get("id", "")))}</chain-id>')
                lines.append(f'      <name>{xml_escape(str(ch.get("name", "")))}</name>')
                steps_str = ', '.join(ch.get('steps', []))
                lines.append(f'      <steps>{xml_escape(steps_str)}</steps>')
                lines.append(f'      <combined-cvss>{ch.get("combined_cvss", 0)}</combined-cvss>')
                lines.append(f'      <combined-severity>{xml_escape(str(ch.get("combined_severity", "")))}</combined-severity>')
                lines.append('    </chain>')
            lines.append('  </exploit-chains>')

        lines.append('</atomic-report>')

        try:
            with open(filepath, 'w', encoding='utf-8') as fh:
                fh.write('\n'.join(lines))
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath

    def _generate_sarif(self):
        """Generate SARIF v2.1.0 report for GitHub Code Scanning integration."""
        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.sarif')
        findings_data = self._get_findings_data()

        severity_to_sarif = {
            'CRITICAL': 'error',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'note',
            'INFO': 'note',
        }

        rules = []
        results = []
        rule_ids_seen = set()

        for f in findings_data:
            technique = f.get('technique', 'Unknown')
            rule_id = re.sub(r'[^a-zA-Z0-9_-]', '_', technique)

            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rule_entry = {
                    'id': rule_id,
                    'name': technique,
                    'shortDescription': {'text': technique},
                    'fullDescription': {'text': f.get('remediation', technique)},
                    'defaultConfiguration': {
                        'level': severity_to_sarif.get(f.get('severity', 'INFO'), 'note'),
                    },
                }
                if f.get('cwe_id'):
                    cwe_num = str(f['cwe_id']).replace('CWE-', '')
                    rule_entry['properties'] = {
                        'tags': ['security'],
                        'security-severity': str(f.get('cvss', 0.0)),
                    }
                    rule_entry['relationships'] = [{
                        'target': {
                            'id': f['cwe_id'],
                            'guid': f'{cwe_num}',
                            'toolComponent': {'name': 'CWE', 'guid': 'cwe'},
                        },
                        'kinds': ['superset'],
                    }]
                rules.append(rule_entry)

            result_entry = {
                'ruleId': rule_id,
                'level': severity_to_sarif.get(f.get('severity', 'INFO'), 'note'),
                'message': {
                    'text': (
                        f"{technique} found on {f.get('url', '')} "
                        f"(param: {f.get('param', 'N/A')}, "
                        f"confidence: {f.get('confidence', 0):.0%})"
                    ),
                },
                'locations': [{
                    'physicalLocation': {
                        'artifactLocation': {
                            'uri': f.get('url', ''),
                            'uriBaseId': 'TARGETROOT',
                        },
                    },
                }],
            }
            if f.get('payload'):
                result_entry['fingerprints'] = {
                    'payload/v1': f['payload'][:200],
                }
            results.append(result_entry)

        sarif = {
            '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
            'version': '2.1.0',
            'runs': [{
                'tool': {
                    'driver': {
                        'name': 'ATOMIC Framework',
                        'version': Config.VERSION,
                        'informationUri': 'https://github.com/hamahasan441-png/Scanner-',
                        'rules': rules,
                    },
                },
                'results': results,
                'columnKind': 'utf16CodeUnits',
            }],
        }

        try:
            with open(filepath, 'w', encoding='utf-8') as fh:
                json.dump(sarif, fh, indent=2, default=str)
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath
