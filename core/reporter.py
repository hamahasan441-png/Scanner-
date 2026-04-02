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

    def __init__(self, scan_id, findings=None, target=None, start_time=None, end_time=None, total_requests=0, output_dir=None):
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
        """Generate report in specified format"""
        generators = {
            'html': self._generate_html,
            'json': self._generate_json,
            'csv': self._generate_csv,
            'txt': self._generate_txt,
        }

        generator = generators.get(fmt)
        if generator:
            filepath = generator()
            if filepath:
                print(f"{Colors.success(f'Report generated: {filepath}')}")
        else:
            print(f"{Colors.error(f'Unsupported format: {fmt}')}")

    def generate_all(self):
        """Generate reports in all formats"""
        for fmt in ['html', 'json', 'csv', 'txt']:
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

    def _generate_json(self):
        """Generate JSON report"""
        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.json')

        report = {
            'scan_id': self.scan_id,
            'target': self.target,
            'start_time': str(self.start_time) if self.start_time else None,
            'end_time': str(self.end_time) if self.end_time else None,
            'total_requests': self.total_requests,
            'total_findings': len(self.findings),
            'findings': self._get_findings_data(),
        }

        try:
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath

    def _generate_html(self):
        """Generate HTML report"""
        filepath = os.path.join(self.output_dir, f'report_{self.scan_id}.html')
        findings_data = self._get_findings_data()

        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#e74c3c',
            'MEDIUM': '#f39c12',
            'LOW': '#3498db',
            'INFO': '#6c757d',
        }

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
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: #16213e; padding: 15px; border-radius: 8px; flex: 1; text-align: center; }}
        .summary-card h3 {{ margin: 0; color: #e94560; font-size: 24px; }}
        .summary-card p {{ margin: 5px 0 0; color: #aaa; }}
        code {{ background: #333; padding: 2px 6px; border-radius: 3px; font-size: 12px; }}
    </style>
</head>
<body>
    <h1>ATOMIC Framework v{Config.VERSION} - Scan Report</h1>

    <h2>Scan Information</h2>
    <div class="summary">
        <div class="summary-card"><h3>{self.scan_id}</h3><p>Scan ID</p></div>
        <div class="summary-card"><h3>{len(self.findings)}</h3><p>Findings</p></div>
        <div class="summary-card"><h3>{self.total_requests}</h3><p>Requests</p></div>
        <div class="summary-card"><h3>{duration}</h3><p>Duration</p></div>
    </div>

    <p><strong>Target:</strong> {self.target}</p>
    <p><strong>Start:</strong> {self.start_time}</p>
    <p><strong>End:</strong> {self.end_time}</p>

    <h2>Findings ({len(self.findings)})</h2>
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
        """Generate text report"""
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
            "FINDINGS",
            "=" * 60,
        ]

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

        try:
            with open(filepath, 'w') as f:
                f.write('\n'.join(lines))
        except (IOError, OSError) as e:
            print(f"{Colors.error(f'Cannot write report to {filepath}: {e}')}")
            return None

        return filepath
