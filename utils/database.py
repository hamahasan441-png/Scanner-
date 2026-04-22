#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Database Module
SQLite/SQLAlchemy database operations
"""

try:
    from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, ForeignKey
    from sqlalchemy.orm import sessionmaker, declarative_base

    SQLALCHEMY_AVAILABLE = True
except ImportError:
    try:
        from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, ForeignKey
        from sqlalchemy.ext.declarative import declarative_base
        from sqlalchemy.orm import sessionmaker

        SQLALCHEMY_AVAILABLE = True
    except ImportError:
        SQLALCHEMY_AVAILABLE = False
        print("[!] SQLAlchemy not installed. Database features disabled.")
        print("    Run: pip install sqlalchemy")

from datetime import datetime, timezone
from config import Config, Colors

Base = declarative_base() if SQLALCHEMY_AVAILABLE else None


class ScanModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Scan metadata model"""

    if SQLALCHEMY_AVAILABLE:
        __tablename__ = "scans"

        id = Column(Integer, primary_key=True)
        scan_id = Column(String(50), unique=True, nullable=False)
        target = Column(String(500), nullable=False)
        start_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        end_time = Column(DateTime)
        total_requests = Column(Integer, default=0)
        findings_count = Column(Integer, default=0)
        config = Column(Text)


class FindingModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Finding model"""

    if SQLALCHEMY_AVAILABLE:
        __tablename__ = "findings"

        id = Column(Integer, primary_key=True)
        scan_id = Column(String(50), ForeignKey("scans.scan_id"))
        timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        technique = Column(String(100))
        mitre_id = Column(String(20))
        cwe_id = Column(String(20))
        cvss = Column(Float)
        severity = Column(String(20))
        confidence = Column(Float)
        url = Column(Text)
        param = Column(String(200))
        payload = Column(Text)
        evidence = Column(Text)
        extracted_data = Column(Text)


class ExploitChainModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Exploit chain model — stores detected multi-step chains."""

    if SQLALCHEMY_AVAILABLE:
        __tablename__ = "exploit_chains"

        id = Column(Integer, primary_key=True)
        scan_id = Column(String(50), ForeignKey("scans.scan_id"))
        chain_id = Column(String(50))
        name = Column(String(200))
        steps = Column(Text)  # JSON list of step labels
        combined_cvss = Column(Float, default=0.0)
        combined_severity = Column(String(20))
        finding_count = Column(Integer, default=0)


class ShellModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Active shell model"""

    if SQLALCHEMY_AVAILABLE:
        __tablename__ = "shells"

        id = Column(Integer, primary_key=True)
        shell_id = Column(String(50), unique=True)
        url = Column(String(500))
        shell_type = Column(String(50))
        password = Column(String(100))
        created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        last_used = Column(DateTime)
        status = Column(String(20), default="active")


class CanonicalFindingModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Canonical finding with full evidence/repro/verification metadata."""

    if SQLALCHEMY_AVAILABLE:
        __tablename__ = "canonical_findings"

        id = Column(Integer, primary_key=True)
        scan_id = Column(String(50), ForeignKey("scans.scan_id"))
        finding_id = Column(String(64), unique=True, nullable=False, index=True)
        timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))
        # Core fields
        technique = Column(String(200))
        url = Column(Text)
        method = Column(String(10))
        param = Column(String(200))
        payload = Column(Text)
        severity = Column(String(20))
        confidence = Column(Float)
        cvss = Column(Float)
        mitre_id = Column(String(20))
        cwe_id = Column(String(20))
        remediation = Column(Text)
        group_id = Column(String(64))
        # Evidence serialized as JSON
        evidence_json = Column(Text)
        # Repro serialized as JSON
        repro_json = Column(Text)
        # VerificationResult serialized as JSON
        verification_json = Column(Text)


class FindingGroupModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Canonical finding group / correlation cluster."""

    if SQLALCHEMY_AVAILABLE:
        __tablename__ = "finding_groups"

        id = Column(Integer, primary_key=True)
        scan_id = Column(String(50), ForeignKey("scans.scan_id"))
        group_id = Column(String(64), index=True)
        root_cause_hypothesis = Column(Text)
        group_confidence = Column(Float)
        # Serialized as JSON lists
        supporting_finding_ids_json = Column(Text)
        affected_endpoints_json = Column(Text)
        recommended_next_check = Column(Text)


class Database:
    """Database handler"""

    def __init__(self):
        self.engine = None
        self.Session = None

        if SQLALCHEMY_AVAILABLE:
            try:
                self.engine = create_engine(Config.DB_URL)
                Base.metadata.create_all(self.engine)
                self.Session = sessionmaker(bind=self.engine)
            except Exception as e:
                print(f"[!] Database error: {e}")

    def save_scan(self, **kwargs):
        """Save scan metadata"""
        if not self.Session:
            return

        try:
            session = self.Session()
            scan = ScanModel(**kwargs)
            session.add(scan)
            session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error saving scan: {e}")

    def save_finding(self, scan_id, finding):
        """Save finding"""
        if not self.Session:
            return

        try:
            session = self.Session()
            f = FindingModel(
                scan_id=scan_id,
                technique=finding.technique,
                mitre_id=finding.mitre_id,
                cwe_id=finding.cwe_id,
                cvss=finding.cvss,
                severity=finding.severity,
                confidence=finding.confidence,
                url=finding.url,
                param=finding.param,
                payload=finding.payload,
                evidence=finding.evidence,
                extracted_data=finding.extracted_data,
            )
            session.add(f)
            session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error saving finding: {e}")

    def save_results(self, scan_id, findings):
        """Bulk-save all verified findings for a scan."""
        if not self.Session:
            return

        try:
            session = self.Session()
            for finding in findings:
                f = FindingModel(
                    scan_id=scan_id,
                    technique=getattr(finding, "technique", ""),
                    mitre_id=getattr(finding, "mitre_id", ""),
                    cwe_id=getattr(finding, "cwe_id", ""),
                    cvss=getattr(finding, "cvss", 0.0),
                    severity=getattr(finding, "severity", "INFO"),
                    confidence=getattr(finding, "confidence", 0.0),
                    url=getattr(finding, "url", ""),
                    param=getattr(finding, "param", ""),
                    payload=getattr(finding, "payload", ""),
                    evidence=getattr(finding, "evidence", ""),
                    extracted_data=getattr(finding, "extracted_data", ""),
                )
                session.add(f)
            session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error bulk-saving findings: {e}")

    def save_chains(self, scan_id, chains):
        """Save exploit chains for a scan."""
        if not self.Session:
            return

        try:
            import json as _json

            session = self.Session()
            for chain in chains:
                c = ExploitChainModel(
                    scan_id=scan_id,
                    chain_id=getattr(chain, "id", ""),
                    name=getattr(chain, "name", ""),
                    steps=_json.dumps(getattr(chain, "steps", [])),
                    combined_cvss=getattr(chain, "combined_cvss", 0.0),
                    combined_severity=getattr(chain, "combined_severity", "HIGH"),
                    finding_count=len(getattr(chain, "findings", [])),
                )
                session.add(c)
            session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error saving exploit chains: {e}")

    def update_scan(self, scan_id, **kwargs):
        """Update scan metadata (e.g. end_time, findings_count, total_requests)"""
        if not self.Session:
            return

        try:
            session = self.Session()
            scan = session.query(ScanModel).filter_by(scan_id=scan_id).first()
            if scan:
                for key, value in kwargs.items():
                    if hasattr(scan, key):
                        setattr(scan, key, value)
                session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error updating scan: {e}")

    def save_shell(self, shell_id, url, shell_type, password=None):
        """Save active shell"""
        if not self.Session:
            return

        try:
            session = self.Session()
            shell = ShellModel(
                shell_id=shell_id,
                url=url,
                shell_type=shell_type,
                password=password,
            )
            session.add(shell)
            session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error saving shell: {e}")

    def get_shells(self):
        """Get all active shells"""
        if not self.Session:
            return []

        try:
            session = self.Session()
            shells = session.query(ShellModel).filter_by(status="active").all()
            result = [
                {
                    "shell_id": s.shell_id,
                    "url": s.url,
                    "shell_type": s.shell_type,
                    "password": "********" if s.password else None,
                    "created_at": s.created_at,
                }
                for s in shells
            ]
            session.close()
            return result
        except Exception as e:
            print(f"[!] Error getting shells: {e}")
            return []

    def update_shell(self, shell_id, **kwargs):
        """Update shell info"""
        if not self.Session:
            return

        try:
            session = self.Session()
            shell = session.query(ShellModel).filter_by(shell_id=shell_id).first()
            if shell:
                for key, value in kwargs.items():
                    setattr(shell, key, value)
                session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error updating shell: {e}")

    # ------------------------------------------------------------------
    # Canonical persistence (CanonicalFinding, FindingGroup, ScanResult)
    # ------------------------------------------------------------------

    def save_canonical_finding(self, scan_id: str, finding) -> None:
        """Persist a ``CanonicalFinding`` with evidence/repro/verification.

        Silently skips if the session is unavailable or if the
        ``finding_id`` already exists (idempotent upsert).
        """
        if not self.Session:
            return
        try:
            import json as _json

            session = self.Session()
            # Skip if already persisted
            existing = session.query(CanonicalFindingModel).filter_by(
                finding_id=finding.finding_id
            ).first()
            if existing:
                session.close()
                return

            evidence_json = ""
            if finding.evidence:
                try:
                    evidence_json = _json.dumps(finding.evidence.to_dict(), sort_keys=True)
                except Exception:
                    pass

            repro_json = ""
            if finding.repro:
                try:
                    repro_json = _json.dumps(finding.repro.to_dict(), sort_keys=True)
                except Exception:
                    pass

            verification_json = ""
            if finding.verification:
                try:
                    verification_json = _json.dumps(finding.verification.to_dict(), sort_keys=True)
                except Exception:
                    pass

            row = CanonicalFindingModel(
                scan_id=scan_id,
                finding_id=finding.finding_id,
                technique=finding.technique,
                url=finding.url,
                method=finding.method,
                param=finding.param,
                payload=finding.payload,
                severity=finding.severity,
                confidence=finding.confidence,
                cvss=finding.cvss,
                mitre_id=finding.mitre_id,
                cwe_id=finding.cwe_id,
                remediation=finding.remediation,
                group_id=finding.group_id,
                evidence_json=evidence_json,
                repro_json=repro_json,
                verification_json=verification_json,
            )
            session.add(row)
            session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error saving canonical finding: {e}")

    def load_canonical_findings(self, scan_id: str) -> list:
        """Load all canonical findings for *scan_id* and return as plain dicts.

        Returns an empty list when the session is unavailable.
        """
        if not self.Session:
            return []
        try:
            import json as _json

            session = self.Session()
            rows = session.query(CanonicalFindingModel).filter_by(scan_id=scan_id).all()
            results = []
            for row in rows:
                d = {
                    "finding_id": row.finding_id,
                    "technique": row.technique,
                    "url": row.url,
                    "method": row.method,
                    "param": row.param,
                    "payload": row.payload,
                    "severity": row.severity,
                    "confidence": row.confidence,
                    "cvss": row.cvss,
                    "mitre_id": row.mitre_id,
                    "cwe_id": row.cwe_id,
                    "remediation": row.remediation,
                    "group_id": row.group_id,
                    "evidence": _json.loads(row.evidence_json) if row.evidence_json else None,
                    "repro": _json.loads(row.repro_json) if row.repro_json else None,
                    "verification": _json.loads(row.verification_json) if row.verification_json else None,
                }
                results.append(d)
            session.close()
            return results
        except Exception as e:
            print(f"[!] Error loading canonical findings: {e}")
            return []

    def save_finding_group(self, scan_id: str, group) -> None:
        """Persist a ``FindingGroup``."""
        if not self.Session:
            return
        try:
            import json as _json

            session = self.Session()
            row = FindingGroupModel(
                scan_id=scan_id,
                group_id=group.group_id,
                root_cause_hypothesis=group.root_cause_hypothesis,
                group_confidence=group.group_confidence,
                supporting_finding_ids_json=_json.dumps(
                    sorted(group.supporting_finding_ids), sort_keys=True
                ),
                affected_endpoints_json=_json.dumps(
                    sorted(group.affected_endpoints), sort_keys=True
                ),
                recommended_next_check=group.recommended_next_check,
            )
            session.add(row)
            session.commit()
            session.close()
        except Exception as e:
            print(f"[!] Error saving finding group: {e}")

    def load_finding_groups(self, scan_id: str) -> list:
        """Load finding groups for *scan_id* and return as plain dicts."""
        if not self.Session:
            return []
        try:
            import json as _json

            session = self.Session()
            rows = session.query(FindingGroupModel).filter_by(scan_id=scan_id).all()
            results = []
            for row in rows:
                d = {
                    "group_id": row.group_id,
                    "root_cause_hypothesis": row.root_cause_hypothesis,
                    "group_confidence": row.group_confidence,
                    "supporting_finding_ids": _json.loads(row.supporting_finding_ids_json or "[]"),
                    "affected_endpoints": _json.loads(row.affected_endpoints_json or "[]"),
                    "recommended_next_check": row.recommended_next_check,
                }
                results.append(d)
            session.close()
            return results
        except Exception as e:
            print(f"[!] Error loading finding groups: {e}")
            return []

    def save_canonical_scan_result(self, scan_id: str, scan_result) -> None:
        """Persist all findings and groups from a ``ScanResult``.

        Args:
            scan_id:     The scan's unique identifier.
            scan_result: A ``core.models.ScanResult`` instance.
        """
        for finding in getattr(scan_result, "findings", []):
            self.save_canonical_finding(scan_id, finding)
        for group in getattr(scan_result, "groups", []):
            self.save_finding_group(scan_id, group)


def list_scans():
    """List all scans"""
    if not SQLALCHEMY_AVAILABLE:
        print("[!] SQLAlchemy not available")
        return

    try:
        engine = create_engine(Config.DB_URL)
        Session = sessionmaker(bind=engine)
        session = Session()

        scans = session.query(ScanModel).order_by(ScanModel.start_time.desc()).all()

        if not scans:
            print(f"{Colors.info('No scans found')}")
            return

        print(f"\n{Colors.BOLD}{'='*100}{Colors.RESET}")
        print(f"{Colors.CYAN}{'Scan ID':<20} {'Target':<35} {'Date':<20} {'Findings':<10}{Colors.RESET}")
        print(f"{Colors.BOLD}{'='*100}{Colors.RESET}")

        for scan in scans:
            target = scan.target[:33] if scan.target else "N/A"
            date_str = scan.start_time.strftime("%Y-%m-%d %H:%M") if scan.start_time else "N/A"
            print(f"{scan.scan_id:<20} {target:<35} {date_str:<20} {scan.findings_count:<10}")

        session.close()
    except Exception as e:
        print(f"[!] Error listing scans: {e}")


def clear_database():
    """Clear all database tables"""
    if not SQLALCHEMY_AVAILABLE:
        print("[!] SQLAlchemy not available")
        return

    try:
        engine = create_engine(Config.DB_URL)
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        print(f"{Colors.success('Database cleared successfully')}")
    except Exception as e:
        print(f"[!] Error clearing database: {e}")
