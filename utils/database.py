#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Database Module
SQLite/SQLAlchemy database operations
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, ForeignKey, JSON
    from sqlalchemy.orm import sessionmaker, relationship, declarative_base
    SQLALCHEMY_AVAILABLE = True
except ImportError:
    try:
        from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, ForeignKey, JSON
        from sqlalchemy.ext.declarative import declarative_base
        from sqlalchemy.orm import sessionmaker, relationship
        SQLALCHEMY_AVAILABLE = True
    except ImportError:
        SQLALCHEMY_AVAILABLE = False
        print("[!] SQLAlchemy not installed. Database features disabled.")
        print("    Run: pip install sqlalchemy")

from datetime import datetime
from config import Config, Colors

Base = declarative_base() if SQLALCHEMY_AVAILABLE else None


class ScanModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Scan metadata model"""
    if SQLALCHEMY_AVAILABLE:
        __tablename__ = 'scans'
        
        id = Column(Integer, primary_key=True)
        scan_id = Column(String(50), unique=True, nullable=False)
        target = Column(String(500), nullable=False)
        start_time = Column(DateTime, default=datetime.utcnow)
        end_time = Column(DateTime)
        total_requests = Column(Integer, default=0)
        findings_count = Column(Integer, default=0)
        config = Column(Text)


class FindingModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Finding model"""
    if SQLALCHEMY_AVAILABLE:
        __tablename__ = 'findings'
        
        id = Column(Integer, primary_key=True)
        scan_id = Column(String(50), ForeignKey('scans.scan_id'))
        timestamp = Column(DateTime, default=datetime.utcnow)
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


class ShellModel(Base if SQLALCHEMY_AVAILABLE else object):
    """Active shell model"""
    if SQLALCHEMY_AVAILABLE:
        __tablename__ = 'shells'
        
        id = Column(Integer, primary_key=True)
        shell_id = Column(String(50), unique=True)
        url = Column(String(500))
        shell_type = Column(String(50))
        password = Column(String(100))
        created_at = Column(DateTime, default=datetime.utcnow)
        last_used = Column(DateTime)
        status = Column(String(20), default='active')


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
            shells = session.query(ShellModel).filter_by(status='active').all()
            result = [{
                'shell_id': s.shell_id,
                'url': s.url,
                'shell_type': s.shell_type,
                'password': s.password,
                'created_at': s.created_at,
            } for s in shells]
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
            target = scan.target[:33] if scan.target else 'N/A'
            date_str = scan.start_time.strftime('%Y-%m-%d %H:%M') if scan.start_time else 'N/A'
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
