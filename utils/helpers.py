#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Helper Utilities
"""

import sys
import subprocess
import platform
from urllib.parse import urlparse, urlunparse

from config import Colors


def build_origin_target(target: str, origin_ip: str) -> str:
    """Build a URL that points to the discovered origin IP.

    Replaces the hostname in *target* with *origin_ip* so that
    subsequent requests bypass CDN/WAF and hit the real server.
    The original hostname is preserved for the ``Host`` header
    (handled by callers via ``requester`` or ``headers`` kwarg).

    Args:
        target: The original target URL (e.g. ``https://example.com/path``).
        origin_ip: The discovered origin IP address.

    Returns:
        A new URL string with the host replaced by *origin_ip*.
        If *origin_ip* is falsy or parsing fails the original
        *target* is returned unchanged.
    """
    if not origin_ip:
        return target
    try:
        parsed = urlparse(target)
        # Preserve explicit port if present in the original URL
        if parsed.port:
            new_netloc = f"{origin_ip}:{parsed.port}"
        else:
            new_netloc = origin_ip
        return urlunparse(parsed._replace(netloc=new_netloc))
    except Exception:
        return target


def get_origin_host(target: str) -> str:
    """Extract the original hostname from *target* for use as ``Host`` header.

    Args:
        target: The original target URL.

    Returns:
        The hostname (and optional port) from *target*, suitable for
        use as an HTTP ``Host`` header value.
    """
    try:
        parsed = urlparse(target)
        return parsed.netloc or ''
    except Exception:
        return ''


def check_dependencies():
    """Check all required dependencies"""
    print(f"{Colors.info('Checking dependencies...')}")
    
    dependencies = {
        'requests': 'HTTP requests library',
        'bs4': 'HTML parsing (beautifulsoup4)',
        'sqlalchemy': 'Database ORM',
        'fpdf': 'PDF report generation (fpdf2)',
        'jwt': 'JWT token handling (PyJWT)',
        'urllib3': 'HTTP client',
    }
    
    optional = {
        'flask': 'Web interface',
        'flask_socketio': 'Real-time updates',
        'flask_cors': 'CORS support',
        'lxml': 'XML/HTML parser (faster parsing)',
        'cryptography': 'Encryption support',
        'paramiko': 'SSH connections',
        'pysocks': 'SOCKS proxy support',
    }
    
    print(f"\n{Colors.BOLD}Required Dependencies:{Colors.RESET}")
    all_ok = True
    for module, description in dependencies.items():
        try:
            __import__(module)
            print(f"  {Colors.GREEN}[✓]{Colors.RESET} {module} - {description}")
        except ImportError:
            print(f"  {Colors.RED}[✗]{Colors.RESET} {module} - {description}")
            all_ok = False
    
    print(f"\n{Colors.BOLD}Optional Dependencies:{Colors.RESET}")
    for module, description in optional.items():
        try:
            __import__(module)
            print(f"  {Colors.GREEN}[✓]{Colors.RESET} {module} - {description}")
        except ImportError:
            print(f"  {Colors.YELLOW}[!]{Colors.RESET} {module} - {description}")
    
    if all_ok:
        print(f"\n{Colors.success('All required dependencies are installed!')}")
    else:
        print(f"\n{Colors.warning('Some required dependencies are missing. Run: pip install -r requirements.txt')}")
    
    return all_ok


def install_deps():
    """Install all dependencies"""
    print(f"{Colors.info('Installing dependencies...')}")
    
    deps = [
        'requests',
        'beautifulsoup4',
        'sqlalchemy',
        'fpdf2',
        'PyJWT',
        'urllib3',
        'flask',
        'flask-socketio',
        'flask-cors',
        'pysocks',
        'colorama',
        'tqdm',
    ]
    
    for dep in deps:
        print(f"{Colors.info(f'Installing {dep}...')}")
        try:
            subprocess.run([sys.executable, '-m', 'pip', 'install', dep, '-q'], check=True)
            print(f"  {Colors.success(f'{dep} installed')}")
        except subprocess.CalledProcessError:
            print(f"  {Colors.error(f'Failed to install {dep}')}")
    
    print(f"\n{Colors.success('Installation complete!')}")


def get_system_info():
    """Get system information"""
    return {
        'platform': platform.system(),
        'release': platform.release(),
        'version': platform.version(),
        'machine': platform.machine(),
        'processor': platform.processor(),
        'python': platform.python_version(),
    }


def print_progress(current, total, prefix='Progress', length=50):
    """Print progress bar"""
    percent = 100 * (current / float(total))
    filled = int(length * current // total)
    bar = '█' * filled + '-' * (length - filled)
    print(f'\r{prefix}: |{bar}| {percent:.1f}%', end='')
    if current == total:
        print()


def encode_payload(payload: str, encoding: str) -> str:
    """Encode payload with various encodings"""
    import base64
    import urllib.parse
    
    if encoding == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif encoding == 'url':
        return urllib.parse.quote(payload)
    elif encoding == 'double_url':
        return urllib.parse.quote(urllib.parse.quote(payload))
    elif encoding == 'hex':
        return ''.join(f'\\x{ord(c):02x}' for c in payload)
    elif encoding == 'unicode':
        return ''.join(f'%u{ord(c):04x}' for c in payload)
    else:
        return payload


def detect_waf(response):
    """Detect WAF from response"""
    waf_signatures = {
        'Cloudflare': ['cf-ray', 'cloudflare', '__cfduid'],
        'AWS WAF': ['awselb', 'aws-waf'],
        'ModSecurity': ['mod_security', 'ModSecurity'],
        'Sucuri': ['sucuri', 'x-sucuri'],
        'Incapsula': ['incap_ses', 'visid_incap'],
        'Akamai': ['akamai', 'ak_bmsc'],
        'F5 BIG-IP': ['bigip', 'f5'],
        'Imperva': ['incap_ses', 'visid_incap'],
        'Barracuda': ['barra'],
        'Fortinet': ['fortigate'],
        'Wordfence': ['wordfence'],
    }
    
    if not response:
        return None
    
    headers = str(response.headers).lower()
    cookies = str(response.cookies).lower()
    content = response.text.lower() if hasattr(response, 'text') else ''
    
    detected = []
    for waf, signatures in waf_signatures.items():
        for sig in signatures:
            if sig.lower() in headers or sig.lower() in cookies or sig.lower() in content:
                detected.append(waf)
                break
    
    return detected if detected else None


def extract_forms(html: str, base_url: str) -> list:
    """Extract forms from HTML"""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return []
    
    soup = BeautifulSoup(html, 'html.parser')
    forms = []
    
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'get').upper(),
            'inputs': []
        }
        
        for inp in form.find_all(['input', 'textarea', 'select']):
            form_data['inputs'].append({
                'name': inp.get('name', ''),
                'type': inp.get('type', 'text'),
                'value': inp.get('value', ''),
            })
        
        forms.append(form_data)
    
    return forms


def extract_links(html: str, base_url: str) -> list:
    """Extract links from HTML"""
    try:
        from bs4 import BeautifulSoup
        from urllib.parse import urljoin, urlparse
    except ImportError:
        return []
    
    soup = BeautifulSoup(html, 'html.parser')
    links = set()
    
    base_domain = urlparse(base_url).netloc
    
    for link in soup.find_all('a', href=True):
        href = link['href']
        full_url = urljoin(base_url, href)
        
        # Only keep same-domain links
        if urlparse(full_url).netloc == base_domain:
            links.add(full_url)
    
    return list(links)


def generate_random_string(length: int = 10) -> str:
    """Generate random string"""
    import random
    import string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def is_valid_url(url: str) -> bool:
    """Check if URL is valid"""
    from urllib.parse import urlparse
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False
