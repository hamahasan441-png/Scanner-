"""
Subdomain Takeover Detection Plugin for ATOMIC Framework

Detects dangling DNS records that could allow subdomain takeover attacks.
Checks CNAME records against known vulnerable service fingerprints.

Usage:
    Drop this folder into the ``plugins/`` directory and the PluginManager
    will auto-discover it on the next scan.
"""

plugin_info = {
    'name': 'subdomain_takeover',
    'version': '1.0.0',
    'author': 'ATOMIC Security',
    'description': 'Detects potential subdomain takeover vulnerabilities via dangling DNS records',
    'category': 'recon',
}


class PluginScanner:
    """Subdomain takeover detection scanner.

    Resolves CNAME records for discovered subdomains and checks whether
    the pointed-to service returns a fingerprint indicating the resource
    is unclaimed (dangling).
    """

    # Known service fingerprints that indicate a takeover-able resource.
    # Each entry maps a CNAME pattern to a tuple of
    # (service_name, http_fingerprint, is_edge_case).
    FINGERPRINTS = {
        '.s3.amazonaws.com': (
            'AWS S3',
            'NoSuchBucket',
            False,
        ),
        '.s3-website': (
            'AWS S3 Website',
            'NoSuchBucket',
            False,
        ),
        'herokuapp.com': (
            'Heroku',
            'no-such-app.html',
            False,
        ),
        '.ghost.io': (
            'Ghost',
            'The thing you were looking for is no longer here',
            False,
        ),
        'github.io': (
            'GitHub Pages',
            "There isn't a GitHub Pages site here",
            False,
        ),
        '.azurewebsites.net': (
            'Azure',
            'Web App - Pair Networks',
            False,
        ),
        '.cloudfront.net': (
            'AWS CloudFront',
            'Bad request',
            True,
        ),
        '.zendesk.com': (
            'Zendesk',
            'Help Center Closed',
            False,
        ),
        '.teamwork.com': (
            'Teamwork',
            'Oops - We didn\'t find your site',
            False,
        ),
        '.unbounce.com': (
            'Unbounce',
            'The requested URL was not found on this server',
            False,
        ),
        '.helpjuice.com': (
            'HelpJuice',
            'We could not find what you\'re looking for',
            False,
        ),
        '.helpscoutdocs.com': (
            'HelpScout',
            'No settings were found for this company',
            False,
        ),
        '.feedpress.me': (
            'FeedPress',
            'The feed has not been found',
            False,
        ),
        '.freshdesk.com': (
            'Freshdesk',
            'May be this is still fresh',
            False,
        ),
        '.pantheonsite.io': (
            'Pantheon',
            '404 error unknown site',
            False,
        ),
        '.bitbucket.io': (
            'Bitbucket',
            'Repository not found',
            False,
        ),
        '.shopify.com': (
            'Shopify',
            'Sorry, this shop is currently unavailable',
            False,
        ),
        '.surge.sh': (
            'Surge.sh',
            'project not found',
            False,
        ),
        '.netlify.app': (
            'Netlify',
            'Not Found - Request ID',
            False,
        ),
        '.fly.dev': (
            'Fly.io',
            'not found',
            True,
        ),
    }

    def __init__(self):
        self.engine = None

    def setup(self, engine):
        """Receive a reference to the main AtomicEngine (optional)."""
        self.engine = engine

    def run(self, target, params=None):
        """Run subdomain takeover detection.

        Args:
            target: Base domain to check (e.g. ``example.com``).
            params: Optional list of subdomains to check. If empty,
                    the plugin will attempt basic enumeration.

        Returns:
            List of finding dicts, each containing:
            - ``type``: always ``'subdomain_takeover'``
            - ``subdomain``: the affected FQDN
            - ``cname``: the dangling CNAME value
            - ``service``: the identified cloud service
            - ``fingerprint``: the HTTP body fingerprint matched
            - ``confidence``: ``'high'`` or ``'medium'``
        """
        import socket
        subdomains = list(params or [])
        if not subdomains:
            subdomains = self._enumerate_common(target)

        findings = []
        for sub in subdomains:
            fqdn = f'{sub}.{target}' if '.' not in sub else sub
            result = self._check_subdomain(fqdn)
            if result:
                findings.append(result)
        return findings

    def teardown(self):
        """Cleanup."""
        self.engine = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _enumerate_common(domain):
        """Return a small default list of common subdomains to probe."""
        return [
            'www', 'mail', 'blog', 'shop', 'dev', 'staging', 'beta',
            'app', 'api', 'docs', 'status', 'cdn', 'support', 'help',
            'portal', 'admin', 'test', 'demo', 'landing', 'go',
        ]

    def _check_subdomain(self, fqdn):
        """Resolve CNAME and check for dangling fingerprint."""
        cname = self._resolve_cname(fqdn)
        if not cname:
            return None

        for pattern, (service, fingerprint, is_edge) in self.FINGERPRINTS.items():
            if pattern in cname.lower():
                body = self._fetch_body(fqdn)
                if body is not None and fingerprint.lower() in body.lower():
                    return {
                        'type': 'subdomain_takeover',
                        'subdomain': fqdn,
                        'cname': cname,
                        'service': service,
                        'fingerprint': fingerprint,
                        'confidence': 'medium' if is_edge else 'high',
                    }
        return None

    @staticmethod
    def _resolve_cname(fqdn):
        """Resolve a CNAME record for the given FQDN.

        Returns the CNAME target string, or ``None`` if no CNAME exists.
        """
        try:
            import dns.resolver
            answers = dns.resolver.resolve(fqdn, 'CNAME')
            for rdata in answers:
                return str(rdata.target).rstrip('.')
        except Exception:
            pass
        return None

    @staticmethod
    def _fetch_body(fqdn):
        """Perform a simple HTTP GET and return the response body text."""
        try:
            import requests
            for scheme in ('https', 'http'):
                try:
                    # SSL verification is intentionally disabled because
                    # subdomain takeover targets often have invalid or
                    # expired certificates on the dangling endpoint.
                    resp = requests.get(
                        f'{scheme}://{fqdn}',
                        timeout=10,
                        allow_redirects=True,
                        verify=False,
                        headers={'User-Agent': 'Mozilla/5.0'},
                    )
                    return resp.text
                except Exception:
                    continue
        except ImportError:
            pass
        return None
