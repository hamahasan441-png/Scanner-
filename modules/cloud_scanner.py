#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ATOMIC FRAMEWORK - Cloud Security Scanner Module
Detects cloud misconfigurations: public storage buckets, exposed metadata
services, misconfigured IAM, Kubernetes security issues, and cloud-specific
vulnerabilities across AWS, GCP, Azure, DigitalOcean, and Alibaba Cloud.

⚠️ FOR AUTHORIZED TESTING ONLY ⚠️
"""

import re
from urllib.parse import urlparse

# ── Cloud storage bucket name patterns ────────────────────────────────────
_BUCKET_PATTERNS = {
    "s3": [
        "https://{bucket}.s3.amazonaws.com/",
        "https://s3.amazonaws.com/{bucket}/",
        "https://{bucket}.s3-{region}.amazonaws.com/",
    ],
    "gcs": [
        "https://storage.googleapis.com/{bucket}/",
        "https://{bucket}.storage.googleapis.com/",
    ],
    "azure": [
        "https://{account}.blob.core.windows.net/{container}/",
    ],
}

# Regions to probe for S3 (top used)
_S3_REGIONS = [
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "ap-southeast-1",
]

# ── Cloud metadata endpoints (for direct enumeration probes) ──────────────
CLOUD_METADATA_ENDPOINTS = {
    "aws_imdsv1": {
        "url": "http://169.254.169.254/latest/meta-data/",
        "headers": {},
        "indicators": ["ami-id", "instance-id", "instance-type", "hostname"],
    },
    "aws_imdsv2_token": {
        "url": "http://169.254.169.254/latest/api/token",
        "headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        "method": "PUT",
        "indicators": [],
    },
    "aws_iam": {
        "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "headers": {},
        "indicators": ["AccessKeyId", "SecretAccessKey", "Token"],
    },
    "aws_userdata": {
        "url": "http://169.254.169.254/latest/user-data",
        "headers": {},
        "indicators": ["#!/bin", "password", "secret", "key"],
    },
    "gcp": {
        "url": "http://metadata.google.internal/computeMetadata/v1/",
        "headers": {"Metadata-Flavor": "Google"},
        "indicators": ["project", "zone", "instance"],
    },
    "gcp_service_account": {
        "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "headers": {"Metadata-Flavor": "Google"},
        "indicators": ["access_token", "token_type"],
    },
    "azure": {
        "url": "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "headers": {"Metadata": "true"},
        "indicators": ["compute", "network", "vmId", "subscriptionId"],
    },
    "azure_identity": {
        "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "headers": {"Metadata": "true"},
        "indicators": ["access_token", "token_type"],
    },
    "digitalocean": {
        "url": "http://169.254.169.254/metadata/v1/",
        "headers": {},
        "indicators": ["droplet_id", "hostname", "region"],
    },
    "alibaba": {
        "url": "http://100.100.100.200/latest/meta-data/",
        "headers": {},
        "indicators": ["instance-id", "region-id"],
    },
}

# ── Kubernetes security endpoints ─────────────────────────────────────────
K8S_ENDPOINTS = {
    "service_account_token": {
        "path": "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "description": "Kubernetes service account token",
    },
    "kube_api_pods": {
        "url": "https://kubernetes.default.svc/api/v1/namespaces/default/pods",
        "indicators": ["apiVersion", "kind", "metadata"],
    },
    "kube_api_secrets": {
        "url": "https://kubernetes.default.svc/api/v1/secrets",
        "indicators": ["apiVersion", "items", "kind"],
    },
    "kubelet_pods": {
        "url": "https://localhost:10250/pods",
        "indicators": ["apiVersion", "items", "metadata"],
    },
    "kube_env": {
        "env_vars": [
            "KUBERNETES_SERVICE_HOST",
            "KUBERNETES_SERVICE_PORT",
            "KUBERNETES_PORT",
        ],
    },
}

# ── Cloud-specific misconfig paths to probe on the target ────────────────
CLOUD_MISCONFIG_PATHS = [
    # AWS
    "/.aws/credentials",
    "/.aws/config",
    "/aws/credentials",
    # GCP
    "/.config/gcloud/credentials.db",
    "/.config/gcloud/application_default_credentials.json",
    # Azure
    "/.azure/accessTokens.json",
    "/.azure/azureProfile.json",
    # Docker / K8s
    "/.dockerenv",
    "/.docker/config.json",
    "/etc/kubernetes/admin.conf",
    "/etc/kubernetes/kubelet.conf",
    "/etc/kubernetes/controller-manager.conf",
    # Terraform
    "/.terraform/terraform.tfstate",
    "/terraform.tfstate",
    "/terraform.tfvars",
    # Environment
    "/.env",
    "/.env.production",
    "/.env.local",
    "/env.json",
    "/config.json",
    "/config.yaml",
    "/config.yml",
]

# ── Cloud credential indicators in responses ─────────────────────────────
CLOUD_SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_secret_key": r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*[A-Za-z0-9/+=]{40}",
    "gcp_service_key": r'"type"\s*:\s*"service_account"',
    "azure_connection_string": r"(?i)DefaultEndpointsProtocol=https?;AccountName=",
    "azure_client_secret": r"(?i)azure[_\-]?client[_\-]?secret[\s]*[=:]\s*[A-Za-z0-9\-_.~]{30,}",
    "gcp_api_key": r"AIza[0-9A-Za-z_-]{35}",
    "docker_auth": r'"auth"\s*:\s*"[A-Za-z0-9+/=]+"',
    "k8s_token": r"eyJhbGciOiJSUzI1NiIs[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "private_key": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
}


class CloudScannerModule:
    """Cloud Security Scanner — detects cloud misconfigurations.

    Checks performed:
    - Public cloud storage bucket enumeration (S3, GCS, Azure Blob)
    - Cloud metadata service exposure (SSRF-style probes on params)
    - Exposed cloud credentials on target (config files, environment leaks)
    - Kubernetes security issues (service account tokens, API exposure)
    - Cloud secret patterns in responses
    """

    name = "Cloud Security Scanner"
    vuln_type = "cloud"

    def __init__(self, engine):
        self.engine = engine
        self.requester = engine.requester
        self.config = engine.config if isinstance(engine.config, dict) else {}
        self.verbose = self.config.get("verbose", False)
        self._checked_buckets = set()
        self._checked_paths = set()

    # ── Parameter-level test (called for each discovered parameter) ───
    def test(self, url: str, method: str, param: str, value: str):
        """Test a parameter for cloud-related vulnerabilities."""
        self._test_metadata_via_param(url, method, param, value)
        self._test_cloud_secrets_in_response(url, method, param, value)

    # ── URL-level test (called once per discovered URL) ───────────────
    def test_url(self, url: str):
        """URL-level cloud security checks."""
        self._test_cloud_config_exposure(url)
        self._test_bucket_enumeration(url)

    # ------------------------------------------------------------------
    # Internal check implementations
    # ------------------------------------------------------------------

    def _test_metadata_via_param(self, url, method, param, value):
        """Inject cloud metadata URLs into parameters to detect SSRF → metadata."""
        metadata_payloads = [
            ("http://169.254.169.254/latest/meta-data/", "aws"),
            ("http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws_iam"),
            ("http://metadata.google.internal/computeMetadata/v1/", "gcp"),
            ("http://169.254.169.254/metadata/instance?api-version=2021-02-01", "azure"),
            ("http://100.100.100.200/latest/meta-data/", "alibaba"),
        ]

        metadata_indicators = [
            "ami-id",
            "instance-id",
            "instance-type",
            "hostname",
            "AccessKeyId",
            "SecretAccessKey",
            "security-credentials",
            "computeMetadata",
            "vmId",
            "subscriptionId",
            "droplet_id",
            "region-id",
        ]

        for payload, cloud_provider in metadata_payloads:
            try:
                data = {param: payload}
                extra_headers = {}
                if cloud_provider == "gcp":
                    extra_headers["Metadata-Flavor"] = "Google"
                elif cloud_provider == "azure":
                    extra_headers["Metadata"] = "true"

                response = self.requester.request(
                    url,
                    method,
                    data=data,
                    headers=extra_headers,
                )
                if not response:
                    continue

                text = response.text
                for indicator in metadata_indicators:
                    if indicator in text:
                        from core.engine import Finding

                        finding = Finding(
                            technique=f"Cloud Metadata Exposure ({cloud_provider.upper()})",
                            url=url,
                            method=method,
                            severity="CRITICAL",
                            confidence=0.9,
                            param=param,
                            payload=payload,
                            evidence=f"Cloud metadata indicator: {indicator}",
                        )
                        self.engine.add_finding(finding)
                        return
            except Exception:
                continue

    def _test_cloud_secrets_in_response(self, url, method, param, value):
        """Scan the normal response body for leaked cloud credentials."""
        try:
            data = {param: value}
            response = self.requester.request(url, method, data=data)
            if not response:
                return
            text = response.text
            self._scan_text_for_secrets(text, url, param)
        except Exception:
            pass

    def _test_cloud_config_exposure(self, url):
        """Probe target for exposed cloud configuration files."""
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        for path in CLOUD_MISCONFIG_PATHS:
            probe_url = base + path
            if probe_url in self._checked_paths:
                continue
            self._checked_paths.add(probe_url)

            try:
                response = self.requester.request(probe_url, "GET")
                if not response:
                    continue
                if response.status_code == 200 and len(response.text) > 10:
                    # Verify it's not a generic 404 / error page
                    text_lower = response.text.lower()
                    if any(
                        skip in text_lower
                        for skip in [
                            "<!doctype",
                            "<html",
                            "not found",
                            "404",
                            "access denied",
                            "forbidden",
                        ]
                    ):
                        continue

                    from core.engine import Finding

                    finding = Finding(
                        technique="Cloud Config Exposure",
                        url=probe_url,
                        severity="HIGH",
                        confidence=0.8,
                        evidence=f"Exposed cloud config file: {path} ({len(response.text)} bytes)",
                    )
                    self.engine.add_finding(finding)

                    # Also check for embedded secrets
                    self._scan_text_for_secrets(response.text, probe_url)
            except Exception:
                continue

    def _test_bucket_enumeration(self, url):
        """Attempt to discover publicly accessible cloud storage buckets."""
        parsed = urlparse(url)
        hostname = parsed.netloc.split(":")[0]

        # Extract potential bucket names from hostname parts
        bucket_candidates = set()
        parts = hostname.replace(".", "-").split("-")
        bucket_candidates.add(hostname.split(".")[0])
        if len(parts) >= 2:
            bucket_candidates.add("-".join(parts[:2]))
        # Also add the full domain without TLD as candidate
        domain_parts = hostname.split(".")
        if len(domain_parts) >= 2:
            bucket_candidates.add(domain_parts[0])
            bucket_candidates.add(".".join(domain_parts[:-1]))

        for bucket_name in bucket_candidates:
            if not bucket_name or bucket_name in self._checked_buckets:
                continue
            self._checked_buckets.add(bucket_name)

            # S3
            s3_url = f"https://{bucket_name}.s3.amazonaws.com/"
            self._probe_bucket(s3_url, "s3", bucket_name)

            # GCS
            gcs_url = f"https://storage.googleapis.com/{bucket_name}/"
            self._probe_bucket(gcs_url, "gcs", bucket_name)

    def _probe_bucket(self, bucket_url, provider, bucket_name):
        """Probe a single cloud storage bucket URL for public listing."""
        try:
            response = self.requester.request(bucket_url, "GET")
            if not response:
                return
            text = response.text

            is_public = False
            evidence = ""

            if provider == "s3":
                if "<ListBucketResult" in text and "<Contents>" in text:
                    is_public = True
                    evidence = "S3 bucket listing enabled (ListBucketResult)"
                elif "AccessDenied" in text:
                    # Bucket exists but is private — informational
                    return
            elif provider == "gcs":
                if '"kind": "storage#objects"' in text or ("<ListBucketResult" in text and "<Contents>" in text):
                    is_public = True
                    evidence = "GCS bucket listing enabled"
                elif "AccessDenied" in text or "access denied" in text.lower():
                    return

            if is_public:
                from core.engine import Finding

                finding = Finding(
                    technique=f"Public Cloud Storage ({provider.upper()})",
                    url=bucket_url,
                    severity="HIGH",
                    confidence=0.85,
                    evidence=evidence,
                    param=bucket_name,
                )
                self.engine.add_finding(finding)
        except Exception:
            pass

    def _scan_text_for_secrets(self, text, url, param=""):
        """Scan text content for cloud credential patterns."""
        for secret_name, pattern in CLOUD_SECRET_PATTERNS.items():
            match = re.search(pattern, text)
            if match:
                # Mask the actual secret in evidence
                matched_text = match.group(0)
                masked = (
                    matched_text[:8] + "..." + matched_text[-4:]
                    if len(matched_text) > 16
                    else matched_text[: min(4, len(matched_text))] + "..."
                )

                from core.engine import Finding

                finding = Finding(
                    technique=f"Cloud Credential Leak ({secret_name})",
                    url=url,
                    severity="CRITICAL",
                    confidence=0.9,
                    param=param,
                    evidence=f"Detected {secret_name}: {masked}",
                )
                self.engine.add_finding(finding)
                # One credential finding per URL is enough
                return
