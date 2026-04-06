# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 9.0.x   | ✅ Active support  |
| < 9.0   | ❌ End of life     |

## Reporting a Vulnerability

If you discover a security vulnerability in the ATOMIC Framework, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

### How to Report

1. **Email:** Send a detailed report to the repository maintainers via GitHub's private vulnerability reporting feature.
2. **GitHub Security Advisories:** Use the [Security Advisories](../../security/advisories/new) tab to privately report the vulnerability.

### What to Include

- A description of the vulnerability and its potential impact
- Steps to reproduce the issue
- Affected version(s)
- Any suggested fix or mitigation (if available)

### Response Timeline

- **Acknowledgment:** Within 48 hours of receiving the report
- **Initial assessment:** Within 7 days
- **Fix or mitigation:** Best effort, typically within 30 days for critical issues

### Scope

This security policy covers vulnerabilities in the ATOMIC Framework codebase itself. It does **not** cover:

- Vulnerabilities found in target applications during authorized security testing
- Issues in third-party dependencies (please report those to the respective projects)

## Security Best Practices

When using ATOMIC Framework:

- **Always obtain written authorization** before scanning any target
- Keep the framework and its dependencies up to date
- Use virtual environments to isolate the framework from your system Python
- Review scan results carefully before acting on findings
- Follow responsible disclosure for any vulnerabilities discovered during testing

## Dependency Security

This project uses automated dependency scanning via:

- **Dependabot** for dependency version updates
- **pip-audit** for known vulnerability detection
- **GitHub CodeQL** for static analysis
- **Bandit** for Python-specific security analysis
