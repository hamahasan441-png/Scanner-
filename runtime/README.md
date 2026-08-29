# Managed Security Tool Runtime

This directory is the framework-owned runtime boundary for external security tools.

- `bin/` contains verified tool artifacts when installed.
- `metadata/tools.json` pins tool identity and platform constraints.
- `metadata/sources.json` records official upstream repositories.
- A binary is executable only after path validation; when a SHA-256 is present it must match exactly.
- Set `ATOMIC_REQUIRE_BUNDLED_TOOLS=1` to fail closed instead of falling back to host-installed tools.

The repository intentionally does not ship third-party binaries without a reproducible release artifact, checksum/signature, platform mapping, and redistribution review.
