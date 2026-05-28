# Security Audit Report: uv Python Package Manager

**Target:** uv (Astral's Python package and project manager)  
**Repository:** https://github.com/astral-sh/uv  
**Audited Commit:** `da5f6a6967b41423fb2a61bf094adff4e403367c`  
**Audit Date:** 2026-05-28  
**Auditor:** AutoFyn Security Audit Team

---

## Executive Summary

This audit identified two independently verified vulnerabilities in uv, plus two defense-in-depth
gaps. The most critical finding is that build backends (setup.py, PEP 517 build systems) inherit the
full parent process environment, allowing malicious packages to exfiltrate sensitive credentials
like AWS keys, API tokens, and other secrets. This is a supply-chain attack vector affecting any
user who installs packages from untrusted sources.

---

## Vulnerability Summary

| Severity | ID          | Title                                 | Status                  |
| -------- | ----------- | ------------------------------------- | ----------------------- |
| **HIGH** | UV-2026-001 | Credential Leakage via Build Backends | VERIFIED                |
| MEDIUM   | UV-2026-002 | GitHub API URL Injection              | VERIFIED                |
| LOW      | UV-2026-003 | Symlink Escape in .data/scripts       | Defense-in-depth gap    |
| INFO     | UV-2026-004 | RECORD Hash Not Validated             | By design (matches pip) |

---

## Detailed Findings

### UV-2026-001: Credential Leakage via Build Backends (HIGH)

**Location:** `crates/uv-build-frontend/src/lib.rs:1203-1222`

**Description:**  
When uv invokes a build backend (e.g., setuptools, hatchling) to build a source distribution, the
subprocess inherits the full parent process environment. Only four environment variables are
explicitly removed:

- `PYX_API_KEY`
- `UV_API_KEY`
- `PYX_AUTH_TOKEN`
- `UV_AUTH_TOKEN`

All other environment variables are passed to the build backend, including:

- `AWS_SECRET_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SESSION_TOKEN`
- `GITHUB_TOKEN`, `GH_TOKEN`, `GIT_TOKEN`
- `HF_TOKEN` (Hugging Face)
- `UV_PUBLISH_TOKEN`, `UV_PUBLISH_PASSWORD`
- `UV_INDEX_{name}_USERNAME`, `UV_INDEX_{name}_PASSWORD`
- Any other secrets present in the shell environment

**Impact:**  
A malicious package's setup.py or build backend can read and exfiltrate these credentials. This is a
supply-chain attack vector: installing a single malicious package (even as a transitive dependency)
compromises all secrets in the user's environment.

**Root Cause:**

```rust
// lib.rs:1203-1218
let mut command = Command::new(venv.python_executable());
// ... environment inherited by default ...
for key in ["PYX_API_KEY", "UV_API_KEY", "PYX_AUTH_TOKEN", "UV_AUTH_TOKEN"] {
    command.env_remove(key);
}
```

The code removes only 4 specific variables instead of using an allowlist approach.

**Reproduction:**

```bash
bash autofyn_audit/exploits/01_credential_leakage/run_exploit.sh
```

**Verified:** PASS. The exploit successfully captured `AWS_SECRET_ACCESS_KEY` and `HF_TOKEN` while
confirming `UV_API_KEY` was correctly stripped.

**Recommendation:**

1. Consider clearing the environment and using an explicit allowlist of safe variables (PATH, HOME,
   LANG, etc.)
2. Alternatively, document this behavior prominently so users understand the risk of installing
   untrusted packages
3. Consider adding a `--sandbox-build` flag that runs builds in a restricted environment

---

### UV-2026-002: GitHub API URL Injection (MEDIUM)

**Location:** `crates/uv-git/src/resolver.rs:101-105`

**Description:**  
When resolving Git dependencies, uv uses a GitHub API fast-path to resolve commit SHAs without
cloning. The `rev` (branch/tag/ref) is interpolated directly into the API URL without
percent-encoding:

```rust
// resolver.rs:105
let github_api_url = format!("{github_api_base_url}/{owner}/{repo}/commits/{rev}");
```

A rev containing `?` (e.g., `main?injected=param`) or `/` (e.g., `../../../admin`) is inserted
literally into the URL, causing:

- Query parameter injection: `main?foo=bar` becomes `...commits/main?foo=bar`
- Path manipulation: `../../../x` could traverse the API path

**Impact:**  
Limited. The response must parse as a 40-character hex SHA (`GitOid::from_str` validation at line
136), so no actual data exfiltration is possible. However:

- Unexpected API endpoints may be hit
- Rate limiting behavior may be affected
- Internal GitHub Enterprise deployments (via `UV_GITHUB_FAST_PATH_URL`) may have different behavior

**Root Cause:**  
The codebase has `as_url_rev()` which correctly percent-encodes the rev, but `resolver.rs` calls
`as_rev()` instead.

**Reproduction:**

```bash
bash autofyn_audit/exploits/02_github_url_injection/run_exploit.sh
```

**Verified:** PASS. Mock server captured request path `/astral-sh/ruff/commits/main?injected=param`
with unencoded query string.

**Recommendation:**  
Replace `as_rev()` with `as_url_rev()` at `resolver.rs:105`.

---

### UV-2026-003: Symlink Escape in .data/scripts (LOW)

**Location:** `crates/uv-install-wheel/src/wheel.rs:453-467`

**Description:**  
When installing wheel scripts from `.data/scripts/`, uv validates that symlinks point to files (not
directories) and are not broken. However, it does not check whether the symlink target is within the
virtual environment boundary. A symlink like `.data/scripts/evil -> /etc/passwd` would pass
validation and be installed to the venv's `bin/` directory.

**Impact:**  
Limited. This is NOT directly exploitable via wheel installation because:

- ZIP extraction writes symlink entries as regular text files containing the target path
- The symlink mode bits (`0o120000`) are not interpreted during extraction

This vulnerability is only exploitable via direct manipulation of uv's wheel cache. An attacker with
local filesystem access could create actual symlinks in the cache and trigger reinstallation.

**Threat Model:**  
If an attacker has write access to uv's cache directory, they can do far worse than symlink attacks
(e.g., replace any cached wheel with malicious code). This is a defense-in-depth gap, not a
practical attack vector.

**Recommendation:**  
After `canonicalize()` at line 454, add a check: `target.starts_with(venv_base)`.

---

### UV-2026-004: RECORD Hash Not Validated (INFO)

**Location:** `crates/uv-install-wheel/src/wheel.rs:955-956`

**Description:**  
The RECORD file in wheels contains SHA256 hashes for each file. uv's `validate_and_heal_record()`
only checks file presence by path; the actual hashes are not verified.

**Impact:**  
None in practice. ZIP CRC32 is validated during extraction. This matches pip's behavior.

**Recommendation:**  
None required. This is consistent with the Python packaging ecosystem.

---

## Reproduction Instructions

### Prerequisites

- Docker (for reproducible environment)
- OR: uv installed locally

### Using Docker (Recommended)

```bash
cd autofyn_audit
docker build -t uv-audit .
docker run --rm uv-audit bash /audit/autofyn_audit/scripts/run_all_exploits.sh
```

### Using Local uv

```bash
# From repository root
bash autofyn_audit/scripts/run_all_exploits.sh
```

### Individual Exploits

```bash
# Exploit 1: Credential Leakage
bash autofyn_audit/exploits/01_credential_leakage/run_exploit.sh

# Exploit 2: GitHub API URL Injection
bash autofyn_audit/exploits/02_github_url_injection/run_exploit.sh
```

---

## Test Environment

- **Base Image:**
  `python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203`
- **Rust Toolchain:** stable (as of audit date)
- **uv Commit:** `da5f6a6967b41423fb2a61bf094adff4e403367c`
- **uv Version:** 0.11.13 (or built from source)

---

## Disclosure Timeline

| Date       | Action                                   |
| ---------- | ---------------------------------------- |
| 2026-05-28 | Audit completed                          |
| TBD        | Report delivered to Astral security team |
| TBD        | Fix released                             |
| TBD        | Public disclosure                        |

---

## Appendix: Code References

### UV-2026-001 (Credential Leakage)

- `crates/uv-build-frontend/src/lib.rs:1203` — Command::new() inherits parent env
- `crates/uv-build-frontend/src/lib.rs:1214-1218` — Only 4 vars removed via env_remove()

### UV-2026-002 (URL Injection)

- `crates/uv-git/src/resolver.rs:101-105` — format!() with raw rev
- `crates/uv-git-types/src/reference.rs:60` — as_rev() returns unencoded string
- `crates/uv-git-types/src/reference.rs:66` — as_url_rev() exists but unused

### UV-2026-003 (Symlink Escape)

- `crates/uv-install-wheel/src/wheel.rs:453-467` — symlink validation missing boundary check
- `crates/uv-extract/src/sync.rs:87` — File::create() used, not symlink creation

### UV-2026-004 (RECORD Hash)

- `crates/uv-install-wheel/src/wheel.rs:955-956` — Comment: "We don't heal the hash"
